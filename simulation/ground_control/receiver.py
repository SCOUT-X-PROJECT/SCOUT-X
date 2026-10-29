
import json
import socket

from simulation.security.response_engine import ResponseEngine
from simulation.logging.attack_logger import AttackLogger
from simulation.analysis.attack_analyzer import AttackAnalyzer
from simulation.security.enforcer import ResponseEnforcer
from simulation.analysis.threat_stats import ThreatStats
from simulation.analysis.report_generator import ReportGenerator

from simulation.hem import (
    HEMController,
    DataVault,
    PeerRegistry,
    SimTransport,
)
from simulation.hem.vault import CRITICAL, SENSITIVE, ROUTINE
from simulation.ml.anomaly_detector import TelemetryAnomalyDetector


HOST = "127.0.0.1"
PORT = 9999

ML_TRAINING_SIZE = 8
BASE_SECRET = b"CHANGE-ME"


def create_hem_session():
    """Create a fresh simulated mission-data vault and HEM controller."""
    vault = DataVault()

    vault.add(
        "recon_images_batch1",
        CRITICAL,
        b"simulated reconnaissance imagery",
    )
    vault.add(
        "route_log",
        SENSITIVE,
        b"simulated mission route data",
    )
    vault.add(
        "weather_scan",
        ROUTINE,
        b"simulated weather data",
    )

    hem = HEMController(
        vault,
        PeerRegistry(),
        SimTransport(),
        base_secret=BASE_SECRET,
    )

    return vault, hem


def create_scenario_components():
    """Reset state that belongs to one scenario, not ML training."""
    return (
        AttackAnalyzer(),
        ResponseEngine(),
        ResponseEnforcer(),
        ThreatStats(),
    )


report = ReportGenerator()
logger = AttackLogger()

# Keep the ML detector and its training across scenarios.
ml_detector = TelemetryAnomalyDetector()
ml_training_packets = []
ml_trained = False

# Initial session
vault, hem = create_hem_session()
analyzer, engine, enforcer, stats = create_scenario_components()
active_scenario = None

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

print(f"[GCS] Listening on {HOST}:{PORT}")
print("[GCS] Waiting for simulated telemetry...\n")


try:
    while True:
        data, addr = sock.recvfrom(4096)

        try:
            packet = json.loads(data.decode("utf-8"))

            if not isinstance(packet, dict):
                print("[WARN] Ignoring non-object telemetry packet.")
                continue

            # Dashboard control messages are not telemetry and must
            # never enter the detection or ML pipeline.
            if packet.get("_scoutx_control") == "scenario_start":
                scenario_name = packet.get("scenario")

                if scenario_name not in {
                    "normal",
                    "gps_spoofing",
                    "command_injection",
                    "critical",
                }:
                    print("[WARN] Ignoring invalid scenario-start message.")
                    continue

                vault, hem = create_hem_session()
                analyzer, engine, enforcer, stats = (
                    create_scenario_components()
                )
                active_scenario = scenario_name

                print("\n" + "=" * 56)
                print(f"[SCENARIO] Started: {active_scenario}")
                print("[HEM] Fresh simulated mission vault created.")
                print("=" * 56 + "\n")
                continue

            # Preserve scenario identity for audit records.
            if active_scenario is not None:
                packet.setdefault("scenario", active_scenario)

            # Analyze attack pattern.
            pattern = analyzer.analyze(packet)

            # Train only on explicitly clean telemetry.
            if (
                not ml_trained
                and not packet.get("validation", {}).get(
                    "is_anomalous",
                    False,
                )
            ):
                ml_training_packets.append(packet)

                print(
                    f"[ML] Collecting clean telemetry: "
                    f"{len(ml_training_packets)}/{ML_TRAINING_SIZE}"
                )

                if len(ml_training_packets) >= ML_TRAINING_SIZE:
                    ml_detector.train(ml_training_packets)
                    ml_trained = True

                    print(
                        "[ML] Model trained on "
                        f"{len(ml_training_packets)} clean packets."
                    )

            # ML second opinion.
            ml_result = ml_detector.predict(packet)

            enriched_packet = {
                **packet,
                **pattern,
                **ml_result,
            }

            # Choose and enforce response.
            decision = engine.decide(enriched_packet)
            enriched_packet["response"] = decision
            enriched_packet = enforcer.enforce(enriched_packet)

            # HEM response and audit data.
            hem_result = hem.on_packet(enriched_packet)
            enriched_packet["hem"] = hem_result

            stats.update(enriched_packet)
            stats.display()

            logger.log(
                enriched_packet,
                pattern,
                decision,
            )

            trust_score = enriched_packet.get("trust_score", 1.0)

            print(
                f"[SEQ {enriched_packet.get('seq')}] | "
                f"{pattern.get('pattern', 'UNKNOWN')} "
                f"({pattern.get('severity', 'UNKNOWN')}) | "
                f"Trust: {trust_score:.2f} | "
                f"Response: {decision}"
            )

            print(
                f"  ML: "
                f"{'ANOMALY' if ml_result.get('ml_anomaly') else 'NORMAL'} | "
                f"Risk: {ml_result.get('ml_score', 0.0):.4f}"
            )

            print(
                f"  HEM: {hem_result.get('hem_phase')} | "
                f"Destination: {hem_result.get('destination')} | "
                f"Moved: {hem_result.get('moved', 0)}"
            )

            if hem_result.get("zeroized"):
                print(
                    "  HEM: ZEROIZED | "
                    "Items lost to zeroize: "
                    f"{hem_result.get('items_lost_to_zeroize', 0)}"
                )

            validation = enriched_packet.get("validation", {})
            if validation.get("is_anomalous"):
                print(f"  Flags: {validation.get('flags')}")

        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            print(f"[WARN] Ignoring invalid JSON packet: {exc}")
        except Exception as exc:
            print(f"[ERROR] Failed to process packet: {exc}")

except KeyboardInterrupt:
    print("\nStopping receiver...")
    report.generate()

finally:
    sock.close()
