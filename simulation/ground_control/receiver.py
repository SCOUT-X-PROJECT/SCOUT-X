from simulation.security.response_engine import ResponseEngine
from simulation.logging.attack_logger import AttackLogger
from simulation.analysis.attack_analyzer import AttackAnalyzer
from simulation.security.enforcer import ResponseEnforcer
from simulation.analysis.threat_stats import ThreatStats
from simulation.analysis.report_generator import ReportGenerator

from simulation.hem import HEMController, DataVault, PeerRegistry, SimTransport
from simulation.hem.vault import CRITICAL, SENSITIVE, ROUTINE

import socket
import json


analyzer = AttackAnalyzer()
report = ReportGenerator()
logger = AttackLogger()
engine = ResponseEngine()
enforcer = ResponseEnforcer()
stats = ThreatStats()

# HEM mission-data vault and simulated transport
vault = DataVault()
vault.add("recon_images_batch1", CRITICAL, b"simulated reconnaissance imagery")
vault.add("route_log", SENSITIVE, b"simulated mission route data")
vault.add("weather_scan", ROUTINE, b"simulated weather data")

hem = HEMController(
    vault,
    PeerRegistry(),
    SimTransport(),
    base_secret=b"CHANGE-ME"
)

HOST = "127.0.0.1"
PORT = 9999

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

print("[GCS] Listening on port 9999...\n")

try:
    while True:
        data, addr = sock.recvfrom(4096)

        try:
            packet = json.loads(data.decode())

            # Analyze attack pattern
            pattern = analyzer.analyze(packet)

            # Merge packet + pattern
            enriched_packet = {**packet, **pattern}

            # Decide response
            decision = engine.decide(enriched_packet)
            enriched_packet["response"] = decision

            # Enforce action
            enriched_packet = enforcer.enforce(enriched_packet)

            # HEM evaluates trust and response state
            hem_result = hem.on_packet(enriched_packet)
            enriched_packet["hem"] = hem_result

            # Update live stats
            stats.update(enriched_packet)
            stats.display()

            # Log event
            logger.log(enriched_packet, pattern, decision)

            # Console output
            trust_score = enriched_packet.get("trust_score", 1.0)

            print(
                f"[SEQ {enriched_packet.get('seq')}] | "
                f"{pattern['pattern']} ({pattern['severity']}) | "
                f"Trust: {trust_score:.2f} | "
                f"Response: {decision}"
            )

            # HEM console output
            print(
                f"  HEM: {hem_result.get('hem_phase')} | "
                f"Destination: {hem_result.get('destination')} | "
                f"Moved: {hem_result.get('moved', 0)}"
            )

            if hem_result.get("zeroized"):
                print(
                    f"  HEM: ZEROIZED | "
                    f"Items lost to zeroize: "
                    f"{hem_result.get('items_lost_to_zeroize', 0)}"
                )

            validation = enriched_packet.get("validation", {})
            if validation.get("is_anomalous"):
                print(f"  ⚠ Flags: {validation.get('flags')}")

        except Exception as e:
            print("[ERROR] Failed to parse packet:", e)

except KeyboardInterrupt:
    print("\nStopping receiver...")
    report.generate()