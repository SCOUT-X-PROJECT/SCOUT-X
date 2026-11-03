"""Run the authenticated telemetry receiver and ground-control processing pipeline."""

import asyncio
from datetime import datetime, timezone
import logging
import secrets
import signal
from typing import Any

from simulation.analysis.attack_analyzer import AttackAnalyzer
from simulation.reporting.report_generator import ReportGenerator
from simulation.analysis.threat_stats import ThreatStats
from simulation.config import settings
from simulation.ground_control.udp_receiver import TelemetryUDPReceiver
from simulation.hem import (
    DataVault,
    HEMController,
    PeerRegistry,
    SimTransport,
)
from simulation.hem.vault import CRITICAL, ROUTINE, SENSITIVE
from simulation.logging.attack_logger import AttackLogger
from simulation.ml.anomaly_detector import TelemetryAnomalyDetector
from simulation.pipeline import SecurityPipeline
from simulation.pipeline import EventBus
from simulation.contracts import SecurityEvent
from simulation.security.enforcer import ResponseEnforcer
from simulation.security.response_engine import ResponseEngine
from simulation.security.telemetry_middleware import SecurityMiddleware
from simulation.security.telemetry_schema import (
    ValidationReason,
    ValidationResult,
)


_VALID_SCENARIOS = {
    "normal",
    "gps_spoofing",
    "command_injection",
    "critical",
}


def is_clean_training_sample(result: ValidationResult) -> bool:
    """Keep accepted packet-loss gaps out of the clean ML baseline."""
    return (
        result.accepted
        and result.reason_code is ValidationReason.ACCEPTED
        and result.classification in (None, "UNKNOWN")
    )


def create_hem_session() -> tuple[DataVault, HEMController]:
    """Isolate each scenario's data so prior protection state cannot leak forward."""
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

    configured_secret = settings.hem.base_secret.get_secret_value()
    base_secret = (
        configured_secret.encode("utf-8")
        if configured_secret
        else secrets.token_bytes(settings.hem.hkdf_key_size_bytes)
    )
    hem = HEMController(
        vault,
        PeerRegistry(),
        SimTransport(),
        base_secret=base_secret,
    )
    return vault, hem


def create_scenario_components() -> tuple[
    AttackAnalyzer,
    ResponseEngine,
    ResponseEnforcer,
    ThreatStats,
]:
    """Reset scenario-local detectors while retaining the clean ML baseline."""
    return AttackAnalyzer(), ResponseEngine(), ResponseEnforcer(), ThreatStats()


def create_receiver() -> tuple[TelemetryUDPReceiver, ReportGenerator]:
    """Bind the network boundary to the existing analysis and response pipeline."""
    settings.initialize_runtime_secrets()
    report = ReportGenerator()
    logger = AttackLogger()
    ml_detector = TelemetryAnomalyDetector()
    event_bus = EventBus()

    def publish_transition(event: Any) -> None:
        event_bus.publish(
            SecurityEvent(
                correlation_id=f"receiver:trust:{int(event.timestamp)}",
                timestamp=datetime.now(timezone.utc),
                event_type="TRUST_TRANSITION",
                severity="CRITICAL" if event.new_state.value == "PROTECT" else "INFO",
                trust=event.trust,
                state=event.new_state.value,
                message=event.trigger_reason,
                details=event.to_dict(),
            )
        )

    security = SecurityMiddleware(event_callback=publish_transition)
    vault, hem = create_hem_session()
    analyzer, engine, enforcer, stats = create_scenario_components()
    pipeline = SecurityPipeline(
        security=security,
        analyzer=analyzer,
        ml_detector=ml_detector,
        response_engine=engine,
        enforcer=enforcer,
        hem=hem,
        logger=logger,
        stats=stats,
        event_bus=event_bus,
    )
    event_bus.subscribe_sink(report.consume_event)
    active_scenario: str | None = None

    def handle_control(packet: dict[str, Any]) -> None:
        """Handle authenticated scenario controls at the receiver boundary."""
        nonlocal vault, hem, analyzer, engine, enforcer, stats, active_scenario
        control = packet.get("_scoutx_control")
        if control == "scenario_end":
            return
        if control == "protect_reset":
            reset_token = packet.get("reset_token")
            if not isinstance(reset_token, str) or not security.reset_protect(
                reset_token
            ):
                raise ValueError(
                    "Ignoring invalid authenticated PROTECT reset command."
                )
            print("\n[TRUST] Authenticated PROTECT reset accepted.")
            return
        if control != "scenario_start":
            raise ValueError("Ignoring unknown authenticated control message.")
        scenario_name = packet.get("scenario")
        if scenario_name not in _VALID_SCENARIOS:
            raise ValueError("Ignoring invalid authenticated scenario-start message.")
        vault, hem = create_hem_session()
        analyzer, engine, enforcer, stats = create_scenario_components()
        pipeline.reset_scenario(
            hem=hem,
            analyzer=analyzer,
            response_engine=engine,
            enforcer=enforcer,
            scenario=scenario_name,
            stats=stats,
        )
        active_scenario = scenario_name
        print(f"\n[SCENARIO] Started: {active_scenario}")
        print("[HEM] Fresh simulated mission vault created.\n")

    def process_result(validation_result: ValidationResult) -> None:
        """Run CPU-heavy analysis in a worker so socket intake remains responsive."""
        result = pipeline.process_validation(validation_result)
        if not result.validation.accepted:
            print("[REJECTED]", result.validation.reason_code.value)
            return
        trust_score = result.state.trust_score
        pattern = result.threat.pattern if result.threat else "UNKNOWN"
        severity = result.threat.severity if result.threat else "UNKNOWN"
        decision = (
            result.response.response.value if result.response else "ISOLATE_DRONE"
        )
        ml_result = result.ml
        hem_result = result.hem
        print(
            f"[CORR {result.correlation_id}] | "
            f"{pattern} ({severity}) | "
            f"Trust: {trust_score:.2f} | Response: {decision}"
        )
        print(
            f"  ML: {'ANOMALY' if ml_result and ml_result.anomaly else 'NORMAL'} | "
            f"Status: {ml_result.status if ml_result else 'n/a'} | "
            f"Risk: {ml_result.risk_score if ml_result and ml_result.risk_score is not None else 'n/a'}"
        )
        print(
            f"  HEM: {hem_result.phase if hem_result else 'n/a'} | "
            f"Destination: {hem_result.destination if hem_result else 'n/a'} | "
            f"Moved: {hem_result.moved_bytes if hem_result else 0}"
        )
        if hem_result and hem_result.zeroized:
            print(f"  HEM: ZEROIZED | Items lost to zeroize: {hem_result.moved_bytes}")

    receiver = TelemetryUDPReceiver(
        security=security,
        packet_handler=process_result,
        control_handler=handle_control,
    )
    return receiver, report


async def run_receiver() -> None:
    """Serve authenticated packets and flush report/log handlers on shutdown."""
    receiver, report = create_receiver()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signum, receiver.stop)
        except (NotImplementedError, RuntimeError):
            signal.signal(
                signum,
                lambda *_: loop.call_soon_threadsafe(receiver.stop),
            )

    address = f"{receiver.host}:{receiver.port}"
    print(f"[GCS] Listening on {address}")
    print("[GCS] Waiting for authenticated telemetry...\n")
    try:
        await receiver.run()
    finally:
        report.generate()
        logging.shutdown()


if __name__ == "__main__":
    try:
        asyncio.run(run_receiver())
    except KeyboardInterrupt:
        print("\nStopping receiver...")
