from simulation.config import PROJECT_ROOT, settings
from simulation.logging.jsonl import JsonlEventWriter
from simulation.security.trust_engine import TrustTransitionEvent
from typing import Any


class AttackLogger:
    def __init__(self) -> None:
        # Store logs in the repository root, independent of the
        # terminal's current working directory.
        self.file = (
            PROJECT_ROOT / settings.logging.directory / settings.logging.attack_log
        )
        self.trust_file = (
            PROJECT_ROOT / settings.logging.directory / settings.logging.trust_log
        )
        self._writer = JsonlEventWriter(self.file)
        self._trust_writer = JsonlEventWriter(self.trust_file)

    def log(
        self,
        packet: dict[str, Any],
        pattern: dict[str, Any],
        decision: str,
        *,
        correlation_id: str | None = None,
    ) -> None:
        """Persist the enriched packet so dashboard and audit views share evidence."""
        hem = packet.get("hem") or {}
        validation = packet.get("validation") or {}

        details = {
            "correlation_id": correlation_id,
            "seq": packet.get("seq"),
            "gps": packet.get("gps"),
            "altitude": packet.get("altitude"),
            "speed": packet.get("speed"),
            "battery": packet.get("battery"),
            "trust_score": packet.get("trust_score"),
            "flagged": packet.get("flagged"),
            "pattern": pattern.get("pattern"),
            "severity": pattern.get("severity"),
            "deterministic_detected": bool(
                packet.get("flagged")
                or validation.get("is_anomalous")
                or validation.get("flags")
                or (
                    pattern.get("pattern")
                    and str(pattern.get("pattern")).upper()
                    not in {"NORMAL", "CLEAN", "NONE", "UNKNOWN"}
                    and str(pattern.get("severity") or "").upper()
                    not in {"", "LOW", "INFO"}
                )
            ),
            "flags": validation.get("flags", []),
            "validation": validation,
            "ml_anomaly": packet.get("ml_anomaly", False),
            "ml_score": packet.get("ml_score", 0.0),
            "ml_status": packet.get("ml_status"),
            "deterministic_response": packet.get("deterministic_response"),
            "ml_fusion": packet.get("ml_fusion"),
            "response": decision,
            "action": packet.get("action"),
            "enforced": packet.get("enforced"),
            "hem_phase": hem.get("hem_phase"),
            "hem_destination": hem.get("destination"),
            "hem_moved": hem.get("moved", 0),
            "hem_zeroized": hem.get("zeroized", False),
            "items_lost_to_zeroize": hem.get("items_lost_to_zeroize", 0),
            "hem": hem,
        }
        self._writer.append(
            event_type="TELEMETRY",
            severity=str(pattern.get("severity") or "INFO"),
            details=details,
            drone_id=packet.get("drone_id") or settings.network.drone_id,
            trust=packet.get("trust_score"),
            state=packet.get("trust_state") or hem.get("hem_phase"),
        )

    def log_trust_transition(self, event: TrustTransitionEvent) -> None:
        """Persist each state transition so response decisions have an audit trail."""
        transition = event.to_dict()
        self._trust_writer.append(
            event_type="TRUST_TRANSITION",
            severity="CRITICAL" if event.new_state.value == "PROTECT" else "INFO",
            details=transition,
            trust=event.trust,
            state=event.new_state.value,
        )
