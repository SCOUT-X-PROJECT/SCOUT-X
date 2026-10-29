
import json
from datetime import datetime, timezone
from pathlib import Path


class AttackLogger:
    def __init__(self):
        # Store logs in the repository root, independent of the
        # terminal's current working directory.
        self.file = (
            Path(__file__).resolve().parents[2]
            / "attack_log.json"
        )

    def log(self, packet, pattern, decision):
        hem = packet.get("hem") or {}
        validation = packet.get("validation") or {}

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "seq": packet.get("seq"),

            # Telemetry
            "gps": packet.get("gps"),
            "altitude": packet.get("altitude"),
            "speed": packet.get("speed"),
            "battery": packet.get("battery"),

            # Trust and detection
            "trust_score": packet.get("trust_score"),
            "flagged": packet.get("flagged"),
            "pattern": pattern.get("pattern"),
            "severity": pattern.get("severity"),
            "flags": validation.get("flags", []),

            # ML anomaly detection
            "ml_anomaly": packet.get("ml_anomaly", False),
            "ml_score": packet.get("ml_score", 0.0),

            # Response and enforcement
            "response": decision,
            "action": packet.get("action"),
            "enforced": packet.get("enforced"),

            # HEM: preserve actual returned values
            "hem_phase": hem.get("hem_phase"),
            "hem_destination": hem.get("destination"),
            "hem_moved": hem.get("moved", 0),
            "hem_zeroized": hem.get("zeroized", False),
            "items_lost_to_zeroize": hem.get(
                "items_lost_to_zeroize", 0
            ),
            "hem": hem,
        }

        with self.file.open("a", encoding="utf-8") as log_file:
            log_file.write(json.dumps(log_entry) + "\n")
