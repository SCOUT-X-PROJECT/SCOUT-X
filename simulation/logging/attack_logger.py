import json
from datetime import datetime


class AttackLogger:
    def __init__(self):
        self.file = "attack_log.json"

    def log(self, packet, pattern, decision):
        hem = packet.get("hem", {})

        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
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
            "flags": packet.get("validation", {}).get("flags", []),

            # Response and enforcement
            "response": decision,
            "action": packet.get("action"),
            "enforced": packet.get("enforced"),

            # HEM state
            "hem_phase": hem.get("hem_phase"),
            "hem_destination": hem.get("destination"),
            "hem_moved": hem.get("moved", 0),
            "hem_zeroized": hem.get("zeroized", False),
            "items_lost_to_zeroize": hem.get(
                "items_lost_to_zeroize", 0
            ),

            # Preserve complete HEM result for analysis/dashboard
            "hem": hem
        }

        with open(self.file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")