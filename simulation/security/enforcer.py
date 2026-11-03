from typing import Any


class ResponseEnforcer:
    def enforce(self, packet: dict[str, Any]) -> dict[str, Any]:
        """Keep response output console-safe so logging cannot interrupt enforcement."""
        response = packet.get("response")

        if response == "FORCE_LAND":
            print("[ENFORCER] Initiating emergency landing protocol")
            packet["enforced"] = "LANDING"

        elif response == "ISOLATE_DRONE":
            print("[ENFORCER] Isolating drone from network")
            packet["enforced"] = "ISOLATED"

        elif response == "LIMIT_MOVEMENT":
            print("[ENFORCER] Limiting drone movement")
            packet["enforced"] = "RESTRICTED"

        elif response == "MONITOR":
            print("[ENFORCER] Monitoring drone behavior")
            packet["enforced"] = "MONITORING"

        else:
            packet["enforced"] = "NONE"

        return packet
