class DefenseLogic:
    def __init__(self):
        self.last_safe_altitude = None

    def apply_defense(self, data):

        # TRUST-BASED CONTROL
        if data.get("trust_score", 1.0) < 0.8:
            data["action"] = "TRUST_LOW_MODE"

            if self.last_safe_altitude is not None:
                data["altitude"] = self.last_safe_altitude
            else:
                self.last_safe_altitude = data.get("altitude", 0)

        else:
            # update safe altitude during normal operation
            if data.get("trust_score", 1.0) > 0.8:
                self.last_safe_altitude = data.get("altitude", 0)

        # DEFENSE LOGIC
        if data.get("flagged") and data.get("trust_score", 1.0) >= 0.8:
            print("[DEFENSE] Taking corrective action")

            if "altitude" in data and data["altitude"] > 100:
                data["altitude"] = 100

            data["action"] = "ALTITUDE_CLAMPED"

        return data