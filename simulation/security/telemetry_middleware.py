class SecurityMiddleware:
    def __init__(self):
        self.trust_score = 1.0
        self.anomaly_threshold = 0.6
        self.prev_altitude = None

    def validate_telemetry(self, data):
        """
        Main entry point for all telemetry data
        """

        # STEP 0 — sanitize garbage input
        data = self.sanitize_data(data)

        # STEP 1 — anomaly detection
        anomaly = self.detect_anomaly(data)

        # STEP 2 — trust update
        if anomaly:
            self.update_trust(flag=True)
            data["flagged"] = True
        else:
            self.update_trust(flag=False)
            data["flagged"] = False

        data["trust_score"] = self.trust_score
        return data

    def sanitize_data(self, data):
        """
        Clamp physically impossible values
        """

        # Battery cannot be negative or >100
        if "battery" in data:
            data["battery"] = max(0, min(100, data["battery"]))

        # Speed cannot be negative
        if "speed" in data:
            data["speed"] = max(0, data["speed"])

        # Altitude cannot be negative
        if "altitude" in data:
            data["altitude"] = max(0, data["altitude"])

        return data

    def detect_anomaly(self, data):
        anomaly_detected = False

        # --- GPS sanity ---
        if "gps" in data:
            gps = data["gps"]
            if abs(gps.get("lat", 0)) > 90 or abs(gps.get("lon", 0)) > 180:
                anomaly_detected = True

        # --- NOISE check ---
        if data.get("noise_level", 0) > 0.8:
            anomaly_detected = True

        # --- ALTITUDE absolute ---
        if "altitude" in data:
            if data["altitude"] > 100:
                print("[SECURITY] ALERT: Altitude anomaly detected")
                anomaly_detected = True

        # --- ALTITUDE delta ---
        if "altitude" in data:
            if self.prev_altitude is not None:
                delta = abs(data["altitude"] - self.prev_altitude)

                if delta > 50:
                    print("[SECURITY] ALERT: Sudden altitude change detected")
                    anomaly_detected = True

            self.prev_altitude = data["altitude"]

        return anomaly_detected

    def update_trust(self, flag):
        """
        Adjust trust score based on behavior
        """
        if flag:
            self.trust_score -= 0.1
        else:
            self.trust_score += 0.02

        # clamp between 0 and 1
        self.trust_score = max(0.0, min(1.0, self.trust_score))