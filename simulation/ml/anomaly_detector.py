import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class TelemetryAnomalyDetector:
    """
    Lightweight unsupervised ML anomaly detector for UAV telemetry.

    The detector learns the expected telemetry distribution from
    normal observations and assigns an anomaly-risk score to new
    telemetry packets.
    """

    def __init__(self):
        self.scaler = StandardScaler()

        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.10,
            random_state=42
        )

        self.trained = False

    @staticmethod
    def _features(packet):
        gps = packet.get("gps", [0.0, 0.0])

        if isinstance(gps, dict):
            latitude = gps.get("lat", 0.0)
            longitude = gps.get("lon", 0.0)
        else:
            latitude = gps[0] if len(gps) > 0 else 0.0
            longitude = gps[1] if len(gps) > 1 else 0.0

        return [
            float(latitude),
            float(longitude),
            float(packet.get("altitude", 0.0)),
            float(packet.get("speed", 0.0)),
            float(packet.get("battery", 0.0)),
        ]

    def train(self, normal_packets):
        if len(normal_packets) < 5:
            raise ValueError(
                "At least 5 normal packets are required for ML training"
            )

        X = np.array(
            [self._features(packet) for packet in normal_packets],
            dtype=float
        )

        X_scaled = self.scaler.fit_transform(X)

        self.model.fit(X_scaled)
        self.trained = True

    def predict(self, packet):
        if not self.trained:
            return {
                "ml_anomaly": False,
                "ml_score": 0.0
            }

        X = np.array(
            [self._features(packet)],
            dtype=float
        )

        X_scaled = self.scaler.transform(X)

        prediction = self.model.predict(X_scaled)[0]
        raw_score = float(
            self.model.decision_function(X_scaled)[0]
        )

        # Isolation Forest produces higher values for normal
        # observations and lower values for anomalies.
        risk_score = max(
            0.0,
            min(
                1.0,
                0.5 - raw_score
            )
        )

        return {
            "ml_anomaly": bool(prediction == -1),
            "ml_score": round(float(risk_score), 4)
        }