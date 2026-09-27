import numpy as np
from sklearn.ensemble import IsolationForest


class TelemetryAnomalyDetector:
    """
    Lightweight unsupervised anomaly detector for UAV telemetry.

    The detector learns the expected telemetry distribution from
    normal observations and assigns an anomaly score to new packets.
    """

    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
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
        if not normal_packets:
            raise ValueError("Training data cannot be empty")

        X = np.array(
            [self._features(packet) for packet in normal_packets],
            dtype=float
        )

        self.model.fit(X)
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

        prediction = self.model.predict(X)[0]
        raw_score = self.model.decision_function(X)[0]

        # Convert Isolation Forest score into a simple 0-1
        # anomaly-risk representation.
        risk_score = max(
            0.0,
            min(1.0, 0.5 - float(raw_score))
        )

        return {
            "ml_anomaly": bool(prediction == -1),
            "ml_score": round(float(risk_score), 4)
        }