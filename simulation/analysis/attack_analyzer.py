import math
from typing import Any

from simulation.config import settings


class AttackAnalyzer:
    def __init__(self, window_size: int | None = None) -> None:
        self.history: list[dict[str, Any]] = []
        self.window_size = (
            settings.trust.attack_history_window if window_size is None else window_size
        )

    def analyze(self, packet: dict[str, Any]) -> dict[str, str]:
        """Use a rolling window so one transient packet does not dominate classification."""
        validation = packet.get("validation", {})
        is_anomalous = validation.get("is_anomalous", False)

        # Store history
        self.history.append(
            {
                "seq": packet.get("seq"),
                "anomaly": is_anomalous,
                "flags": validation.get("flags", []),
            }
        )

        # Maintain fixed window
        if len(self.history) > self.window_size:
            self.history.pop(0)

        return self._detect_patterns()

    def _detect_patterns(self) -> dict[str, str]:
        anomaly_count = sum(1 for h in self.history if h["anomaly"])

        # Pattern 1: Persistent anomaly
        persistent_required = math.ceil(
            settings.trust.persistent_attack_ratio * len(self.history)
        )
        if self.history and anomaly_count >= persistent_required:
            return {"pattern": "PERSISTENT_ATTACK", "severity": "HIGH"}

        # Pattern 2: Frequent spikes
        intermittent_required = math.ceil(
            settings.trust.intermittent_attack_ratio * len(self.history)
        )
        if self.history and anomaly_count >= intermittent_required:
            return {"pattern": "INTERMITTENT_ATTACK", "severity": "MEDIUM"}

        return {"pattern": "NORMAL", "severity": "LOW"}
