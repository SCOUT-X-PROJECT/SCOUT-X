"""Engineered rolling-window Isolation Forest for secondary telemetry alerts."""

from collections import deque
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import tempfile
from hmac import compare_digest
from typing import Any, ClassVar

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from simulation.config import PROJECT_ROOT, settings
from simulation.validators.motion_validator import haversine_distance_m


_BASE_FEATURES = (
    "gps_delta_distance_m",
    "implied_speed_mps",
    "reported_speed_mps",
    "speed_error_mps",
    "altitude_rate_mps",
    "battery_drain_rate_percent_per_s",
    "heading_change_deg",
    "inter_packet_time_s",
)


def _build_feature_names() -> tuple[str, ...]:
    """Keep the saved feature contract stable and explicit for model metadata."""
    return tuple(
        name
        for feature in _BASE_FEATURES
        for name in (
            f"window_mean_{feature}",
            f"window_max_abs_{feature}",
        )
    )


FEATURE_NAMES = _build_feature_names()


class TelemetryAnomalyDetector:
    """Fit only to reviewed clean telemetry and emit calibrated secondary signals."""

    feature_names: ClassVar[tuple[str, ...]] = FEATURE_NAMES

    def __init__(self) -> None:
        """Create a reproducible preprocessing/model pipeline and bounded history."""
        self.pipeline = Pipeline(
            steps=[
                ("scaler", StandardScaler()),
                (
                    "isolation_forest",
                    IsolationForest(
                        n_estimators=settings.ml.n_estimators,
                        contamination=settings.ml.contamination,
                        random_state=settings.ml.random_seed,
                    ),
                ),
            ]
        )
        self.trained = False
        self._calibration_scores = np.asarray([], dtype=float)
        self._packet_history: deque[dict[str, Any]] = deque(
            maxlen=settings.ml.feature_window_size
        )
        self.training_metadata: dict[str, Any] | None = None

    @staticmethod
    def _number(packet: dict[str, Any], key: str) -> float:
        value = packet.get(key)
        if value is None:
            raise ValueError(f"{key} must be a finite number")
        if isinstance(value, bool):
            raise ValueError(f"{key} must be a finite number")
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"{key} must be a finite number") from exc
        if not math.isfinite(number):
            raise ValueError(f"{key} must be a finite number")
        return number

    @classmethod
    def _normalized_packet(cls, packet: dict[str, Any]) -> dict[str, Any]:
        """Validate the feature inputs before numeric operations can poison a model."""
        gps = packet.get("gps")
        if isinstance(gps, dict):
            latitude = gps.get("lat", packet.get("lat"))
            longitude = gps.get("lon", packet.get("lon"))
        elif isinstance(gps, (list, tuple)) and len(gps) >= 2:
            latitude, longitude = gps[0], gps[1]
        else:
            latitude = packet.get("lat")
            longitude = packet.get("lon")

        normalized: dict[str, Any] = {
            "lat": cls._number({"value": latitude}, "value"),
            "lon": cls._number({"value": longitude}, "value"),
            "altitude": cls._number(packet, "altitude"),
            "speed": cls._number(packet, "speed"),
            "battery": cls._number(packet, "battery"),
            "timestamp": cls._number(packet, "timestamp"),
            "heading": None,
        }
        heading = packet.get("heading")
        if heading is not None:
            normalized["heading"] = cls._number({"value": heading}, "value")
        if not -90 <= normalized["lat"] <= 90:
            raise ValueError("latitude is outside geographic limits")
        if not -180 <= normalized["lon"] <= 180:
            raise ValueError("longitude is outside geographic limits")
        if normalized["speed"] < 0:
            raise ValueError("speed must not be negative")
        if normalized["battery"] < 0:
            raise ValueError("battery must not be negative")
        if normalized["altitude"] < 0:
            raise ValueError("altitude must not be negative")
        if normalized["heading"] is not None and not 0 <= normalized["heading"] < 360:
            raise ValueError("heading must be in [0, 360)")
        return normalized

    @staticmethod
    def _transition(
        previous: dict[str, Any] | None,
        current: dict[str, Any],
    ) -> np.ndarray:
        """Derive motion and sensor rates from consecutive normalized samples."""
        if previous is None:
            return np.zeros(len(_BASE_FEATURES), dtype=float)

        elapsed = current["timestamp"] - previous["timestamp"]
        if not math.isfinite(elapsed) or elapsed <= 0:
            raise ValueError("timestamps must increase between feature samples")
        distance = haversine_distance_m(
            previous["lat"],
            previous["lon"],
            current["lat"],
            current["lon"],
        )
        implied_speed = distance / elapsed
        heading_change = 0.0
        if previous["heading"] is not None and current["heading"] is not None:
            delta = abs(current["heading"] - previous["heading"]) % 360.0
            heading_change = min(delta, 360.0 - delta)
        return np.asarray(
            [
                distance,
                implied_speed,
                current["speed"],
                abs(implied_speed - current["speed"]),
                abs(current["altitude"] - previous["altitude"]) / elapsed,
                (previous["battery"] - current["battery"]) / elapsed,
                heading_change,
                elapsed,
            ],
            dtype=float,
        )

    @staticmethod
    def _rolling_row(
        transition: np.ndarray,
        rolling_transitions: deque[np.ndarray],
    ) -> np.ndarray:
        rolling_transitions.append(transition)
        matrix = np.vstack(rolling_transitions)
        means = np.mean(matrix, axis=0)
        maximum_absolute = np.max(np.abs(matrix), axis=0)
        row = np.column_stack((means, maximum_absolute)).reshape(-1)
        if not np.isfinite(row).all():
            raise ValueError("engineered features must all be finite")
        return row

    @classmethod
    def _training_matrix(
        cls,
        packets: list[dict[str, Any]],
    ) -> tuple[np.ndarray, list[dict[str, Any]]]:
        """Build leakage-free rolling features in packet order for clean data only."""
        normalized_packets: list[dict[str, Any]] = []
        rolling_transitions: deque[np.ndarray] = deque(
            maxlen=settings.ml.feature_window_size
        )
        previous: dict[str, Any] | None = None
        rows: list[np.ndarray] = []
        for packet in packets:
            if not isinstance(packet, dict):
                raise ValueError("training samples must be telemetry dictionaries")
            validation = packet.get("validation", {})
            if not isinstance(validation, dict):
                raise ValueError("training validation metadata must be a dictionary")
            if (
                validation.get("is_anomalous") is True
                or packet.get("is_clean") is False
                or str(packet.get("label", "")).lower()
                in {"attack", "anomaly", "malicious"}
            ):
                raise ValueError("training data must contain only clean telemetry")
            current = cls._normalized_packet(packet)
            rows.append(
                cls._rolling_row(
                    cls._transition(previous, current),
                    rolling_transitions,
                )
            )
            normalized_packets.append(current)
            previous = current
        return np.asarray(rows, dtype=float), normalized_packets

    def _prediction_row(self, packet: dict[str, Any]) -> np.ndarray:
        current = self._normalized_packet(packet)
        previous_packets = list(self._packet_history)
        transitions: deque[np.ndarray] = deque(maxlen=settings.ml.feature_window_size)
        previous: dict[str, Any] | None = None
        for history_packet in previous_packets:
            transitions.append(self._transition(previous, history_packet))
            previous = history_packet
        row = self._rolling_row(
            self._transition(previous, current),
            transitions,
        )
        self._packet_history.append(current)
        return row

    def train(self, clean_packets: list[dict[str, Any]]) -> None:
        """Fit preprocessing and forest only from explicitly clean ordered samples."""
        if len(clean_packets) < settings.ml.minimum_training_samples:
            raise ValueError(
                "At least "
                f"{settings.ml.minimum_training_samples} clean packets "
                "are required for ML training"
            )
        matrix, normalized_packets = self._training_matrix(clean_packets)
        if not np.isfinite(matrix).all():
            raise ValueError("training features must all be finite")

        calibration_count = max(
            1,
            math.ceil(len(matrix) * settings.ml.calibration_fraction),
        )
        permutation = np.random.RandomState(settings.ml.random_seed).permutation(
            len(matrix)
        )
        calibration_indices = permutation[:calibration_count]
        fit_indices = permutation[calibration_count:]
        fit_count = len(fit_indices)
        fit_matrix = matrix[fit_indices]
        calibration_matrix = matrix[calibration_indices]
        self.pipeline.fit(fit_matrix)
        self._calibration_scores = np.sort(
            self.pipeline.score_samples(calibration_matrix).astype(float)
        )
        self._packet_history.clear()
        self._packet_history.extend(
            normalized_packets[-settings.ml.feature_window_size :]
        )
        self.trained = True
        self.training_metadata = {
            "feature_list": list(self.feature_names),
            "sklearn_version": sklearn.__version__,
            "training_date": datetime.now(timezone.utc).isoformat(),
            "data_hash": hashlib.sha256(
                np.ascontiguousarray(matrix, dtype=np.float64).tobytes()
            ).hexdigest(),
            "training_samples": len(clean_packets),
            "fit_samples": fit_count,
            "calibration_samples": calibration_count,
            "risk_mapping": (
                "empirical lower-tail percentile of held-out clean score_samples"
            ),
            "risk_threshold": settings.ml.risk_threshold,
            "feature_window_size": settings.ml.feature_window_size,
            "calibration_fraction": settings.ml.calibration_fraction,
        }

    def _risk_from_score(self, score: float) -> float:
        """Map low forest scores to their empirical lower-tail clean percentile."""
        left = int(np.searchsorted(self._calibration_scores, score, side="left"))
        right = int(np.searchsorted(self._calibration_scores, score, side="right"))
        tied = right - left
        return float(
            np.clip(
                (len(self._calibration_scores) - right + 0.5 * tied)
                / len(self._calibration_scores),
                0.0,
                1.0,
            )
        )

    @staticmethod
    def _result(
        *,
        status: str,
        anomaly: bool = False,
        score: float | None = None,
        detail: str | None = None,
    ) -> dict[str, bool | float | str | None]:
        result: dict[str, bool | float | str | None] = {
            "ml_status": status,
            "ml_anomaly": anomaly,
            "ml_score": score,
        }
        if detail is not None:
            result["ml_detail"] = detail
        return result

    def predict(
        self,
        packet: dict[str, Any],
    ) -> dict[str, bool | float | str | None]:
        """Return readiness explicitly and percentile-calibrated risk when trained."""
        try:
            row = self._prediction_row(packet)
        except (TypeError, ValueError, OverflowError, KeyError) as exc:
            return self._result(
                status="invalid_input",
                detail=str(exc),
            )

        if not self.trained:
            return self._result(status="model_not_ready")

        score = float(self.pipeline.score_samples(row.reshape(1, -1))[0])
        risk = self._risk_from_score(score)
        return self._result(
            status="ready",
            anomaly=risk > settings.ml.risk_threshold,
            score=round(risk, 4),
        )

    @staticmethod
    def _metadata_path(model_path: Path) -> Path:
        return model_path.with_suffix(model_path.suffix + ".json")

    @staticmethod
    def _resolve_model_path(path: str | Path | None) -> Path:
        """Constrain deserialization to the configured model directory in deployments."""
        candidate = (
            Path(path) if path is not None else PROJECT_ROOT / settings.ml.model_path
        ).expanduser()
        trusted = (PROJECT_ROOT / settings.ml.trusted_model_directory).resolve()
        resolved = candidate.resolve()
        if not settings.network.dev_mode and (
            not resolved.is_relative_to(trusted) or candidate.is_symlink()
        ):
            raise ValueError("model path is outside the trusted model directory")
        return resolved

    def save(self, path: str | Path | None = None) -> tuple[Path, Path]:
        """Persist a trusted local model and sidecar calibration metadata."""
        if not self.trained or self.training_metadata is None:
            raise RuntimeError("cannot persist a model before clean-data training")
        model_path = self._resolve_model_path(path)
        model_path.parent.mkdir(parents=True, exist_ok=True)
        metadata_path = self._metadata_path(model_path)
        with tempfile.NamedTemporaryFile(
            dir=model_path.parent, prefix=f".{model_path.name}.", delete=False
        ) as temporary:
            temporary_path = Path(temporary.name)
        try:
            joblib.dump(
                {
                    "pipeline": self.pipeline,
                    "calibration_scores": self._calibration_scores,
                    "packet_history": list(self._packet_history),
                },
                temporary_path,
            )
            os.replace(temporary_path, model_path)
        finally:
            temporary_path.unlink(missing_ok=True)
        model_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
        metadata = dict(self.training_metadata)
        metadata["model_sha256"] = model_hash
        metadata_path.write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.training_metadata = metadata
        return model_path, metadata_path

    @classmethod
    def load(cls, path: str | Path | None = None) -> "TelemetryAnomalyDetector":
        """Load a local model only when its feature and sklearn contracts match."""
        model_path = cls._resolve_model_path(path)
        metadata_path = cls._metadata_path(model_path)
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if metadata.get("feature_list") != list(cls.feature_names):
            raise ValueError("saved model feature list does not match this detector")
        if metadata.get("sklearn_version") != sklearn.__version__:
            raise ValueError("saved model scikit-learn version does not match runtime")
        if metadata.get("feature_window_size") != settings.ml.feature_window_size:
            raise ValueError(
                "saved model rolling feature window does not match runtime"
            )
        expected_hash = metadata.get("model_sha256")
        if not isinstance(expected_hash, str) or not compare_digest(
            hashlib.sha256(model_path.read_bytes()).hexdigest(), expected_hash
        ):
            raise ValueError("saved model integrity hash does not match")
        artifacts = joblib.load(model_path)
        detector = cls()
        detector.pipeline = artifacts["pipeline"]
        detector._calibration_scores = np.asarray(
            artifacts["calibration_scores"],
            dtype=float,
        )
        detector._packet_history.extend(artifacts.get("packet_history", []))
        if (
            detector._calibration_scores.size == 0
            or not np.isfinite(detector._calibration_scores).all()
        ):
            raise ValueError("saved model calibration scores are invalid")
        detector.trained = True
        detector.training_metadata = metadata
        return detector
