import json
import math
from pathlib import Path
from typing import Any

import pytest
from sklearn.pipeline import Pipeline

from simulation.config import settings
from simulation.ml.anomaly_detector import FEATURE_NAMES, TelemetryAnomalyDetector
from simulation.ml.fusion import fuse_ml_signal


def clean_packets(count: int = 20) -> list[dict[str, Any]]:
    """Build ordered, clean simulator-shaped telemetry with plausible transitions."""
    packets: list[dict[str, Any]] = []
    latitude = 12.9716
    for sequence in range(count):
        if sequence:
            latitude += math.degrees(
                (10.0 + sequence % 3) / settings.validation.earth_radius_meters
            )
        packets.append(
            {
                "drone_id": "ml-test",
                "sequence": sequence,
                "timestamp": 1_800_000_000.0 + sequence,
                "lat": latitude,
                "lon": 77.5946,
                "altitude": 100.0 + 0.1 * (sequence % 3),
                "speed": 10.0 + sequence % 3,
                "battery": 95.0 - 0.1 * sequence,
                "heading": float(sequence % 360),
                "validation": {"is_anomalous": False},
            }
        )
    return packets


def test_untrained_detector_reports_readiness_not_fake_score() -> None:
    result = TelemetryAnomalyDetector().predict(clean_packets()[0])

    assert result == {
        "ml_status": "model_not_ready",
        "ml_anomaly": False,
        "ml_score": None,
    }


def test_pipeline_engineers_rolling_motion_features() -> None:
    detector = TelemetryAnomalyDetector()
    detector.train(clean_packets())

    assert isinstance(detector.pipeline, Pipeline)
    assert (
        detector.pipeline.named_steps["scaler"].__class__.__name__ == "StandardScaler"
    )
    assert (
        detector.pipeline.named_steps["isolation_forest"].__class__.__name__
        == "IsolationForest"
    )
    assert len(FEATURE_NAMES) == 16
    assert any("gps_delta_distance_m" in name for name in FEATURE_NAMES)
    assert any("speed_error_mps" in name for name in FEATURE_NAMES)
    assert any("altitude_rate_mps" in name for name in FEATURE_NAMES)
    assert any("battery_drain_rate" in name for name in FEATURE_NAMES)
    assert any("heading_change_deg" in name for name in FEATURE_NAMES)
    assert any("inter_packet_time_s" in name for name in FEATURE_NAMES)
    assert detector.pipeline.named_steps["scaler"].n_features_in_ == len(FEATURE_NAMES)
    assert detector.training_metadata is not None
    assert detector.training_metadata["fit_samples"] == 16
    assert detector.training_metadata["calibration_samples"] == 4
    assert len(detector.training_metadata["data_hash"]) == 64


def test_requires_minimum_clean_training_samples() -> None:
    with pytest.raises(ValueError, match="At least"):
        TelemetryAnomalyDetector().train(clean_packets()[:4])


@pytest.mark.parametrize(
    "dirty_marker",
    [
        {"validation": {"is_anomalous": True}},
        {"is_clean": False},
        {"label": "attack"},
    ],
)
def test_training_rejects_explicitly_non_clean_samples(
    dirty_marker: dict[str, Any],
) -> None:
    samples = clean_packets()
    samples[3].update(dirty_marker)

    with pytest.raises(ValueError, match="only clean"):
        TelemetryAnomalyDetector().train(samples)


def test_nan_inference_is_rejected_without_crashing() -> None:
    detector = TelemetryAnomalyDetector()
    detector.train(clean_packets())
    invalid = clean_packets(1)[0]
    invalid["speed"] = float("nan")

    result = detector.predict(invalid)

    assert result["ml_status"] == "invalid_input"
    assert result["ml_score"] is None
    assert result["ml_anomaly"] is False


def test_non_monotonic_time_is_invalid_inference() -> None:
    detector = TelemetryAnomalyDetector()
    detector.train(clean_packets())
    invalid = clean_packets(1)[0]
    invalid["timestamp"] = clean_packets()[-1]["timestamp"]

    result = detector.predict(invalid)

    assert result["ml_status"] == "invalid_input"
    assert "timestamps must increase" in str(result["ml_detail"])


def test_constant_features_produce_finite_calibrated_score() -> None:
    samples = [
        {
            "lat": 1.0,
            "lon": 1.0,
            "altitude": 10.0,
            "speed": 0.0,
            "battery": 50.0,
            "timestamp": 1_800_000_000.0 + index,
            "heading": 0.0,
        }
        for index in range(12)
    ]
    detector = TelemetryAnomalyDetector()
    detector.train(samples)

    result = detector.predict(
        {
            **samples[-1],
            "timestamp": samples[-1]["timestamp"] + 1,
        }
    )

    assert result["ml_status"] == "ready"
    assert math.isfinite(float(result["ml_score"]))
    assert 0.0 <= float(result["ml_score"]) <= 1.0
    assert result["ml_anomaly"] is False


def test_training_is_deterministic() -> None:
    samples = clean_packets()
    first = TelemetryAnomalyDetector()
    second = TelemetryAnomalyDetector()
    first.train(samples)
    second.train(samples)
    candidate = clean_packets()[-1] | {
        "timestamp": clean_packets()[-1]["timestamp"] + 1
    }

    assert first.predict(candidate) == second.predict(candidate)
    assert first.training_metadata is not None
    assert first.training_metadata["data_hash"] == second.training_metadata["data_hash"]


def test_risk_is_empirical_percentile_and_bounded() -> None:
    detector = TelemetryAnomalyDetector()
    detector.train(clean_packets())
    assert detector._risk_from_score(float(detector._calibration_scores[0])) > (
        detector._risk_from_score(float(detector._calibration_scores[-1]))
    )

    result = detector.predict(
        {
            **clean_packets()[-1],
            "timestamp": clean_packets()[-1]["timestamp"] + 1,
            "lat": 14.0,
            "speed": 100.0,
        }
    )

    assert result["ml_status"] == "ready"
    assert 0.0 <= float(result["ml_score"]) <= 1.0
    assert result["ml_anomaly"] is (
        float(result["ml_score"]) > settings.ml.risk_threshold
    )


def test_save_and_load_round_trip_and_refuse_feature_mismatch(tmp_path: Path) -> None:
    detector = TelemetryAnomalyDetector()
    detector.train(clean_packets())
    model_path, metadata_path = detector.save(tmp_path / "model.joblib")
    candidate = {
        **clean_packets()[-1],
        "timestamp": clean_packets()[-1]["timestamp"] + 1,
    }
    expected = detector.predict(candidate)

    loaded = TelemetryAnomalyDetector.load(model_path)

    assert metadata_path.exists()
    assert loaded.predict(candidate) == expected

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["feature_list"].append("unexpected_feature")
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    with pytest.raises(ValueError, match="feature list"):
        TelemetryAnomalyDetector.load(model_path)


@pytest.mark.parametrize(
    ("deterministic", "ml_result", "expected", "escalated"),
    [
        (
            "NORMAL_OPERATION",
            {"ml_status": "model_not_ready", "ml_anomaly": False},
            "NORMAL_OPERATION",
            False,
        ),
        (
            "NORMAL_OPERATION",
            {"ml_status": "invalid_input", "ml_anomaly": False},
            "NORMAL_OPERATION",
            False,
        ),
        (
            "NORMAL_OPERATION",
            {"ml_status": "ready", "ml_anomaly": True},
            "MONITOR",
            True,
        ),
        (
            "MONITOR",
            {"ml_status": "ready", "ml_anomaly": True},
            "LIMIT_MOVEMENT",
            True,
        ),
        (
            "LIMIT_MOVEMENT",
            {"ml_status": "ready", "ml_anomaly": True},
            "LIMIT_MOVEMENT",
            False,
        ),
        (
            "ISOLATE_DRONE",
            {"ml_status": "ready", "ml_anomaly": True},
            "ISOLATE_DRONE",
            False,
        ),
        (
            "FORCE_LAND",
            {"ml_status": "ready", "ml_anomaly": True},
            "FORCE_LAND",
            False,
        ),
    ],
)
def test_ml_fusion_only_raises_bounded_secondary_response(
    deterministic: str,
    ml_result: dict[str, Any],
    expected: str,
    escalated: bool,
) -> None:
    result = fuse_ml_signal(deterministic, ml_result)

    assert result["response"] == expected
    assert result["ml_escalated"] is escalated
    assert result["response"] not in {"ISOLATE_DRONE", "FORCE_LAND"} or (
        deterministic in {"ISOLATE_DRONE", "FORCE_LAND"}
    )
