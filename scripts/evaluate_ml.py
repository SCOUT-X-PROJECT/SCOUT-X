"""Reproduce labeled simulator-based evaluation for the secondary ML detector."""

from collections.abc import Iterator
import math
from pathlib import Path
import random
import sys
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sklearn.metrics import (
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from simulation.config import PROJECT_ROOT, settings
from simulation.ml.anomaly_detector import TelemetryAnomalyDetector
from simulation.telemetry.telemetry_engine import TelemetryEngine


_EPOCH = 1_800_000_000.0
_TRAINING_SAMPLES = 256
_EPISODE_COUNT = 4
_CLEAN_PACKETS_PER_EPISODE = 32
_ATTACK_PACKETS_PER_EPISODE = 32
_ATTACK_JUMP_METERS = 800.0


def _simulated_labeled_stream() -> Iterator[tuple[dict[str, Any], int]]:
    """Generate fixed-time telemetry from TelemetryEngine with labeled attacks."""
    random.seed(settings.ml.random_seed)
    engine = TelemetryEngine()
    latitude = settings.dashboard.aircraft_center_latitude
    longitude = settings.dashboard.aircraft_center_longitude
    latitude_offset = 0.0
    sequence = 0
    attack_active = False

    def advance(label: int) -> tuple[dict[str, Any], int]:
        nonlocal latitude, latitude_offset, sequence, attack_active
        # Reset simulator state around nominal control values so clean flights
        # remain stationary in distribution rather than random-walk drifting.
        engine.speed = settings.validation.initial_speed
        engine.altitude = settings.validation.initial_altitude
        raw = engine.update()
        if label and not attack_active:
            latitude_offset += _ATTACK_JUMP_METERS
        attack_active = bool(label)
        speed = float(raw["speed"])
        latitude += math.degrees(speed / settings.validation.earth_radius_meters)
        packet = {
            **raw,
            "sequence": sequence,
            "timestamp": _EPOCH + sequence,
            "lat": latitude
            + math.degrees(latitude_offset / settings.validation.earth_radius_meters),
            "lon": longitude,
            "heading": 0.0,
            "validation": {"is_anomalous": False},
        }
        if label:
            packet["speed"] = min(
                settings.validation.max_speed,
                float(packet["speed"]) + 25.0,
            )
            packet["altitude"] = min(
                settings.validation.max_altitude,
                float(packet["altitude"]) + 10.0,
            )
        sequence += 1
        return packet, label

    for _ in range(_TRAINING_SAMPLES):
        yield advance(0)
    for _ in range(_EPISODE_COUNT):
        for _ in range(_CLEAN_PACKETS_PER_EPISODE):
            yield advance(0)
        for _ in range(_ATTACK_PACKETS_PER_EPISODE):
            yield advance(1)


def evaluate() -> str:
    """Fit on simulator-clean samples and report held-out labeled flight metrics."""
    stream = list(_simulated_labeled_stream())
    clean_training = [
        packet for packet, label in stream[:_TRAINING_SAMPLES] if label == 0
    ]
    detector = TelemetryAnomalyDetector()
    detector.train(clean_training)

    evaluation = stream[_TRAINING_SAMPLES:]
    labels: list[int] = []
    predictions: list[int] = []
    risk_scores: list[float] = []
    detection_delays: list[int] = []
    attack_start: int | None = None
    attack_detected = False

    for index, (packet, label) in enumerate(evaluation):
        result = detector.predict(packet)
        if result["ml_status"] != "ready" or result["ml_score"] is None:
            raise RuntimeError(
                f"model was not ready for evaluation packet {index}: {result}"
            )
        prediction = int(result["ml_anomaly"] is True)
        labels.append(label)
        predictions.append(prediction)
        risk_scores.append(float(result["ml_score"]))

        if label and attack_start is None:
            attack_start = index
            attack_detected = False
        elif not label and attack_start is not None:
            if not attack_detected:
                detection_delays.append(_ATTACK_PACKETS_PER_EPISODE)
            attack_start = None
        if label and prediction and not attack_detected and attack_start is not None:
            detection_delays.append(index - attack_start)
            attack_detected = True
    if attack_start is not None and not attack_detected:
        detection_delays.append(_ATTACK_PACKETS_PER_EPISODE)

    false_positive = sum(
        label == 0 and prediction == 1 for label, prediction in zip(labels, predictions)
    )
    true_negative = sum(
        label == 0 and prediction == 0 for label, prediction in zip(labels, predictions)
    )
    false_positive_rate = false_positive / max(
        1,
        false_positive + true_negative,
    )
    metrics = {
        "precision": precision_score(labels, predictions, zero_division=0),
        "recall": recall_score(labels, predictions, zero_division=0),
        "f1": f1_score(labels, predictions, zero_division=0),
        "roc_auc": roc_auc_score(labels, risk_scores),
        "false_positive_rate_clean": false_positive_rate,
        "mean_detection_delay_packets": (
            sum(detection_delays) / len(detection_delays)
            if detection_delays
            else float("nan")
        ),
    }

    output = [
        "# ML Detector Evaluation",
        "",
        "Generated by `python scripts/evaluate_ml.py`. The detector was fitted",
        "only on the first 256 clean samples from `TelemetryEngine`. Evaluation",
        "uses four clean/attack episodes from the same deterministic simulator",
        "stream. Each attack begins with an 800 m GPS displacement and elevated",
        "reported speed and altitude. This synthetic evaluation does not establish",
        "performance on real aircraft or unseen attack classes.",
        "",
        f"- Random seed: `{settings.ml.random_seed}`",
        f"- Training samples: `{len(clean_training)}`",
        f"- Evaluation samples: `{len(evaluation)}`",
        f"- Attack episodes: `{_EPISODE_COUNT}`",
        f"- Clean calibration holdout: `{settings.ml.calibration_fraction:.0%}`",
        f"- Risk threshold: `{settings.ml.risk_threshold:.2f}`",
        "",
        "| Metric | Result |",
        "|---|---:|",
    ]
    output.extend(
        f"| {name.replace('_', ' ').title()} | {value:.4f} |"
        for name, value in metrics.items()
    )
    content = "\n".join(output) + "\n"
    destination = PROJECT_ROOT / "docs" / "ml_evaluation.md"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8")
    return content


if __name__ == "__main__":
    print(evaluate())
