"""Regression tests for the newest security boundaries."""

import hashlib
import json
from pathlib import Path

import pytest

from simulation.config import Settings
from simulation.logging.jsonl import redact
from simulation.ml.anomaly_detector import TelemetryAnomalyDetector


def test_development_secrets_are_ephemeral() -> None:
    first = Settings()
    second = Settings()
    first.initialize_runtime_secrets()
    second.initialize_runtime_secrets()

    assert first.network.telemetry_shared_secret.get_secret_value()
    assert (
        first.network.telemetry_shared_secret != second.network.telemetry_shared_secret
    )


def test_non_development_requires_secrets() -> None:
    configured = Settings()
    configured.network.dev_mode = False

    with pytest.raises(ValueError, match="Required secrets"):
        configured.initialize_runtime_secrets()


def test_log_strings_cannot_inject_records() -> None:
    result = redact({"details": "attacker\n forged\tentry\r"})

    assert result["details"] == "attacker? forged?entry?"


def test_model_hash_is_required_and_tampering_is_rejected(tmp_path: Path) -> None:
    detector = TelemetryAnomalyDetector()
    packets = []
    for sequence in range(20):
        packets.append(
            {
                "drone_id": "security",
                "sequence": sequence,
                "timestamp": 1_800_000_000.0 + sequence,
                "lat": 12.0 + sequence * 0.00001,
                "lon": 77.0,
                "altitude": 100.0,
                "speed": 10.0,
                "battery": 90.0 - sequence * 0.1,
                "heading": 0.0,
                "validation": {"is_anomalous": False},
            }
        )
    detector.train(packets)
    model_path, metadata_path = detector.save(tmp_path / "model.joblib")

    artifacts = model_path.read_bytes()
    assert (
        hashlib.sha256(artifacts).hexdigest()
        == json.loads(metadata_path.read_text(encoding="utf-8"))["model_sha256"]
    )
    model_path.write_bytes(artifacts + b"tampered")

    with pytest.raises(ValueError, match="integrity hash"):
        TelemetryAnomalyDetector.load(model_path)
