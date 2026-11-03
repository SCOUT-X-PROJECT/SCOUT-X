from pathlib import Path

import pytest
from pydantic import ValidationError

from simulation.config import Settings


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("protect_threshold", 0.5),
        ("evacuate_threshold", 0.1),
        ("prepare_threshold", 0.4),
        ("standby_threshold", 0.7),
    ],
)
def test_rejects_invalid_trust_threshold_order(field: str, value: float) -> None:
    trust = {
        "protect_threshold": 0.2,
        "evacuate_threshold": 0.5,
        "prepare_threshold": 0.8,
        "standby_threshold": 0.8,
    }
    trust[field] = value

    with pytest.raises(ValidationError, match="trust thresholds must satisfy"):
        Settings(_env_file=None, trust=trust)


def test_rejects_hysteresis_not_smaller_than_threshold_gap() -> None:
    with pytest.raises(ValidationError, match="hysteresis_margin"):
        Settings(
            _env_file=None,
            trust={"hysteresis_margin": 0.3},
        )


@pytest.mark.parametrize(
    ("section", "field"),
    [("network", "udp_port"), ("network", "tcp_port"), ("dashboard", "port")],
)
@pytest.mark.parametrize("port", [0, 65536])
def test_rejects_ports_out_of_range(section: str, field: str, port: int) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **{section: {field: port}})


def test_reads_nested_environment_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCOUTX_NETWORK__UDP_PORT", "12000")

    config = Settings(_env_file=None)

    assert config.network.udp_port == 12000


def test_reads_dotenv_overrides(tmp_path: Path) -> None:
    dotenv_file = tmp_path / ".env"
    dotenv_file.write_text(
        "SCOUTX_DASHBOARD__PORT=8123\n",
        encoding="utf-8",
    )

    config = Settings(_env_file=dotenv_file)

    assert config.dashboard.port == 8123


def test_defaults_keep_equal_prepare_and_standby_boundary() -> None:
    config = Settings(_env_file=None)

    assert config.trust.prepare_threshold == config.trust.standby_threshold
    assert config.trust.hysteresis_margin < (
        config.trust.evacuate_threshold - config.trust.protect_threshold
    )


def test_rejects_different_prepare_and_standby_boundaries() -> None:
    with pytest.raises(ValidationError, match="must match"):
        Settings(
            _env_file=None,
            trust={"standby_threshold": 0.9},
        )


def test_rejects_unbounded_clean_recovery_rate() -> None:
    with pytest.raises(ValidationError, match="recovery_rate"):
        Settings(_env_file=None, trust={"recovery_rate": 0.11})


def test_classifier_flood_threshold_fits_history_window() -> None:
    with pytest.raises(ValidationError, match="classifier_flood_threshold"):
        Settings(
            _env_file=None,
            trust={
                "classifier_history_window": 4,
                "classifier_flood_threshold": 5,
            },
        )


def test_hem_peer_score_weights_must_sum_to_one() -> None:
    with pytest.raises(ValidationError, match="weights must sum"):
        Settings(
            _env_file=None,
            hem={"peer_weight_trust": 0.2},
        )


def test_hem_priorities_must_be_strictly_ordered() -> None:
    with pytest.raises(ValidationError, match="priorities must be ordered"):
        Settings(
            _env_file=None,
            hem={"sensitive_priority": 0},
        )


@pytest.mark.parametrize("fraction", [0.0, 0.5, 1.0])
def test_ml_calibration_fraction_must_be_between_zero_and_half(
    fraction: float,
) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, ml={"calibration_fraction": fraction})


def test_ml_training_window_must_meet_minimum_sample_count() -> None:
    with pytest.raises(ValidationError, match="training_window"):
        Settings(
            _env_file=None,
            ml={
                "training_window": 4,
                "minimum_training_samples": 5,
            },
        )
