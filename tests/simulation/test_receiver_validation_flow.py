from simulation.ground_control.receiver import is_clean_training_sample
from simulation.security.telemetry_schema import (
    ValidationReason,
    ValidationResult,
    ValidationSeverity,
)


def test_accepted_sequence_gap_is_not_clean_ml_training_data() -> None:
    result = ValidationResult(
        accepted=True,
        reason_code=ValidationReason.SEQUENCE_GAP,
        severity=ValidationSeverity.MEDIUM,
        offending_field="sequence",
        detail="Forward sequence gap.",
    )

    assert not is_clean_training_sample(result)


def test_only_fully_clean_accepted_telemetry_trains_ml() -> None:
    clean = ValidationResult(
        accepted=True,
        reason_code=ValidationReason.ACCEPTED,
        severity=ValidationSeverity.INFO,
    )
    rejected = ValidationResult(
        accepted=False,
        reason_code=ValidationReason.MALFORMED_PAYLOAD,
        severity=ValidationSeverity.MEDIUM,
    )

    assert is_clean_training_sample(clean)
    assert not is_clean_training_sample(rejected)
