"""Physical plausibility checks shared by the telemetry trust boundary."""

import math

from simulation.config import settings
from simulation.security.telemetry_schema import (
    TelemetryPacket,
    ValidationReason,
    ValidationResult,
    ValidationSeverity,
)
from simulation.validators.motion_validator import (
    validate_motion,
)


def validate_consistency(
    previous: TelemetryPacket | None,
    current: TelemetryPacket,
) -> ValidationResult:
    """Reject impossible state transitions before they affect trust or response."""
    if previous is None:
        return _accepted()

    sequence_gap = current.sequence > previous.sequence + 1
    elapsed = current.timestamp - previous.timestamp
    if elapsed <= 0:
        return _rejected(
            ValidationReason.TIMESTAMP_NON_MONOTONIC,
            "timestamp",
            "Timestamp must increase for each accepted packet.",
        )

    motion_result = validate_motion(previous, current)
    if not motion_result.accepted:
        return motion_result

    altitude_rate = abs(current.altitude - previous.altitude) / elapsed
    if altitude_rate > settings.validation.altitude_rate_limit_mps and not math.isclose(
        altitude_rate,
        settings.validation.altitude_rate_limit_mps,
        rel_tol=0.0,
        abs_tol=settings.validation.comparison_tolerance,
    ):
        return _rejected(
            ValidationReason.ALTITUDE_RATE_EXCEEDED,
            "altitude",
            "Altitude rate exceeds the configured physical limit.",
        )

    battery_increase = current.battery - previous.battery
    if (
        battery_increase > settings.validation.battery_increase_tolerance
        and not math.isclose(
            battery_increase,
            settings.validation.battery_increase_tolerance,
            rel_tol=0.0,
            abs_tol=settings.validation.comparison_tolerance,
        )
    ):
        return _rejected(
            ValidationReason.BATTERY_INCREASE,
            "battery",
            "Battery increased beyond the configured measurement tolerance.",
        )

    if sequence_gap:
        return ValidationResult(
            accepted=True,
            reason_code=ValidationReason.SEQUENCE_GAP,
            severity=ValidationSeverity.MEDIUM,
            offending_field="sequence",
            detail="Forward sequence gap observed; packet passed physical checks.",
        )

    return _accepted()


def _accepted() -> ValidationResult:
    return ValidationResult(
        accepted=True,
        reason_code=ValidationReason.ACCEPTED,
        severity=ValidationSeverity.INFO,
    )


def _rejected(
    reason: ValidationReason,
    field: str,
    detail: str,
) -> ValidationResult:
    return ValidationResult(
        accepted=False,
        reason_code=reason,
        severity=ValidationSeverity.HIGH,
        offending_field=field,
        detail=detail,
    )
