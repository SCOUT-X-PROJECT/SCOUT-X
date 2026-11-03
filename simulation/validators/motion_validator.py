"""Geodesic movement checks for consecutive, schema-validated packets."""

import math

from simulation.config import settings
from simulation.security.telemetry_schema import (
    TelemetryPacket,
    ValidationReason,
    ValidationResult,
    ValidationSeverity,
)


def haversine_distance_m(
    lat1: float,
    lon1: float,
    lat2: float,
    lon2: float,
) -> float:
    """Measure surface distance because latitude/longitude degrees are not linear."""
    latitude_delta = math.radians(lat2 - lat1)
    longitude_delta = math.radians(lon2 - lon1)
    lat1_radians = math.radians(lat1)
    lat2_radians = math.radians(lat2)
    haversine = (
        math.sin(latitude_delta / 2) ** 2
        + math.cos(lat1_radians)
        * math.cos(lat2_radians)
        * math.sin(longitude_delta / 2) ** 2
    )
    central_angle = 2 * math.asin(math.sqrt(min(1.0, haversine)))
    return settings.validation.earth_radius_meters * central_angle


def calculate_distance(
    prev_gps: dict[str, float],
    curr_gps: dict[str, float],
) -> float:
    """Keep the coordinate-pair helper geodesic for standalone validator callers."""
    return haversine_distance_m(
        prev_gps["lat"],
        prev_gps["lon"],
        curr_gps["lat"],
        curr_gps["lon"],
    )


def validate_motion(
    previous: TelemetryPacket | None,
    current: TelemetryPacket,
) -> ValidationResult:
    """Reject GPS motion that contradicts reported speed or the jump policy."""
    if previous is None:
        return _accepted()

    elapsed = current.timestamp - previous.timestamp
    if elapsed <= 0:
        return _rejected(
            ValidationReason.TIMESTAMP_NON_MONOTONIC,
            "timestamp",
            "Timestamp must increase for each accepted packet.",
        )

    distance = haversine_distance_m(
        previous.lat,
        previous.lon,
        current.lat,
        current.lon,
    )
    implied_speed = distance / elapsed
    speed_error = abs(implied_speed - current.speed)
    if speed_error > settings.validation.speed_mismatch_limit and not math.isclose(
        speed_error,
        settings.validation.speed_mismatch_limit,
        rel_tol=0.0,
        abs_tol=settings.validation.comparison_tolerance,
    ):
        return _rejected(
            ValidationReason.GPS_SPEED_MISMATCH,
            "speed",
            "Reported speed differs from haversine displacement.",
        )

    if (
        elapsed <= settings.validation.max_time_delta_seconds
        and distance > settings.validation.gps_jump_limit_m
        and not math.isclose(
            distance,
            settings.validation.gps_jump_limit_m,
            rel_tol=0.0,
            abs_tol=settings.validation.comparison_tolerance,
        )
    ):
        return _rejected(
            ValidationReason.GPS_JUMP,
            "lat",
            "GPS displacement exceeds the configured jump limit.",
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
