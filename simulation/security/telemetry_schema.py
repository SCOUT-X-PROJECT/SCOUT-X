"""Strict wire schema and structured validation outcomes for telemetry packets."""

from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictFloat,
    StrictInt,
    field_validator,
)

from simulation.config import settings


class ValidationReason(str, Enum):
    """Stable reason codes so callers can classify rejected packets safely."""

    ACCEPTED = "accepted"
    MALFORMED_PAYLOAD = "malformed_payload"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    INVALID_SCHEMA = "invalid_schema"
    UNKNOWN_FIELD = "unknown_field"
    INVALID_TYPE = "invalid_type"
    VALUE_OUT_OF_RANGE = "value_out_of_range"
    STALE_TIMESTAMP = "stale_timestamp"
    FUTURE_TIMESTAMP = "future_timestamp"
    TIMESTAMP_NON_MONOTONIC = "timestamp_non_monotonic"
    SEQUENCE_DUPLICATE = "sequence_duplicate"
    SEQUENCE_OUT_OF_ORDER = "sequence_out_of_order"
    SEQUENCE_GAP = "sequence_gap"
    GPS_JUMP = "gps_jump"
    GPS_SPEED_MISMATCH = "gps_speed_mismatch"
    ALTITUDE_RATE_EXCEEDED = "altitude_rate_exceeded"
    BATTERY_INCREASE = "battery_increase"
    REPLAY_CACHE_FULL = "replay_cache_full"
    TELEMETRY_FLOODING = "telemetry_flooding"
    FRAME_SEQUENCE_MISMATCH = "frame_sequence_mismatch"


class ValidationSeverity(str, Enum):
    """Severity communicates the likely security impact of a rejection."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TelemetryPacket(BaseModel):
    """Bound the wire contract because downstream code assumes physical values."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        str_strip_whitespace=True,
    )

    drone_id: str = Field(min_length=1)
    sequence: StrictInt = Field(ge=0)
    timestamp: StrictFloat = Field(gt=0, allow_inf_nan=False)
    lat: StrictFloat = Field(allow_inf_nan=False)
    lon: StrictFloat = Field(allow_inf_nan=False)
    altitude: StrictFloat = Field(allow_inf_nan=False)
    speed: StrictFloat = Field(ge=0, allow_inf_nan=False)
    battery: StrictFloat = Field(ge=0, allow_inf_nan=False)
    heading: StrictFloat | None = Field(
        default=None,
        ge=0,
        lt=360,
        allow_inf_nan=False,
    )

    @field_validator("drone_id")
    @classmethod
    def drone_id_within_configured_limit(cls, value: str) -> str:
        """Bound identity keys because each active drone consumes replay state."""
        if len(value) > settings.validation.max_drone_id_length:
            raise ValueError("drone_id exceeds configured maximum length")
        return value

    @field_validator("sequence")
    @classmethod
    def sequence_within_configured_limit(cls, value: int) -> int:
        """Reject counters that exceed the configured wire integer range."""
        if value > settings.validation.max_sequence_number:
            raise ValueError("sequence exceeds configured maximum")
        return value

    @field_validator("lat")
    @classmethod
    def latitude_within_configured_limit(cls, value: float) -> float:
        """Apply configured geographic bounds before distance calculations."""
        if abs(value) > settings.validation.gps_max_latitude:
            raise ValueError("latitude is outside configured limits")
        return value

    @field_validator("lon")
    @classmethod
    def longitude_within_configured_limit(cls, value: float) -> float:
        """Apply configured geographic bounds before distance calculations."""
        if abs(value) > settings.validation.gps_max_longitude:
            raise ValueError("longitude is outside configured limits")
        return value

    @field_validator("altitude")
    @classmethod
    def altitude_within_configured_limit(cls, value: float) -> float:
        """Use the configured ceiling so invalid values never reach response code."""
        if not (
            settings.validation.minimum_altitude
            <= value
            <= settings.validation.max_altitude
        ):
            raise ValueError("altitude is outside configured limits")
        return value

    @field_validator("speed")
    @classmethod
    def speed_within_configured_limit(cls, value: float) -> float:
        """Reject impossible speeds instead of clamping away evidence of tampering."""
        if not (
            settings.validation.minimum_speed <= value <= settings.validation.max_speed
        ):
            raise ValueError("speed is outside configured limits")
        return value

    @field_validator("battery")
    @classmethod
    def battery_within_configured_limits(cls, value: float) -> float:
        """Keep battery readings within the configured sensor range."""
        if not (
            settings.validation.battery_minimum
            <= value
            <= settings.validation.battery_maximum
        ):
            raise ValueError("battery is outside configured limits")
        return value


@dataclass(frozen=True)
class ValidationResult:
    """Return machine-readable validation evidence without forwarding bad data."""

    accepted: bool
    reason_code: ValidationReason
    severity: ValidationSeverity
    offending_field: str | None = None
    packet: TelemetryPacket | None = None
    detail: str = ""
    classification: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize outcomes consistently for logging and attack classification."""
        return {
            "accepted": self.accepted,
            "reason_code": self.reason_code.value,
            "severity": self.severity.value,
            "offending_field": self.offending_field,
            "detail": self.detail,
            "classification": self.classification,
        }
