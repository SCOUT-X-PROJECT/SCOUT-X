import json
import math
from typing import Any

import pytest
from hypothesis import given, settings as hypothesis_settings, strategies as st

from simulation.analysis.attack_classifier import AttackType
from simulation.config import settings
from simulation.security.telemetry_middleware import SecurityMiddleware
from simulation.security.telemetry_schema import (
    TelemetryPacket,
    ValidationReason,
    ValidationResult,
)
from simulation.validators.motion_validator import haversine_distance_m


NOW = 1_800_000_000.0


@pytest.fixture
def fixed_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "simulation.security.telemetry_middleware.time.time", lambda: NOW
    )


def valid_packet(**overrides: Any) -> dict[str, Any]:
    return {
        "drone_id": "test-drone",
        "sequence": 1,
        "timestamp": NOW,
        "lat": 0.0,
        "lon": 0.0,
        "altitude": 10.0,
        "speed": 10.0,
        "battery": 90.0,
        **overrides,
    }


def second_position(distance_m: float, *, latitude: float = 0.0) -> float:
    return latitude + math.degrees(distance_m / settings.validation.earth_radius_meters)


def assert_rejected(
    result: ValidationResult,
    reason: ValidationReason,
    field: str | None = None,
) -> None:
    assert result.accepted is False
    assert result.reason_code is reason
    assert result.offending_field == field
    assert result.packet is None


def test_accepts_strict_packet_and_optional_heading(fixed_clock: None) -> None:
    result = SecurityMiddleware().validate_telemetry(valid_packet(heading=359.0))

    assert result.accepted is True
    assert result.reason_code is ValidationReason.ACCEPTED
    assert isinstance(result.packet, TelemetryPacket)
    assert result.packet.heading == 359.0


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("sequence", True, ValidationReason.INVALID_TYPE),
        ("sequence", "1", ValidationReason.INVALID_TYPE),
        ("sequence", -1, ValidationReason.VALUE_OUT_OF_RANGE),
        ("timestamp", "1800000000", ValidationReason.INVALID_TYPE),
        ("lat", "0", ValidationReason.INVALID_TYPE),
        ("lat", 90.01, ValidationReason.VALUE_OUT_OF_RANGE),
        ("lon", -180.01, ValidationReason.VALUE_OUT_OF_RANGE),
        ("lat", math.nan, ValidationReason.VALUE_OUT_OF_RANGE),
        ("lon", math.inf, ValidationReason.VALUE_OUT_OF_RANGE),
        ("altitude", -0.01, ValidationReason.VALUE_OUT_OF_RANGE),
        ("speed", -0.01, ValidationReason.VALUE_OUT_OF_RANGE),
        ("battery", -0.01, ValidationReason.VALUE_OUT_OF_RANGE),
        (
            "altitude",
            settings.validation.max_altitude + 0.01,
            ValidationReason.VALUE_OUT_OF_RANGE,
        ),
        (
            "speed",
            settings.validation.max_speed + 0.01,
            ValidationReason.VALUE_OUT_OF_RANGE,
        ),
        (
            "battery",
            settings.validation.battery_maximum + 0.01,
            ValidationReason.VALUE_OUT_OF_RANGE,
        ),
        ("heading", 360.0, ValidationReason.VALUE_OUT_OF_RANGE),
        (
            "sequence",
            settings.validation.max_sequence_number + 1,
            ValidationReason.VALUE_OUT_OF_RANGE,
        ),
        (
            "drone_id",
            "d" * (settings.validation.max_drone_id_length + 1),
            ValidationReason.VALUE_OUT_OF_RANGE,
        ),
    ],
)
def test_rejects_wrong_types_and_out_of_range_values(
    field: str,
    value: object,
    reason: ValidationReason,
    fixed_clock: None,
) -> None:
    result = SecurityMiddleware().validate_telemetry(valid_packet(**{field: value}))

    assert_rejected(result, reason, field)


def test_rejects_unknown_and_missing_fields(fixed_clock: None) -> None:
    unknown = SecurityMiddleware().validate_telemetry(
        valid_packet(command={"authorized": True})
    )
    missing_packet = valid_packet()
    del missing_packet["drone_id"]
    missing = SecurityMiddleware().validate_telemetry(missing_packet)

    assert_rejected(unknown, ValidationReason.UNKNOWN_FIELD, "command")
    assert_rejected(missing, ValidationReason.INVALID_SCHEMA, "drone_id")


def test_accepts_inclusive_coordinate_and_numeric_boundaries(fixed_clock: None) -> None:
    result = SecurityMiddleware().validate_telemetry(
        valid_packet(
            lat=-90.0,
            lon=180.0,
            altitude=settings.validation.max_altitude,
            speed=settings.validation.max_speed,
            battery=settings.validation.battery_minimum,
            heading=0.0,
        )
    )

    assert result.accepted is True


def test_accepts_configured_sequence_maximum(fixed_clock: None) -> None:
    result = SecurityMiddleware().validate_telemetry(
        valid_packet(sequence=settings.validation.max_sequence_number)
    )

    assert result.accepted is True


def test_accepts_payload_at_exact_size_limit(fixed_clock: None) -> None:
    encoded = json.dumps(valid_packet(), separators=(",", ":")).encode("utf-8")
    payload = encoded + b" " * (
        settings.validation.max_telemetry_payload_bytes - len(encoded)
    )

    result = SecurityMiddleware().validate_telemetry(payload)

    assert len(payload) == settings.validation.max_telemetry_payload_bytes
    assert result.accepted is True


def test_rejects_oversized_raw_payload(fixed_clock: None) -> None:
    middleware = SecurityMiddleware()

    result = middleware.validate_telemetry(
        b"x" * (settings.validation.max_telemetry_payload_bytes + 1)
    )
    oversized_object = middleware.validate_telemetry(
        valid_packet(note="x" * (settings.validation.max_telemetry_payload_bytes + 1))
    )

    assert_rejected(result, ValidationReason.PAYLOAD_TOO_LARGE)
    assert_rejected(oversized_object, ValidationReason.PAYLOAD_TOO_LARGE)


@pytest.mark.parametrize(
    "payload",
    [b"\xff\xfe", b'{"sequence":', b"null", b"[]"],
)
def test_malformed_bytes_return_structured_rejection(
    payload: bytes,
    fixed_clock: None,
) -> None:
    result = SecurityMiddleware().validate_telemetry(payload)

    assert isinstance(result, ValidationResult)
    assert result.accepted is False
    assert result.reason_code in {
        ValidationReason.MALFORMED_PAYLOAD,
        ValidationReason.INVALID_SCHEMA,
    }


def test_checks_staleness_and_future_skew(fixed_clock: None) -> None:
    middleware = SecurityMiddleware()
    stale = middleware.validate_telemetry(
        valid_packet(
            timestamp=NOW - settings.validation.stale_timestamp_skew_seconds - 0.01
        )
    )
    future = SecurityMiddleware().validate_telemetry(
        valid_packet(
            timestamp=NOW + settings.validation.stale_timestamp_skew_seconds + 0.01
        )
    )
    boundary = SecurityMiddleware().validate_telemetry(
        valid_packet(timestamp=NOW - settings.validation.stale_timestamp_skew_seconds)
    )

    assert_rejected(stale, ValidationReason.STALE_TIMESTAMP, "timestamp")
    assert_rejected(future, ValidationReason.FUTURE_TIMESTAMP, "timestamp")
    assert boundary.accepted is True


def test_rejects_replays_and_reports_forward_sequence_gaps(fixed_clock: None) -> None:
    middleware = SecurityMiddleware()
    assert middleware.validate_telemetry(valid_packet(sequence=4, speed=0.0)).accepted

    duplicate = middleware.validate_telemetry(valid_packet(sequence=4))
    out_of_order = middleware.validate_telemetry(
        valid_packet(sequence=3, timestamp=NOW + 1)
    )
    gap = middleware.validate_telemetry(
        valid_packet(sequence=6, timestamp=NOW + 1, speed=0.0)
    )

    assert_rejected(duplicate, ValidationReason.SEQUENCE_DUPLICATE, "sequence")
    assert_rejected(out_of_order, ValidationReason.SEQUENCE_OUT_OF_ORDER, "sequence")
    assert gap.accepted is True
    assert gap.reason_code is ValidationReason.SEQUENCE_GAP
    assert gap.offending_field == "sequence"
    assert gap.classification == AttackType.UNKNOWN.value


def test_rejects_non_monotonic_timestamps(fixed_clock: None) -> None:
    middleware = SecurityMiddleware()
    assert middleware.validate_telemetry(valid_packet()).accepted

    result = middleware.validate_telemetry(valid_packet(sequence=2, timestamp=NOW))

    assert_rejected(
        result,
        ValidationReason.TIMESTAMP_NON_MONOTONIC,
        "timestamp",
    )


def test_haversine_distance_handles_antimeridian() -> None:
    distance = haversine_distance_m(0.0, 179.999, 0.0, -179.999)

    assert 220 < distance < 225


def test_rejects_reported_speed_inconsistent_with_gps(fixed_clock: None) -> None:
    middleware = SecurityMiddleware()
    assert middleware.validate_telemetry(valid_packet()).accepted

    result = middleware.validate_telemetry(
        valid_packet(
            sequence=2,
            timestamp=NOW + 1,
            lat=second_position(100.0),
        )
    )

    assert_rejected(result, ValidationReason.GPS_SPEED_MISMATCH, "speed")


def test_speed_mismatch_tolerance_boundary_is_inclusive(
    fixed_clock: None,
) -> None:
    middleware = SecurityMiddleware()
    assert middleware.validate_telemetry(valid_packet(speed=0.0)).accepted

    distance = settings.validation.speed_mismatch_limit
    result = middleware.validate_telemetry(
        valid_packet(
            sequence=2,
            timestamp=NOW + 1,
            lat=second_position(distance),
            speed=0.0,
        )
    )

    assert result.accepted is True


def test_gps_jump_limit_boundary_is_inclusive(fixed_clock: None) -> None:
    middleware = SecurityMiddleware()
    assert middleware.validate_telemetry(valid_packet(speed=0.0)).accepted

    distance = settings.validation.gps_jump_limit_m
    result = middleware.validate_telemetry(
        valid_packet(
            sequence=2,
            timestamp=NOW + 1,
            lat=second_position(distance),
            speed=distance,
        )
    )

    assert result.accepted is True


def test_rejects_gps_jump_even_when_reported_speed_matches(fixed_clock: None) -> None:
    middleware = SecurityMiddleware()
    assert middleware.validate_telemetry(valid_packet()).accepted
    distance = settings.validation.gps_jump_limit_m + 1

    result = middleware.validate_telemetry(
        valid_packet(
            sequence=2,
            timestamp=NOW + 1,
            lat=second_position(distance),
            speed=distance,
        )
    )

    assert_rejected(result, ValidationReason.GPS_JUMP, "lat")


def test_rejects_excessive_altitude_rate(fixed_clock: None) -> None:
    middleware = SecurityMiddleware()
    assert middleware.validate_telemetry(valid_packet(speed=0.0)).accepted

    result = middleware.validate_telemetry(
        valid_packet(
            sequence=2,
            timestamp=NOW + 1,
            altitude=16.0,
            speed=0.0,
        )
    )

    assert_rejected(result, ValidationReason.ALTITUDE_RATE_EXCEEDED, "altitude")


def test_altitude_rate_limit_boundary_is_inclusive(fixed_clock: None) -> None:
    middleware = SecurityMiddleware()
    assert middleware.validate_telemetry(valid_packet(speed=0.0)).accepted

    result = middleware.validate_telemetry(
        valid_packet(
            sequence=2,
            timestamp=NOW + 1,
            altitude=10.0 + settings.validation.altitude_rate_limit_mps,
            speed=0.0,
        )
    )

    assert result.accepted is True


def test_battery_increase_tolerance_is_inclusive(fixed_clock: None) -> None:
    middleware = SecurityMiddleware()
    assert middleware.validate_telemetry(valid_packet(speed=0.0)).accepted

    boundary = middleware.validate_telemetry(
        valid_packet(
            sequence=2,
            timestamp=NOW + 1,
            speed=0.0,
            battery=90.0 + settings.validation.battery_increase_tolerance,
        )
    )
    over = middleware.validate_telemetry(
        valid_packet(
            sequence=3,
            timestamp=NOW + 2,
            speed=0.0,
            battery=90.0 + 2 * settings.validation.battery_increase_tolerance + 0.01,
        )
    )

    assert boundary.accepted is True
    assert_rejected(over, ValidationReason.BATTERY_INCREASE, "battery")


def test_rejected_packet_does_not_consume_its_sequence(fixed_clock: None) -> None:
    middleware = SecurityMiddleware()
    assert middleware.validate_telemetry(valid_packet(speed=0.0)).accepted

    rejected = middleware.validate_telemetry(
        valid_packet(
            sequence=2,
            timestamp=NOW + 1,
            altitude=settings.validation.max_altitude + 1,
            speed=0.0,
        )
    )
    retried = middleware.validate_telemetry(
        valid_packet(sequence=2, timestamp=NOW + 1, speed=0.0)
    )

    assert_rejected(rejected, ValidationReason.VALUE_OUT_OF_RANGE, "altitude")
    assert retried.accepted is True


def test_replay_cache_rejects_new_ids_after_capacity(fixed_clock: None) -> None:
    middleware = SecurityMiddleware()
    capacity = settings.validation.replay_cache_capacity
    for index in range(capacity):
        result = middleware.validate_telemetry(valid_packet(drone_id=f"drone-{index}"))
        assert result.accepted

    result = middleware.validate_telemetry(valid_packet(drone_id="untracked-drone"))

    assert_rejected(result, ValidationReason.REPLAY_CACHE_FULL, "drone_id")
    assert len(middleware._windows) == capacity


def test_attack_classifier_consumes_structured_rejections(fixed_clock: None) -> None:
    result = SecurityMiddleware().validate_telemetry(
        valid_packet(sequence=1, sequence_extra="unexpected")
    )

    assert result.classification == AttackType.UNKNOWN.value


json_leaf = (
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=True, allow_infinity=True)
    | st.text(max_size=100)
)
json_value = st.recursive(
    json_leaf,
    lambda children: (
        st.lists(children, max_size=5)
        | st.dictionaries(st.text(max_size=30), children, max_size=5)
    ),
    max_leaves=30,
)
fuzz_payloads = st.one_of(
    st.binary(max_size=4096),
    st.dictionaries(st.text(max_size=40), json_value, max_size=20),
)


@given(fuzz_payloads)
@hypothesis_settings(max_examples=200, deadline=None)
def test_fuzz_payloads_never_crash_or_bypass_schema(payload: object) -> None:
    result = SecurityMiddleware().validate_telemetry(payload)

    assert isinstance(result, ValidationResult)
    if result.accepted:
        assert result.packet is not None
        assert TelemetryPacket.model_validate(result.packet.model_dump())
    else:
        assert result.packet is None


def test_fuzz_random_bytes_never_crash() -> None:
    middleware = SecurityMiddleware()
    for payload in (bytes(range(256)), b"\x00" * 2048, b"not-json"):
        assert isinstance(middleware.validate_telemetry(payload), ValidationResult)
