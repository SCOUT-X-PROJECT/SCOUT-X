import json
import time

import pytest

from simulation.config import settings
from simulation.security.telemetry_middleware import SecurityMiddleware
from simulation.security.telemetry_schema import ValidationReason


def _valid_packet() -> dict[str, object]:
    return {
        "drone_id": settings.network.drone_id,
        "sequence": 1,
        "timestamp": time.time(),
        "lat": 12.0,
        "lon": 77.0,
        "altitude": 30.0,
        "speed": 10.0,
        "battery": 80.0,
    }


@pytest.mark.parametrize(
    ("mutate", "expected_reason"),
    [
        (
            lambda packet: packet.update(lat=float("nan")),
            ValidationReason.VALUE_OUT_OF_RANGE,
        ),
        (
            lambda packet: packet.update(speed=float("inf")),
            ValidationReason.VALUE_OUT_OF_RANGE,
        ),
        (lambda packet: packet.update(sequence=True), ValidationReason.INVALID_TYPE),
        (
            lambda packet: packet.update(unrecognized="extra"),
            ValidationReason.UNKNOWN_FIELD,
        ),
        (lambda packet: packet.update(lat=91.0), ValidationReason.VALUE_OUT_OF_RANGE),
        (
            lambda packet: packet.update(
                timestamp=time.time()
                - settings.validation.stale_timestamp_skew_seconds
                - 1
            ),
            ValidationReason.STALE_TIMESTAMP,
        ),
    ],
)
def test_signed_schema_edge_inputs_are_rejected(
    mutate,
    expected_reason: ValidationReason,
) -> None:
    packet = _valid_packet()
    mutate(packet)

    result = SecurityMiddleware().validate_telemetry(
        json.dumps(packet, allow_nan=True).encode()
    )

    assert not result.accepted
    assert result.reason_code is expected_reason


def test_random_bytes_and_nested_json_never_escape_as_exceptions() -> None:
    middleware = SecurityMiddleware()
    inputs: list[object] = [
        b"\xff\x00not-json",
        b"{" * 1000,
        {"unexpected": object()},
        None,
    ]

    for candidate in inputs:
        result = middleware.validate_telemetry(candidate)
        assert not result.accepted


def test_duplicate_and_out_of_order_sequence_are_rejected() -> None:
    middleware = SecurityMiddleware()
    first = _valid_packet()
    accepted = middleware.validate_telemetry(first)
    duplicate = middleware.validate_telemetry({**first, "timestamp": time.time() + 0.1})
    older = middleware.validate_telemetry(
        {
            **first,
            "sequence": 0,
            "timestamp": time.time() + 0.2,
        }
    )

    assert accepted.accepted
    assert duplicate.reason_code is ValidationReason.SEQUENCE_DUPLICATE
    assert older.reason_code is ValidationReason.SEQUENCE_OUT_OF_ORDER
