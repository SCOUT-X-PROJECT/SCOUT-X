import asyncio
import json
import socket
import threading
import time
from collections.abc import Callable
from typing import Any

import pytest

from simulation.ground_control.udp_receiver import (
    TelemetryUDPReceiver,
    _SourceRateLimiter,
)
from simulation.security.telemetry_auth import (
    TelemetryAuthenticationError,
    TelemetryAuthenticator,
)
from simulation.security.telemetry_middleware import SecurityMiddleware
from simulation.security.replay_store import PersistentFrameReplayCache
from simulation.security.telemetry_schema import ValidationResult
from simulation.config import settings


_SHARED_SECRET = "integration-test-secret-not-for-production"


def _packet(sequence: int, timestamp: float | None = None) -> dict[str, Any]:
    return {
        "drone_id": settings.network.drone_id,
        "sequence": sequence,
        "timestamp": time.time() if timestamp is None else timestamp,
        "lat": 0.0,
        "lon": 0.0,
        "altitude": 10.0,
        "speed": 10.0,
        "battery": 90.0,
    }


def test_telemetry_authentication_binds_sequence_and_payload() -> None:
    sender = TelemetryAuthenticator(_SHARED_SECRET)
    receiver = TelemetryAuthenticator(_SHARED_SECRET)
    packet = _packet(11)
    frame = sender.encode_packet(packet)

    sequence, payload = receiver.decode_frame(frame)

    assert sequence == packet["sequence"]
    assert json.loads(payload) == packet
    modified_sequence = bytearray(frame)
    modified_sequence[5] ^= 0x01
    with pytest.raises(TelemetryAuthenticationError):
        receiver.decode_frame(bytes(modified_sequence))
    with pytest.raises(TelemetryAuthenticationError):
        receiver.decode_frame(sender.encode_packet(_packet(12))[:-1] + b"x")

    sender.close()
    receiver.close()


def test_telemetry_authenticator_rejects_empty_or_weak_secrets() -> None:
    with pytest.raises(ValueError, match="required"):
        TelemetryAuthenticator("")
    with pytest.raises(ValueError, match="at least 32 bytes"):
        TelemetryAuthenticator("short")


def test_source_token_bucket_refills_and_bounds_source_state() -> None:
    now = [0.0]
    limiter = _SourceRateLimiter(
        rate=2.0,
        capacity=2,
        source_capacity=2,
        clock=lambda: now[0],
    )

    assert limiter.consume("drone")[0] is True
    assert limiter.consume("drone")[0] is True
    assert limiter.consume("drone") == (False, True)
    assert limiter.consume("drone") == (False, False)
    assert limiter.consume("other")[0] is True
    now[0] += 1.0
    assert limiter.consume("drone")[0] is True
    assert len(limiter._buckets) == 2


@pytest.mark.asyncio
async def test_udp_receiver_authentication_replay_flood_and_malformed_traffic() -> None:
    sender = TelemetryAuthenticator(_SHARED_SECRET)
    security = SecurityMiddleware()
    first_processed = threading.Event()
    accepted_sequences: list[int] = []

    def process_result(result: ValidationResult) -> None:
        time.sleep(0.02)
        if result.accepted and result.packet is not None:
            accepted_sequences.append(result.packet.sequence)
            first_processed.set()

    receiver = TelemetryUDPReceiver(
        packet_handler=process_result,
        security=security,
        authenticator=TelemetryAuthenticator(_SHARED_SECRET),
        host="127.0.0.1",
        port=0,
        queue_capacity=2,
        rate_limit_per_second=1000,
        burst_capacity=1000,
    )
    server_task = asyncio.create_task(receiver.run())
    await asyncio.wait_for(receiver.started.wait(), timeout=2)
    address = receiver.address
    assert address is not None

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.setblocking(False)
    loop = asyncio.get_running_loop()

    async def send(frame: bytes) -> None:
        await loop.sock_sendto(client, frame, address)

    try:
        valid_frame = sender.encode_packet(_packet(1))
        await send(valid_frame)
        assert await asyncio.to_thread(first_processed.wait, 2)

        await send(sender.encode_payload(2, b"{malformed"))
        await _wait_for_event(
            receiver,
            lambda event: (
                event.get("event") == "telemetry_rejected"
                and event.get("reason_code") == "malformed_payload"
            ),
        )

        await send(valid_frame)
        await _wait_for_event(
            receiver,
            lambda event: (
                event.get("event") == "telemetry_rejected"
                and event.get("reason_code") == "sequence_duplicate"
            ),
        )

        forged_frame = bytearray(sender.encode_packet(_packet(2)))
        forged_frame[-1] ^= 0x01
        await send(bytes(forged_frame))
        await _wait_for_event(
            receiver,
            lambda event: event.get("event") == "authentication_failed",
        )
        assert accepted_sequences == [1]

        await send(b"x" * 4097)
        await _wait_for_event(
            receiver,
            lambda event: event.get("event") == "datagram_too_large",
        )

        trust_before_flood = security.trust_score
        for sequence in range(2, 80):
            await send(sender.encode_packet(_packet(sequence)))
        flood_event = await _wait_for_event(
            receiver,
            lambda event: event.get("event") == "telemetry_flooding",
        )

        assert flood_event["trust_score"] < trust_before_flood
        assert flood_event["classification"] == "TELEMETRY_FLOODING"
        assert accepted_sequences[0] == 1
        assert "authentication_failed" in {
            event.get("event") for event in list(receiver.events)
        }
    finally:
        client.close()
        sender.close()
        receiver.stop()
        await asyncio.wait_for(server_task, timeout=5)
        assert receiver.address is None


@pytest.mark.asyncio
async def test_udp_receiver_accepts_signed_protect_reset_control() -> None:
    sender = TelemetryAuthenticator(_SHARED_SECRET)
    received_control = threading.Event()
    controls: list[dict[str, Any]] = []

    def handle_control(packet: dict[str, Any]) -> None:
        controls.append(packet)
        received_control.set()

    receiver = TelemetryUDPReceiver(
        packet_handler=lambda _: None,
        control_handler=handle_control,
        authenticator=TelemetryAuthenticator(_SHARED_SECRET),
        host="127.0.0.1",
        port=0,
        rate_limit_per_second=1000,
        burst_capacity=1000,
    )
    server_task = asyncio.create_task(receiver.run())
    await asyncio.wait_for(receiver.started.wait(), timeout=2)
    assert receiver.address is not None
    stale_packet = {
        "_scoutx_control": "protect_reset",
        "reset_token": "receiver-validates-this-token",
        "drone_id": settings.dashboard.drone_id,
        "sequence": 123,
        "timestamp": time.time() - settings.validation.stale_timestamp_skew_seconds - 1,
    }
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        client.sendto(sender.encode_packet(stale_packet), receiver.address)
        await _wait_for_event(
            receiver,
            lambda event: (
                event.get("event") == "telemetry_rejected"
                and event.get("reason_code") == "stale_timestamp"
            ),
        )
        packet = {**stale_packet, "timestamp": time.time()}
        client.sendto(sender.encode_packet(packet), receiver.address)
        assert await asyncio.to_thread(received_control.wait, 2)
        assert controls == [packet]
    finally:
        client.close()
        sender.close()
        receiver.stop()
        await asyncio.wait_for(server_task, timeout=5)


@pytest.mark.asyncio
async def test_exact_authenticated_frame_is_rejected_after_receiver_restart(
    tmp_path,
) -> None:
    sender = TelemetryAuthenticator(_SHARED_SECRET)
    packet = _packet(203)
    captured_frame = sender.encode_packet(packet)
    cache_path = tmp_path / "accepted-frames.sqlite3"
    cache = PersistentFrameReplayCache(cache_path, capacity=8)
    accepted: list[ValidationResult] = []
    accepted_event = threading.Event()

    def handle_packet(result: ValidationResult) -> None:
        accepted.append(result)
        accepted_event.set()

    first_receiver = TelemetryUDPReceiver(
        packet_handler=handle_packet,
        authenticator=TelemetryAuthenticator(_SHARED_SECRET),
        replay_cache=cache,
        host="127.0.0.1",
        port=0,
        rate_limit_per_second=1000,
        burst_capacity=1000,
    )
    first_task = asyncio.create_task(first_receiver.run())
    await asyncio.wait_for(first_receiver.started.wait(), timeout=2)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.setblocking(False)
    loop = asyncio.get_running_loop()
    try:
        await loop.sock_sendto(client, captured_frame, first_receiver.address)
        assert await asyncio.to_thread(accepted_event.wait, 2)
    finally:
        first_receiver.stop()
        await asyncio.wait_for(first_task, timeout=5)
        cache.close()

    restarted_cache = PersistentFrameReplayCache(cache_path, capacity=8)
    restarted_accepted: list[ValidationResult] = []
    restarted = TelemetryUDPReceiver(
        packet_handler=restarted_accepted.append,
        security=SecurityMiddleware(),
        authenticator=TelemetryAuthenticator(_SHARED_SECRET),
        replay_cache=restarted_cache,
        host="127.0.0.1",
        port=0,
        rate_limit_per_second=1000,
        burst_capacity=1000,
    )
    restarted_task = asyncio.create_task(restarted.run())
    await asyncio.wait_for(restarted.started.wait(), timeout=2)
    try:
        await loop.sock_sendto(client, captured_frame, restarted.address)
        replay = await _wait_for_event(
            restarted,
            lambda event: (
                event.get("event") == "telemetry_rejected"
                and event.get("reason_code") == "sequence_duplicate"
            ),
        )
        assert replay["reason_code"] == "sequence_duplicate"
        assert restarted_accepted == []
    finally:
        client.close()
        sender.close()
        restarted.stop()
        await asyncio.wait_for(restarted_task, timeout=5)
        restarted_cache.close()


@pytest.mark.asyncio
async def test_shared_key_cannot_switch_to_an_unconfigured_drone_identity(
    tmp_path,
) -> None:
    sender = TelemetryAuthenticator(_SHARED_SECRET)
    accepted: list[ValidationResult] = []
    replay_cache = PersistentFrameReplayCache(
        tmp_path / "identity-cache.sqlite3",
        8,
    )
    receiver = TelemetryUDPReceiver(
        packet_handler=accepted.append,
        authenticator=TelemetryAuthenticator(_SHARED_SECRET),
        replay_cache=replay_cache,
        host="127.0.0.1",
        port=0,
        rate_limit_per_second=1000,
        burst_capacity=1000,
    )
    task = asyncio.create_task(receiver.run())
    await asyncio.wait_for(receiver.started.wait(), timeout=2)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.setblocking(False)
    loop = asyncio.get_running_loop()
    try:
        legitimate = sender.encode_packet(_packet(305))
        await loop.sock_sendto(client, legitimate, receiver.address)
        await _wait_until(lambda: bool(accepted))
        switched = _packet(305)
        switched["drone_id"] = "unconfigured-drone"
        await loop.sock_sendto(client, sender.encode_packet(switched), receiver.address)
        rejection = await _wait_for_event(
            receiver,
            lambda event: (
                event.get("event") == "telemetry_rejected"
                and event.get("reason_code") == "invalid_schema"
            ),
        )
        assert rejection["offending_field"] == "drone_id"
        assert len(accepted) == 1
    finally:
        client.close()
        sender.close()
        receiver.stop()
        await asyncio.wait_for(task, timeout=5)
        replay_cache.close()


@pytest.mark.asyncio
async def test_scenario_end_ack_waits_until_queued_telemetry_is_processed(
    tmp_path,
) -> None:
    sender = TelemetryAuthenticator(_SHARED_SECRET)
    processed: list[int] = []
    packet_processed = threading.Event()

    def handle_packet(result: ValidationResult) -> None:
        if result.accepted and result.packet is not None:
            processed.append(result.packet.sequence)
            packet_processed.set()

    replay_cache = PersistentFrameReplayCache(tmp_path / "ack-cache.sqlite3", 16)
    receiver = TelemetryUDPReceiver(
        packet_handler=handle_packet,
        control_handler=lambda _: None,
        authenticator=TelemetryAuthenticator(_SHARED_SECRET),
        replay_cache=replay_cache,
        host="127.0.0.1",
        port=0,
        rate_limit_per_second=1000,
        burst_capacity=1000,
    )
    task = asyncio.create_task(receiver.run())
    await asyncio.wait_for(receiver.started.wait(), timeout=2)
    address = receiver.address
    assert address is not None
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.setblocking(False)
    loop = asyncio.get_running_loop()
    completion_sequence = 820
    completion = {
        "_scoutx_control": "scenario_end",
        "drone_id": settings.dashboard.drone_id,
        "sequence": completion_sequence,
        "timestamp": time.time(),
    }
    try:
        await loop.sock_sendto(client, sender.encode_packet(_packet(819)), address)
        await loop.sock_sendto(client, sender.encode_packet(completion), address)
        ack_frame, _ = await asyncio.wait_for(
            loop.sock_recvfrom(client, 4096),
            timeout=3,
        )
        ack_sequence, ack_payload = sender.decode_frame(ack_frame)
        assert ack_sequence == completion_sequence
        assert json.loads(ack_payload)["_scoutx_control_ack"] == "scenario_end"
        assert await asyncio.to_thread(packet_processed.wait, 1)
        assert processed == [819]
    finally:
        client.close()
        sender.close()
        receiver.stop()
        await asyncio.wait_for(task, timeout=5)
        replay_cache.close()


async def _wait_until(predicate: Callable[[], bool]) -> None:
    deadline = asyncio.get_running_loop().time() + 3
    while asyncio.get_running_loop().time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition was not met before timeout")


async def _wait_for_event(
    receiver: TelemetryUDPReceiver,
    predicate: Callable[[dict[str, object]], bool],
) -> dict[str, object]:
    deadline = asyncio.get_running_loop().time() + 3
    while asyncio.get_running_loop().time() < deadline:
        for event in list(receiver.events):
            if predicate(event):
                return event
        await asyncio.sleep(0.01)
    raise AssertionError("expected receiver event was not emitted")
