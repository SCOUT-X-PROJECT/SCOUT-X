"""Bounded authenticated UDP intake with an isolated telemetry worker."""

import asyncio
from collections import OrderedDict, deque
from dataclasses import dataclass
import hashlib
import json
import logging
import math
import sqlite3
import socket
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from simulation.config import settings
from simulation.security.telemetry_auth import (
    TelemetryAuthenticationError,
    TelemetryAuthenticator,
)
from simulation.security.telemetry_middleware import SecurityMiddleware
from simulation.security.replay_store import PersistentFrameReplayCache
from simulation.security.telemetry_schema import (
    ValidationReason,
    ValidationResult,
)


_LOGGER = logging.getLogger("scoutx.receiver")


@dataclass
class _TokenBucket:
    tokens: float
    updated_at: float
    flood_reported: bool = False


@dataclass(frozen=True)
class _QueuedDatagram:
    sequence: int
    payload: bytes
    source: str
    source_address: tuple[str, int]
    fingerprint: str


class _SourceRateLimiter:
    """Bound per-source accounting while preventing one address flooding intake."""

    def __init__(
        self,
        *,
        rate: float,
        capacity: int,
        source_capacity: int,
        clock: Callable[[], float],
    ) -> None:
        self.rate = rate
        self.capacity = capacity
        self.source_capacity = source_capacity
        self.clock = clock
        self._buckets: OrderedDict[str, _TokenBucket] = OrderedDict()

    def consume(self, source: str) -> tuple[bool, bool]:
        """Return whether a packet is admitted and whether this is a new flood."""
        now = self.clock()
        bucket = self._buckets.get(source)
        if bucket is None:
            if len(self._buckets) >= self.source_capacity:
                self._buckets.popitem(last=False)
            bucket = _TokenBucket(float(self.capacity), now)
            self._buckets[source] = bucket
        else:
            self._buckets.move_to_end(source)
            bucket.tokens = min(
                float(self.capacity),
                bucket.tokens + max(0.0, now - bucket.updated_at) * self.rate,
            )
            bucket.updated_at = now

        if bucket.tokens >= self.capacity:
            bucket.flood_reported = False
        if bucket.tokens < 1:
            newly_reported = not bucket.flood_reported
            bucket.flood_reported = True
            return False, newly_reported

        bucket.tokens -= 1
        return True, False

    def report_overflow(self, source: str) -> bool:
        """Coalesce repeated queue-overflow events until the bucket refills."""
        bucket = self._buckets.get(source)
        if bucket is None:
            self.consume(source)
            bucket = self._buckets[source]
        if bucket.flood_reported:
            return False
        bucket.flood_reported = True
        return True


class TelemetryUDPReceiver:
    """Verify MACs at intake, then validate and process packets off the receive loop."""

    def __init__(
        self,
        *,
        packet_handler: Callable[[ValidationResult], None],
        control_handler: Callable[[dict[str, Any]], None] | None = None,
        security: SecurityMiddleware | None = None,
        authenticator: TelemetryAuthenticator | None = None,
        host: str = settings.network.host,
        port: int = settings.network.udp_port,
        queue_capacity: int = settings.network.receiver_queue_capacity,
        rate_limit_per_second: float = settings.network.receiver_rate_limit_per_second,
        burst_capacity: int = settings.network.receiver_burst_capacity,
        source_capacity: int = settings.network.receiver_source_capacity,
        max_datagram_size: int = settings.network.max_datagram_size_bytes,
        event_capacity: int = settings.network.receiver_event_capacity,
        replay_cache: PersistentFrameReplayCache | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Inject processing and limits so UDP behavior is testable without global state."""
        if queue_capacity <= 0 or source_capacity <= 0 or event_capacity <= 0:
            raise ValueError("receiver queue and cache capacities must be positive")
        if (
            not math.isfinite(rate_limit_per_second)
            or rate_limit_per_second <= 0
            or burst_capacity <= 0
            or not 0 < max_datagram_size <= 65507
        ):
            raise ValueError("receiver rate and datagram limits are invalid")
        self.packet_handler = packet_handler
        self.control_handler = control_handler
        self.security = security or SecurityMiddleware()
        self.authenticator = authenticator or TelemetryAuthenticator.from_settings()
        self._owns_replay_cache = replay_cache is None
        cache_path = settings.network.replay_frame_cache_file
        if not cache_path.is_absolute():
            cache_path = Path(__file__).resolve().parents[2] / cache_path
        self.replay_cache = replay_cache or PersistentFrameReplayCache(
            str(cache_path),
            settings.network.replay_frame_cache_capacity,
        )
        self.host = host
        self.port = port
        self.max_datagram_size = max_datagram_size
        self._queue: asyncio.Queue[_QueuedDatagram | None] = asyncio.Queue(
            maxsize=queue_capacity
        )
        self._limiter = _SourceRateLimiter(
            rate=rate_limit_per_second,
            capacity=burst_capacity,
            source_capacity=source_capacity,
            clock=clock,
        )
        self._clock = clock
        self.events: deque[dict[str, object]] = deque(maxlen=event_capacity)
        self._control_sequences: dict[str, int] = {}
        self.started = asyncio.Event()
        self._stop = asyncio.Event()
        self._socket: socket.socket | None = None

    @property
    def address(self) -> tuple[str, int] | None:
        """Expose the bound address after startup, including an assigned ephemeral port."""
        if self._socket is None:
            return None
        host, port = self._socket.getsockname()[:2]
        return str(host), int(port)

    def stop(self) -> None:
        """Request shutdown without interrupting the worker's queue flush."""
        self._stop.set()

    async def run(self) -> None:
        """Receive until stopped, drain queued work, and close owned resources."""
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            sock.bind((self.host, self.port))
        except OSError:
            sock.close()
            self.authenticator.close()
            if self._owns_replay_cache:
                self.replay_cache.close()
            raise
        self._socket = sock
        worker = asyncio.create_task(self._process_queue())
        self.started.set()

        try:
            while not self._stop.is_set():
                try:
                    frame, address = await asyncio.wait_for(
                        loop.sock_recvfrom(
                            sock,
                            self.max_datagram_size + 1,
                        ),
                        timeout=settings.network.receiver_poll_interval_seconds,
                    )
                except TimeoutError:
                    continue
                except asyncio.CancelledError:
                    raise
                except OSError as exc:
                    if not self._stop.is_set():
                        self._emit(
                            "receiver_socket_error",
                            detail=str(exc),
                        )
                    self._stop.set()
                    break

                try:
                    self._admit_datagram(
                        frame,
                        str(address[0]),
                        (str(address[0]), int(address[1])),
                    )
                except Exception as exc:
                    self._emit(
                        "receiver_intake_error",
                        source=str(address[0]),
                        detail=f"{type(exc).__name__}: {exc}",
                    )
        finally:
            self._stop.set()
            await self._queue.join()
            await self._queue.put(None)
            await worker
            sock.close()
            self._socket = None
            self.authenticator.close()
            if self._owns_replay_cache:
                self.replay_cache.close()
            self._flush_logs()

    def _admit_datagram(
        self,
        frame: bytes,
        source: str,
        source_address: tuple[str, int],
    ) -> None:
        allowed, newly_flooding = self._limiter.consume(source)
        if not allowed:
            if newly_flooding:
                self._record_flood(source, "source_rate_limit")
            return

        if len(frame) > self.max_datagram_size:
            self._emit(
                "datagram_too_large",
                source=source,
                detail="Datagram exceeds the configured maximum.",
            )
            return

        try:
            sequence, payload = self.authenticator.decode_frame(frame)
        except TelemetryAuthenticationError as exc:
            self._emit(
                "authentication_failed",
                source=source,
                detail=str(exc),
            )
            return

        try:
            self._queue.put_nowait(
                _QueuedDatagram(
                    sequence,
                    payload,
                    source,
                    source_address,
                    hashlib.sha256(frame).hexdigest(),
                )
            )
        except asyncio.QueueFull:
            if self._limiter.report_overflow(source):
                self._record_flood(source, "processing_queue_full")

    async def _process_queue(self) -> None:
        """Process each authenticated frame away from socket intake and isolate failures."""
        while True:
            item = await self._queue.get()
            try:
                if item is None:
                    return
                await self._run_in_processor(lambda: self._process_datagram(item))
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._emit(
                    "packet_processing_error",
                    source=None if item is None else item.source,
                    detail=f"{type(exc).__name__}: {exc}",
                )
            finally:
                self._queue.task_done()

    async def _run_in_processor(self, callback: Callable[[], None]) -> None:
        await asyncio.to_thread(callback)

    def _process_datagram(self, item: _QueuedDatagram) -> None:
        try:
            decoded = json.loads(item.payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            result = self.security.validate_telemetry(item.payload)
            self._emit_validation(result, item.source)
            return

        if isinstance(decoded, dict) and decoded.get("_scoutx_control") in {
            "scenario_start",
            "protect_reset",
            "scenario_end",
        }:
            if (
                type(decoded.get("sequence")) is not int
                or decoded["sequence"] != item.sequence
                or not isinstance(decoded.get("drone_id"), str)
                or not decoded["drone_id"]
                or len(decoded["drone_id"]) > settings.validation.max_drone_id_length
                or decoded["drone_id"] != settings.dashboard.drone_id
            ):
                result = self.security.report_receiver_event(
                    ValidationReason.FRAME_SEQUENCE_MISMATCH,
                    offending_field="sequence or drone_id",
                    detail="Signed control identity or sequence is invalid.",
                )
                self._emit_validation(result, item.source)
                return
            timestamp = decoded.get("timestamp")
            control_timestamp = (
                float(timestamp)
                if isinstance(timestamp, (int, float))
                and not isinstance(timestamp, bool)
                else None
            )
            if (
                control_timestamp is None
                or not math.isfinite(control_timestamp)
                or abs(time.time() - control_timestamp)
                > settings.validation.stale_timestamp_skew_seconds
            ):
                reason = (
                    ValidationReason.FUTURE_TIMESTAMP
                    if control_timestamp is not None and control_timestamp > time.time()
                    else ValidationReason.STALE_TIMESTAMP
                )
                result = self.security.report_receiver_event(
                    reason,
                    offending_field="timestamp",
                    detail="Control timestamp is outside the configured skew window.",
                )
                self._emit_validation(result, item.source)
                return
            drone_id = decoded["drone_id"]
            previous_sequence = self._control_sequences.get(drone_id)
            if previous_sequence is not None and item.sequence <= previous_sequence:
                reason = (
                    ValidationReason.SEQUENCE_DUPLICATE
                    if item.sequence == previous_sequence
                    else ValidationReason.SEQUENCE_OUT_OF_ORDER
                )
                result = self.security.report_receiver_event(
                    reason,
                    offending_field="sequence",
                    detail="Control sequence is replayed or out of order.",
                )
                self._emit_validation(result, item.source)
                return
            if (
                previous_sequence is None
                and len(self._control_sequences)
                >= settings.validation.replay_cache_capacity
            ):
                result = self.security.report_receiver_event(
                    ValidationReason.REPLAY_CACHE_FULL,
                    offending_field="drone_id",
                    detail="Control replay cache is full; new identities are rejected.",
                )
                self._emit_validation(result, item.source)
                return
            if self.control_handler is None:
                self._emit(
                    "unsupported_control_message",
                    source=item.source,
                    detail="No authenticated control handler is configured.",
                )
                return
            if not self._record_frame(item):
                return
            self._control_sequences[drone_id] = item.sequence
            self.control_handler(decoded)
            self._emit("authenticated_control", source=item.source)
            if decoded["_scoutx_control"] == "scenario_end":
                self._send_control_ack(item)
            return

        if not isinstance(decoded, dict) or type(decoded.get("sequence")) is not int:
            result = self.security.validate_telemetry(item.payload)
            self._emit_validation(result, item.source)
            return
        telemetry_identity = decoded.get("drone_id")
        if not isinstance(telemetry_identity, str) or telemetry_identity not in {
            settings.network.drone_id,
            settings.dashboard.drone_id,
        }:
            result = self.security.report_receiver_event(
                ValidationReason.INVALID_SCHEMA,
                offending_field="drone_id",
                detail="Signed telemetry identity is not configured for this receiver.",
            )
            self._emit_validation(result, item.source)
            return
        if decoded["sequence"] != item.sequence:
            result = self.security.report_receiver_event(
                ValidationReason.FRAME_SEQUENCE_MISMATCH,
                offending_field="sequence",
                detail="Signed frame sequence does not match the telemetry payload.",
            )
            self._emit_validation(result, item.source)
            return

        result = self.security.validate_telemetry(item.payload)
        if result.accepted:
            if not self._record_frame(item):
                return
            self.packet_handler(result)
        else:
            self._emit_validation(result, item.source)

    def _record_frame(self, item: _QueuedDatagram) -> bool:
        try:
            is_new = self.replay_cache.record(item.fingerprint)
        except sqlite3.Error:
            self._emit(
                "replay_cache_error",
                source=item.source,
                detail="Persistent replay state is unavailable; frame was rejected.",
            )
            return False
        if not is_new:
            result = self.security.report_receiver_event(
                ValidationReason.SEQUENCE_DUPLICATE,
                offending_field="sequence",
                detail="Authenticated frame was already accepted before this process.",
            )
            self._emit_validation(result, item.source)
            return False
        return True

    def _send_control_ack(self, item: _QueuedDatagram) -> None:
        if self._socket is None:
            return
        message = {
            "_scoutx_control_ack": "scenario_end",
            "drone_id": settings.network.drone_id,
            "sequence": item.sequence,
            "timestamp": time.time(),
        }
        try:
            self._socket.sendto(
                self.authenticator.encode_packet(message),
                item.source_address,
            )
        except OSError as exc:
            self._emit(
                "control_ack_error",
                source=item.source,
                detail=f"{type(exc).__name__}: {exc}",
            )

    def _record_flood(self, source: str, cause: str) -> None:
        result = self.security.report_receiver_event(
            ValidationReason.TELEMETRY_FLOODING,
            offending_field="source",
            detail=f"Telemetry intake limit exceeded: {cause}.",
        )
        self._emit(
            "telemetry_flooding",
            source=source,
            cause=cause,
            classification=result.classification,
            trust_score=self.security.trust_score,
        )

    def _emit_validation(self, result: ValidationResult, source: str) -> None:
        self._emit(
            "telemetry_rejected",
            source=source,
            reason_code=result.reason_code.value,
            severity=result.severity.value,
            offending_field=result.offending_field,
            classification=result.classification,
        )

    def _emit(
        self,
        event: str,
        *,
        source: str | None = None,
        **fields: object,
    ) -> None:
        record: dict[str, object] = {
            "event": event,
            "source": source,
            **fields,
        }
        self.events.append(record)
        level = logging.WARNING if event != "authenticated_control" else logging.INFO
        _LOGGER.log(level, json.dumps(record, sort_keys=True))

    @staticmethod
    def _flush_logs() -> None:
        for logger in (_LOGGER, logging.getLogger()):
            for handler in logger.handlers:
                handler.flush()
