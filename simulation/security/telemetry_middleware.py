"""Validate untrusted telemetry before it can affect simulation state."""

import json
import time
from collections import OrderedDict, deque
from threading import RLock
from typing import Callable

from pydantic import ValidationError

from simulation.analysis.attack_classifier import AttackClassifier
from simulation.config import settings
from simulation.security.telemetry_schema import (
    TelemetryPacket,
    ValidationReason,
    ValidationResult,
    ValidationSeverity,
)
from simulation.security.trust_engine import (
    TrustScoreEngine,
    TrustState,
    TrustTransitionEvent,
)
from simulation.validators.consistency_validator import validate_consistency


_REASON_SEVERITY = {
    ValidationReason.ACCEPTED: ValidationSeverity.INFO,
    ValidationReason.MALFORMED_PAYLOAD: ValidationSeverity.MEDIUM,
    ValidationReason.PAYLOAD_TOO_LARGE: ValidationSeverity.HIGH,
    ValidationReason.INVALID_SCHEMA: ValidationSeverity.MEDIUM,
    ValidationReason.UNKNOWN_FIELD: ValidationSeverity.MEDIUM,
    ValidationReason.INVALID_TYPE: ValidationSeverity.MEDIUM,
    ValidationReason.VALUE_OUT_OF_RANGE: ValidationSeverity.HIGH,
    ValidationReason.STALE_TIMESTAMP: ValidationSeverity.MEDIUM,
    ValidationReason.FUTURE_TIMESTAMP: ValidationSeverity.MEDIUM,
    ValidationReason.TIMESTAMP_NON_MONOTONIC: ValidationSeverity.HIGH,
    ValidationReason.SEQUENCE_DUPLICATE: ValidationSeverity.HIGH,
    ValidationReason.SEQUENCE_OUT_OF_ORDER: ValidationSeverity.HIGH,
    ValidationReason.SEQUENCE_GAP: ValidationSeverity.MEDIUM,
    ValidationReason.GPS_JUMP: ValidationSeverity.HIGH,
    ValidationReason.GPS_SPEED_MISMATCH: ValidationSeverity.HIGH,
    ValidationReason.ALTITUDE_RATE_EXCEEDED: ValidationSeverity.HIGH,
    ValidationReason.BATTERY_INCREASE: ValidationSeverity.MEDIUM,
    ValidationReason.REPLAY_CACHE_FULL: ValidationSeverity.HIGH,
    ValidationReason.TELEMETRY_FLOODING: ValidationSeverity.HIGH,
    ValidationReason.FRAME_SEQUENCE_MISMATCH: ValidationSeverity.HIGH,
}

_VALIDATION_ERROR_REASONS = {
    "extra_forbidden": ValidationReason.UNKNOWN_FIELD,
    "int_type": ValidationReason.INVALID_TYPE,
    "float_type": ValidationReason.INVALID_TYPE,
    "string_type": ValidationReason.INVALID_TYPE,
    "missing": ValidationReason.INVALID_SCHEMA,
    "model_type": ValidationReason.INVALID_SCHEMA,
}


class SecurityMiddleware:
    """Keep replay state and physical validation at the telemetry trust boundary."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] | None = None,
        event_callback: Callable[[TrustTransitionEvent], None] | None = None,
    ) -> None:
        """Centralize validation and trust updates at the untrusted telemetry boundary."""
        if clock is None:
            self.trust_engine = TrustScoreEngine(event_callback=event_callback)
            self.attack_classifier = AttackClassifier()
        else:
            self.trust_engine = TrustScoreEngine(
                clock=clock,
                event_callback=event_callback,
            )
            self.attack_classifier = AttackClassifier(clock=clock)
        self._windows: OrderedDict[str, deque[TelemetryPacket]] = OrderedDict()
        self._lock = RLock()

    @property
    def trust_score(self) -> float:
        """Provide downstream components the middleware's authoritative trust score."""
        with self._lock:
            return self.trust_engine.score

    @property
    def trust_state(self) -> TrustState:
        """Keep response components aligned with the middleware's state machine."""
        with self._lock:
            return self.trust_engine.state

    def reset_protect(self, token: str) -> bool:
        """Expose the authenticated trust-latch reset without adding an API route."""
        return self.trust_engine.reset_protect(token)

    def validate_telemetry(self, data: object) -> ValidationResult:
        """Serialize replay and trust-state updates shared by intake and worker threads."""
        with self._lock:
            return self._validate_telemetry(data)

    def _validate_telemetry(self, data: object) -> ValidationResult:
        """Return a structured decision and retain only successfully checked packets."""
        try:
            payload = self._get_json_payload(data)
        except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
            return self._reject(
                ValidationReason.MALFORMED_PAYLOAD,
                detail="Payload is not valid bounded JSON telemetry.",
            )

        if isinstance(payload, ValidationResult):
            return payload

        try:
            candidate = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            return self._reject(
                ValidationReason.MALFORMED_PAYLOAD,
                detail="Payload is not valid UTF-8 JSON.",
            )

        try:
            packet = TelemetryPacket.model_validate(candidate)
        except ValidationError as exc:
            error = exc.errors()[0]
            reason = _VALIDATION_ERROR_REASONS.get(
                str(error["type"]),
                ValidationReason.VALUE_OUT_OF_RANGE,
            )
            field_path = ".".join(str(item) for item in error["loc"]) or None
            return self._reject(
                reason,
                offending_field=field_path,
                detail="Telemetry does not satisfy the strict packet schema.",
            )

        now = time.time()
        skew = settings.validation.stale_timestamp_skew_seconds
        if packet.timestamp < now - skew:
            return self._reject(
                ValidationReason.STALE_TIMESTAMP,
                offending_field="timestamp",
                detail="Timestamp is older than the configured skew window.",
            )
        if packet.timestamp > now + skew:
            return self._reject(
                ValidationReason.FUTURE_TIMESTAMP,
                offending_field="timestamp",
                detail="Timestamp exceeds the configured future skew window.",
            )

        previous: TelemetryPacket | None = None
        window = self._windows.get(packet.drone_id)
        if window is None:
            if len(self._windows) >= settings.validation.replay_cache_capacity:
                return self._reject(
                    ValidationReason.REPLAY_CACHE_FULL,
                    offending_field="drone_id",
                    detail="Replay cache is full; untracked drones are rejected.",
                )
            window = deque(maxlen=settings.validation.replay_window_size)
        else:
            previous = window[-1]
            if packet.sequence == previous.sequence:
                return self._reject(
                    ValidationReason.SEQUENCE_DUPLICATE,
                    offending_field="sequence",
                    detail="Sequence number has already been accepted.",
                )
            if packet.sequence < previous.sequence:
                return self._reject(
                    ValidationReason.SEQUENCE_OUT_OF_ORDER,
                    offending_field="sequence",
                    detail="Sequence number is older than the latest accepted packet.",
                )

        previous = window[-1] if window else None
        consistency = validate_consistency(previous, packet)
        if not consistency.accepted:
            return self._record_result(consistency)

        window.append(packet)
        self._windows[packet.drone_id] = window
        self._windows.move_to_end(packet.drone_id)
        result = ValidationResult(
            accepted=True,
            reason_code=consistency.reason_code,
            severity=consistency.severity,
            offending_field=consistency.offending_field,
            packet=packet,
            detail=consistency.detail,
        )
        return self._record_result(result)

    def _get_json_payload(self, data: object) -> bytes | ValidationResult:
        """Bound payload size before parsing to avoid unbounded wire allocations."""
        size_limit = settings.validation.max_telemetry_payload_bytes
        if isinstance(data, memoryview):
            if data.nbytes > size_limit:
                return self._reject(
                    ValidationReason.PAYLOAD_TOO_LARGE,
                    detail="Payload exceeds the configured byte limit.",
                )
            payload = bytes(data)
        elif isinstance(data, (bytes, bytearray)):
            if len(data) > size_limit:
                return self._reject(
                    ValidationReason.PAYLOAD_TOO_LARGE,
                    detail="Payload exceeds the configured byte limit.",
                )
            payload = bytes(data)
        elif isinstance(data, str):
            if len(data) > size_limit:
                return self._reject(
                    ValidationReason.PAYLOAD_TOO_LARGE,
                    detail="Payload exceeds the configured byte limit.",
                )
            payload = data.encode("utf-8")
        elif isinstance(data, dict):
            encoder = json.JSONEncoder(
                separators=(",", ":"),
                ensure_ascii=False,
            )
            payload_parts: list[bytes] = []
            payload_size = 0
            for chunk in encoder.iterencode(data):
                if len(chunk) > size_limit:
                    return self._reject(
                        ValidationReason.PAYLOAD_TOO_LARGE,
                        detail="Payload exceeds the configured byte limit.",
                    )
                encoded_chunk = chunk.encode("utf-8")
                payload_size += len(encoded_chunk)
                if payload_size > size_limit:
                    return self._reject(
                        ValidationReason.PAYLOAD_TOO_LARGE,
                        detail="Payload exceeds the configured byte limit.",
                    )
                payload_parts.append(encoded_chunk)
            payload = b"".join(payload_parts)
        else:
            return self._reject(
                ValidationReason.MALFORMED_PAYLOAD,
                detail="Expected UTF-8 JSON bytes or a JSON object.",
            )

        if len(payload) > size_limit:
            return self._reject(
                ValidationReason.PAYLOAD_TOO_LARGE,
                offending_field=None,
                detail="Payload exceeds the configured byte limit.",
            )
        return payload

    def _reject(
        self,
        reason: ValidationReason,
        *,
        offending_field: str | None = None,
        detail: str,
    ) -> ValidationResult:
        """Return structured evidence and account for its classified attack type."""
        return self._record_result(
            ValidationResult(
                accepted=False,
                reason_code=reason,
                severity=_REASON_SEVERITY[reason],
                offending_field=offending_field,
                detail=detail,
            )
        )

    def _record_result(self, result: ValidationResult) -> ValidationResult:
        attack_type = self.attack_classifier.classify(result)
        if result.accepted:
            self.trust_engine.recover()
        else:
            self.trust_engine.apply_attack(attack_type)
        return ValidationResult(
            accepted=result.accepted,
            reason_code=result.reason_code,
            severity=result.severity,
            offending_field=result.offending_field,
            packet=result.packet,
            detail=result.detail,
            classification=attack_type.value,
        )

    def report_receiver_event(
        self,
        reason: ValidationReason,
        *,
        offending_field: str | None = None,
        detail: str,
    ) -> ValidationResult:
        """Apply receiver-level attack evidence under the same trust-state lock."""
        with self._lock:
            return self._reject(
                reason,
                offending_field=offending_field,
                detail=detail,
            )
