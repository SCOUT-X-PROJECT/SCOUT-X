"""Classify structured validation results and recognize short-window attack mixes."""

from collections import deque
from typing import Callable
import time

from simulation.config import settings
from simulation.contracts import AttackType
from simulation.security.telemetry_schema import ValidationReason, ValidationResult

_REASON_TYPES = {
    ValidationReason.GPS_JUMP: AttackType.GPS_JUMP,
    ValidationReason.GPS_SPEED_MISMATCH: AttackType.SPEED_ANOMALY,
    ValidationReason.ALTITUDE_RATE_EXCEEDED: AttackType.ALTITUDE_MANIPULATION,
    ValidationReason.BATTERY_INCREASE: AttackType.BATTERY_ANOMALY,
    ValidationReason.SEQUENCE_DUPLICATE: AttackType.REPLAY,
    ValidationReason.SEQUENCE_OUT_OF_ORDER: AttackType.REPLAY,
    ValidationReason.TIMESTAMP_NON_MONOTONIC: AttackType.REPLAY,
    ValidationReason.STALE_TIMESTAMP: AttackType.REPLAY,
    ValidationReason.FUTURE_TIMESTAMP: AttackType.REPLAY,
    ValidationReason.FRAME_SEQUENCE_MISMATCH: AttackType.REPLAY,
    ValidationReason.TELEMETRY_FLOODING: AttackType.TELEMETRY_FLOODING,
}


class AttackClassifier:
    """Use validation evidence and a bounded history instead of packet dictionaries."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        history_window: int | None = None,
        flood_threshold: int | None = None,
        flood_window_seconds: float | None = None,
    ) -> None:
        """Bound retained evidence so classification cannot grow memory indefinitely."""
        self._clock = clock
        self._history: deque[tuple[float, AttackType, bool]] = deque(
            maxlen=(
                settings.trust.classifier_history_window
                if history_window is None
                else history_window
            )
        )
        self._flood_threshold = (
            settings.trust.classifier_flood_threshold
            if flood_threshold is None
            else flood_threshold
        )
        self._flood_window_seconds = (
            settings.trust.classifier_flood_window_seconds
            if flood_window_seconds is None
            else flood_window_seconds
        )

    def classify(self, result: ValidationResult) -> AttackType:
        """Return one attack type while accounting for recent independent signals."""
        now = self._clock()
        self._discard_expired(now)
        detected = self._classify_result(result)
        self._history.append((now, detected, not result.accepted))
        if detected is AttackType.TELEMETRY_FLOODING:
            return detected
        recent_attacks = [
            attack
            for timestamp, attack, rejected in self._history
            if (
                rejected
                and attack is not AttackType.UNKNOWN
                and now - timestamp <= self._flood_window_seconds
            )
        ]
        recent_rejections = sum(
            rejected
            for timestamp, _attack, rejected in self._history
            if now - timestamp <= self._flood_window_seconds
        )
        if not result.accepted and recent_rejections >= self._flood_threshold:
            return AttackType.TELEMETRY_FLOODING

        distinct_types = set(recent_attacks)
        if len(distinct_types) > 1:
            return AttackType.MULTI_VECTOR

        return detected

    def _classify_result(self, result: ValidationResult) -> AttackType:
        if result.reason_code is ValidationReason.SEQUENCE_GAP and result.accepted:
            return AttackType.UNKNOWN
        if result.accepted:
            return AttackType.UNKNOWN

        reason_type = _REASON_TYPES.get(result.reason_code)
        if reason_type is not None:
            return reason_type
        if (
            result.reason_code is ValidationReason.VALUE_OUT_OF_RANGE
            and result.offending_field in {"lat", "lon"}
        ):
            return AttackType.GPS_SPOOFING
        if (
            result.reason_code is ValidationReason.VALUE_OUT_OF_RANGE
            and result.offending_field == "altitude"
        ):
            return AttackType.ALTITUDE_MANIPULATION
        return AttackType.UNKNOWN

    def _discard_expired(self, now: float) -> None:
        while self._history and now - self._history[0][0] > self._flood_window_seconds:
            self._history.popleft()
