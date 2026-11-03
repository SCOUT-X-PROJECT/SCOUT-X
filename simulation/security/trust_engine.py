"""Deterministic, hysteretic trust scoring and explicit protection state machine."""

from __future__ import annotations

import hmac
import math
import time
from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Callable

from pydantic import SecretStr

from simulation.config import settings

if TYPE_CHECKING:
    from simulation.analysis.attack_classifier import AttackType


class TrustState(str, Enum):
    """Trust phases ordered from normal operation to terminal protection."""

    STANDBY = "STANDBY"
    PREPARE = "PREPARE"
    EVACUATE = "EVACUATE"
    PROTECT = "PROTECT"


class TrustPolicy:
    """Provide one authoritative interpretation of configured trust boundaries."""

    def __init__(self) -> None:
        self.protect_threshold = settings.trust.protect_threshold
        self.evacuate_threshold = settings.trust.evacuate_threshold
        self.prepare_threshold = settings.trust.prepare_threshold
        self.standby_threshold = settings.trust.standby_threshold
        self.hysteresis_margin = settings.trust.hysteresis_margin
        self.force_land_attack_streak = settings.trust.force_land_attack_streak
        self.limit_movement_attack_streak = settings.trust.limit_movement_attack_streak

    def state_for_score(self, score: float) -> TrustState:
        """Map a score using the documented inclusive/exclusive boundaries."""
        if score <= self.protect_threshold:
            return TrustState.PROTECT
        if score < self.evacuate_threshold:
            return TrustState.EVACUATE
        if score < self.prepare_threshold:
            return TrustState.PREPARE
        return TrustState.STANDBY

    def recovery_threshold(self, state: TrustState) -> float | None:
        """Return the base threshold plus margin required to leave a state."""
        base = {
            TrustState.PREPARE: self.prepare_threshold,
            TrustState.EVACUATE: self.evacuate_threshold,
        }.get(state)
        return None if base is None else base + self.hysteresis_margin

    def is_protect(self, score: float, state: TrustState | None = None) -> bool:
        """Treat either the latched state or the protect boundary as protective."""
        return state is TrustState.PROTECT or score <= self.protect_threshold


@dataclass(frozen=True)
class TrustTransitionEvent:
    """Immutable transition evidence suitable for persistence and audit."""

    old_state: TrustState
    new_state: TrustState
    trust: float
    trigger_reason: str
    timestamp: float

    def to_dict(self) -> dict[str, str | float]:
        """Return a JSON-ready event while retaining explicit state names."""
        return {
            "old_state": self.old_state.value,
            "new_state": self.new_state.value,
            "trust": self.trust,
            "trigger_reason": self.trigger_reason,
            "timestamp": self.timestamp,
        }


TRANSITION_TABLE: dict[TrustState, dict[TrustState, str]] = {
    TrustState.STANDBY: {
        TrustState.PREPARE: "trust_below_prepare",
        TrustState.EVACUATE: "trust_below_evacuate",
        TrustState.PROTECT: "trust_at_or_below_protect",
    },
    TrustState.PREPARE: {
        TrustState.EVACUATE: "trust_below_evacuate",
        TrustState.PROTECT: "trust_at_or_below_protect",
        TrustState.STANDBY: "recovery_hysteresis_satisfied",
    },
    TrustState.EVACUATE: {
        TrustState.PROTECT: "trust_at_or_below_protect",
        TrustState.PREPARE: "recovery_hysteresis_satisfied",
    },
    TrustState.PROTECT: {},
}

_STATE_SEVERITY = {
    TrustState.STANDBY: 0,
    TrustState.PREPARE: 1,
    TrustState.EVACUATE: 2,
    TrustState.PROTECT: 3,
}


class TrustScoreEngine:
    """Apply weighted deterministic penalties and auditable state transitions."""

    def __init__(
        self,
        *,
        initial_score: float | None = None,
        clock: Callable[[], float] = time.monotonic,
        reset_token: SecretStr | str | None = None,
        event_callback: Callable[[TrustTransitionEvent], None] | None = None,
        policy: TrustPolicy | None = None,
    ) -> None:
        """Inject time and event handling so transitions stay testable and auditable."""
        self._clock = clock
        self._event_callback = event_callback
        self.policy = policy or TrustPolicy()
        self._reset_token = (
            settings.trust.reset_token
            if reset_token is None
            else (
                reset_token
                if isinstance(reset_token, SecretStr)
                else SecretStr(reset_token)
            )
        )
        score = settings.trust.default_score if initial_score is None else initial_score
        self._score = self._bounded_score(score)
        self._state = self.policy.state_for_score(self._score)
        self._clean_recovery_streak = 0
        self.transition_events: deque[TrustTransitionEvent] = deque(maxlen=256)

    @property
    def score(self) -> float:
        """Expose the single authoritative, bounded trust value to consumers."""
        return self._score

    @property
    def state(self) -> TrustState:
        """Expose the latched operational state used by downstream response logic."""
        return self._state

    @staticmethod
    def state_for_score(score: float) -> TrustState:
        """Match README boundaries exactly, including PROTECT at 0.20."""
        return TrustPolicy().state_for_score(score)

    def observe_score(
        self,
        score: float,
        *,
        clean_packet: bool,
        trigger_reason: str = "trust_observation",
    ) -> TrustTransitionEvent | None:
        """Evaluate a supplied score so boundaries and hysteresis remain testable."""
        self._score = self._bounded_score(score)
        return self._evaluate_state(clean_packet, trigger_reason)

    def apply_attack(self, attack_type: AttackType) -> TrustTransitionEvent | None:
        """Apply the configured attack weight, then immediately evaluate escalation."""
        penalty = self._penalty_for(attack_type)
        self._score = self._bounded_score(self._score - penalty)
        self._clean_recovery_streak = 0
        return self._evaluate_state(
            clean_packet=False,
            trigger_reason=f"attack:{attack_type.value}",
        )

    def recover(self) -> TrustTransitionEvent | None:
        """Apply one bounded clean-packet recovery step and evaluate hysteresis."""
        self._score = self._bounded_score(self._score + settings.trust.recovery_rate)
        return self._evaluate_state(
            clean_packet=True,
            trigger_reason="clean_packet_recovery",
        )

    def reset_protect(self, token: str) -> bool:
        """Clear the protection latch only with the configured bearer credential."""
        expected = self._reset_token.get_secret_value()
        if (
            not expected
            or not token
            or not hmac.compare_digest(
                token.encode("utf-8"),
                expected.encode("utf-8"),
            )
        ):
            return False
        if self._state is not TrustState.PROTECT:
            return False
        if self._score <= self.policy.protect_threshold:
            return False

        old_state = self._state
        self._state = self.policy.state_for_score(self._score)
        self._clean_recovery_streak = 0
        self._emit_transition(
            old_state,
            self._state,
            "authenticated_protect_reset",
        )
        return True

    def _evaluate_state(
        self,
        clean_packet: bool,
        trigger_reason: str,
    ) -> TrustTransitionEvent | None:
        old_state = self._state
        escalation_target = self._escalation_target(old_state, self._score)
        if escalation_target is not None:
            self._clean_recovery_streak = 0
            return self._emit_transition(
                old_state,
                escalation_target,
                (f"{trigger_reason}:{TRANSITION_TABLE[old_state][escalation_target]}"),
            )

        if old_state in (TrustState.PREPARE, TrustState.EVACUATE):
            target, threshold = self._recovery_target(old_state)
            if clean_packet and self._score > threshold:
                self._clean_recovery_streak += 1
            else:
                self._clean_recovery_streak = 0

            if (
                target is not None
                and self._clean_recovery_streak >= settings.trust.recovery_clean_packets
            ):
                self._clean_recovery_streak = 0
                return self._emit_transition(
                    old_state,
                    target,
                    TRANSITION_TABLE[old_state][target],
                )
        else:
            self._clean_recovery_streak = 0
        return None

    def _escalation_target(
        self,
        current: TrustState,
        score: float,
    ) -> TrustState | None:
        candidates = (
            (
                TrustState.PROTECT,
                score <= self.policy.protect_threshold,
            ),
            (
                TrustState.EVACUATE,
                score < self.policy.evacuate_threshold,
            ),
            (
                TrustState.PREPARE,
                score < self.policy.prepare_threshold,
            ),
        )
        for target, crossed_threshold in candidates:
            if (
                crossed_threshold
                and _STATE_SEVERITY[target] > _STATE_SEVERITY[current]
                and target in TRANSITION_TABLE[current]
            ):
                return target
        return None

    def _recovery_target(
        self,
        current: TrustState,
    ) -> tuple[TrustState | None, float]:
        recovery_transitions = {
            TrustState.EVACUATE: TrustState.PREPARE,
            TrustState.PREPARE: TrustState.STANDBY,
        }
        target = recovery_transitions[current]
        if target not in TRANSITION_TABLE[current]:
            return None, math.inf
        threshold = self.policy.recovery_threshold(current)
        return target, math.inf if threshold is None else threshold

    def _emit_transition(
        self,
        old_state: TrustState,
        new_state: TrustState,
        reason: str,
    ) -> TrustTransitionEvent:
        self._state = new_state
        event = TrustTransitionEvent(
            old_state=old_state,
            new_state=new_state,
            trust=self._score,
            trigger_reason=reason,
            timestamp=self._clock(),
        )
        self.transition_events.append(event)
        if self._event_callback is not None:
            self._event_callback(event)
        return event

    def _penalty_for(self, attack_type: AttackType) -> float:
        penalty_setting = {
            "GPS_SPOOFING": "penalty_gps_spoofing",
            "GPS_JUMP": "penalty_gps_jump",
            "ALTITUDE_MANIPULATION": "penalty_altitude_manipulation",
            "SPEED_ANOMALY": "penalty_speed_anomaly",
            "BATTERY_ANOMALY": "penalty_battery_anomaly",
            "REPLAY": "penalty_replay",
            "TELEMETRY_FLOODING": "penalty_telemetry_flooding",
            "MULTI_VECTOR": "penalty_multi_vector",
            "UNKNOWN": "penalty_unknown",
        }
        return float(getattr(settings.trust, penalty_setting[attack_type.value]))

    @staticmethod
    def _bounded_score(score: float) -> float:
        """Reject non-finite scores and clamp all updates to the trust domain."""
        if not math.isfinite(score):
            raise ValueError("trust score must be finite")
        return min(1.0, max(0.0, score))
