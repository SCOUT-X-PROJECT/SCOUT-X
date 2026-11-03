import pytest

from simulation.analysis.attack_classifier import AttackClassifier, AttackType
from simulation.config import settings
from simulation.security.response_engine import ResponseEngine
from simulation.security.telemetry_schema import (
    ValidationReason,
    ValidationResult,
    ValidationSeverity,
)
from simulation.security.trust_engine import (
    TRANSITION_TABLE,
    TrustScoreEngine,
    TrustState,
)


THRESHOLD_SCENARIOS = [
    (1.0, TrustState.STANDBY),
    (0.95, TrustState.STANDBY),
    (0.800001, TrustState.STANDBY),
    (0.8, TrustState.STANDBY),
    (0.799999, TrustState.PREPARE),
    (0.75, TrustState.PREPARE),
    (0.500001, TrustState.PREPARE),
    (0.5, TrustState.PREPARE),
    (0.499999, TrustState.EVACUATE),
    (0.4, TrustState.EVACUATE),
    (0.200001, TrustState.EVACUATE),
    (0.2, TrustState.PROTECT),
    (0.199999, TrustState.PROTECT),
    (0.1, TrustState.PROTECT),
    (0.0, TrustState.PROTECT),
    (0.81, TrustState.STANDBY),
    (0.79, TrustState.PREPARE),
    (0.51, TrustState.PREPARE),
    (0.49, TrustState.EVACUATE),
    (0.21, TrustState.EVACUATE),
    (0.19, TrustState.PROTECT),
    (0.999, TrustState.STANDBY),
    (0.6, TrustState.PREPARE),
    (0.3, TrustState.EVACUATE),
    (0.01, TrustState.PROTECT),
]


def validation_result(
    reason: ValidationReason,
    *,
    accepted: bool = False,
    field: str | None = None,
) -> ValidationResult:
    return ValidationResult(
        accepted=accepted,
        reason_code=reason,
        severity=(ValidationSeverity.INFO if accepted else ValidationSeverity.HIGH),
        offending_field=field,
    )


def test_readme_threshold_defaults_are_exact() -> None:
    assert settings.trust.standby_threshold == 0.80
    assert settings.trust.prepare_threshold == 0.80
    assert settings.trust.evacuate_threshold == 0.50
    assert settings.trust.protect_threshold == 0.20


def test_response_engine_protects_at_inclusive_boundary() -> None:
    engine = ResponseEngine()

    assert engine.decide({"trust_score": 0.20}) == "ISOLATE_DRONE"
    assert engine.decide({"trust_score": 0.200001}) == "NORMAL_OPERATION"


def test_transition_table_is_explicit_and_protect_has_no_exit() -> None:
    assert TRANSITION_TABLE[TrustState.PROTECT] == {}
    assert TrustState.PREPARE in TRANSITION_TABLE[TrustState.STANDBY]
    assert TrustState.EVACUATE in TRANSITION_TABLE[TrustState.PREPARE]
    assert TrustState.PROTECT in TRANSITION_TABLE[TrustState.EVACUATE]


@pytest.mark.parametrize(("score", "expected_state"), THRESHOLD_SCENARIOS)
def test_threshold_state_mapping_table(
    score: float,
    expected_state: TrustState,
) -> None:
    assert TrustScoreEngine.state_for_score(score) is expected_state


def test_escalations_use_base_thresholds_without_hysteresis() -> None:
    engine = TrustScoreEngine(initial_score=0.8)
    event = engine.observe_score(0.79, clean_packet=True)

    assert engine.state is TrustState.PREPARE
    assert event is not None
    assert event.trigger_reason.endswith("trust_below_prepare")

    engine = TrustScoreEngine(initial_score=0.8)
    event = engine.observe_score(0.2, clean_packet=True)
    assert engine.state is TrustState.PROTECT
    assert event is not None
    assert event.trigger_reason.endswith("trust_at_or_below_protect")


def test_higher_severity_transition_is_immediate() -> None:
    engine = TrustScoreEngine(initial_score=0.79)

    event = engine.observe_score(0.499, clean_packet=False)

    assert engine.state is TrustState.EVACUATE
    assert event is not None


def test_recovery_requires_strict_margin_and_consecutive_clean_packets() -> None:
    engine = TrustScoreEngine(initial_score=0.79)
    threshold = settings.trust.prepare_threshold + settings.trust.hysteresis_margin

    for _ in range(settings.trust.recovery_clean_packets):
        assert engine.observe_score(threshold, clean_packet=True) is None
    assert engine.state is TrustState.PREPARE

    event = None
    for _ in range(settings.trust.recovery_clean_packets):
        event = engine.observe_score(threshold + 0.001, clean_packet=True)

    assert engine.state is TrustState.STANDBY
    assert event is not None
    assert event.trigger_reason == "recovery_hysteresis_satisfied"


def test_one_non_clean_packet_resets_recovery_streak() -> None:
    engine = TrustScoreEngine(initial_score=0.79)
    recovery_score = (
        settings.trust.prepare_threshold + settings.trust.hysteresis_margin + 0.01
    )

    for _ in range(settings.trust.recovery_clean_packets - 1):
        engine.observe_score(recovery_score, clean_packet=True)
    engine.observe_score(recovery_score, clean_packet=False)
    for _ in range(settings.trust.recovery_clean_packets - 1):
        engine.observe_score(recovery_score, clean_packet=True)

    assert engine.state is TrustState.PREPARE
    assert engine.observe_score(recovery_score, clean_packet=True) is not None
    assert engine.state is TrustState.STANDBY


def test_borderline_oscillation_does_not_flap() -> None:
    engine = TrustScoreEngine(initial_score=0.79)

    for score in [0.79, 0.81] * 20:
        engine.observe_score(score, clean_packet=True)

    assert engine.state is TrustState.PREPARE
    assert not engine.transition_events


def test_evacuate_recovery_uses_evacuate_threshold_plus_margin() -> None:
    engine = TrustScoreEngine(initial_score=0.49)
    recovery_score = (
        settings.trust.evacuate_threshold + settings.trust.hysteresis_margin
    )

    for _ in range(settings.trust.recovery_clean_packets):
        engine.observe_score(recovery_score, clean_packet=True)
    assert engine.state is TrustState.EVACUATE

    for _ in range(settings.trust.recovery_clean_packets):
        engine.observe_score(recovery_score + 0.001, clean_packet=True)
    assert engine.state is TrustState.PREPARE


def test_protect_latch_survives_arbitrary_clean_score_sequence() -> None:
    engine = TrustScoreEngine(initial_score=0.2)

    for score in [0.21, 0.5, 0.79, 0.81, 1.0] * 10:
        engine.observe_score(score, clean_packet=True)

    assert engine.state is TrustState.PROTECT


def test_protect_reset_requires_authentication_and_recovered_trust() -> None:
    engine = TrustScoreEngine(
        initial_score=0.2,
        reset_token="private-reset-token",
    )
    engine.observe_score(0.7, clean_packet=True)

    assert engine.reset_protect("wrong-token") is False
    assert engine.state is TrustState.PROTECT
    assert engine.reset_protect("private-reset-token") is True
    assert engine.state is TrustState.PREPARE
    assert engine.transition_events[-1].trigger_reason == (
        "authenticated_protect_reset"
    )


def test_protect_reset_is_disabled_without_configured_secret() -> None:
    engine = TrustScoreEngine(initial_score=0.2, reset_token="")
    engine.observe_score(0.7, clean_packet=True)

    assert engine.reset_protect("anything") is False
    assert engine.state is TrustState.PROTECT


def test_protect_reset_does_not_override_low_score() -> None:
    engine = TrustScoreEngine(
        initial_score=0.2,
        reset_token="private-reset-token",
    )

    assert engine.reset_protect("private-reset-token") is False
    assert engine.state is TrustState.PROTECT


def test_transition_callback_and_queue_receive_structured_event() -> None:
    now = [123.0]
    callbacks = []
    engine = TrustScoreEngine(
        initial_score=0.8,
        clock=lambda: now[0],
        event_callback=callbacks.append,
    )

    now[0] = 456.0
    event = engine.observe_score(0.79, clean_packet=False)

    assert event is not None
    assert event.timestamp == 456.0
    assert callbacks == [event]
    assert engine.transition_events[-1].to_dict() == event.to_dict()


def test_weighted_attack_penalties_and_clamping() -> None:
    engine = TrustScoreEngine(initial_score=0.9)
    expected = 0.9 - settings.trust.penalty_gps_spoofing

    engine.apply_attack(AttackType.GPS_SPOOFING)

    assert engine.score == expected
    engine = TrustScoreEngine(initial_score=0.1)
    engine.apply_attack(AttackType.MULTI_VECTOR)
    assert engine.score == 0.0


def test_recovery_is_bounded_and_time_independent() -> None:
    now = [0.0]
    engine = TrustScoreEngine(initial_score=0.5, clock=lambda: now[0])

    engine.recover()
    now[0] = 1_000_000.0
    engine.recover()

    assert engine.score == 0.5 + 2 * settings.trust.recovery_rate
    assert settings.trust.recovery_rate <= 0.10


def test_non_finite_scores_are_rejected() -> None:
    engine = TrustScoreEngine()

    try:
        engine.observe_score(float("nan"), clean_packet=True)
    except ValueError as exc:
        assert "finite" in str(exc)
    else:
        raise AssertionError("non-finite trust scores must be rejected")


def test_classifier_maps_validation_reasons_to_typed_attacks() -> None:
    cases = [
        (ValidationReason.GPS_JUMP, "lat", AttackType.GPS_JUMP),
        (
            ValidationReason.GPS_SPEED_MISMATCH,
            "speed",
            AttackType.SPEED_ANOMALY,
        ),
        (
            ValidationReason.ALTITUDE_RATE_EXCEEDED,
            "altitude",
            AttackType.ALTITUDE_MANIPULATION,
        ),
        (
            ValidationReason.BATTERY_INCREASE,
            "battery",
            AttackType.BATTERY_ANOMALY,
        ),
        (
            ValidationReason.SEQUENCE_DUPLICATE,
            "sequence",
            AttackType.REPLAY,
        ),
        (
            ValidationReason.VALUE_OUT_OF_RANGE,
            "lat",
            AttackType.GPS_SPOOFING,
        ),
    ]

    for reason, field, expected in cases:
        result = validation_result(reason, field=field)
        assert AttackClassifier().classify(result) is expected


def test_classifier_detects_multi_vector_with_bounded_history() -> None:
    classifier = AttackClassifier(clock=lambda: 1.0, history_window=3)

    assert (
        classifier.classify(validation_result(ValidationReason.GPS_JUMP, field="lat"))
        is AttackType.GPS_JUMP
    )
    assert (
        classifier.classify(
            validation_result(ValidationReason.BATTERY_INCREASE, field="battery")
        )
        is AttackType.MULTI_VECTOR
    )


def test_classifier_detects_telemetry_flooding_in_configured_window() -> None:
    now = [1.0]
    classifier = AttackClassifier(
        clock=lambda: now[0],
        history_window=5,
        flood_threshold=3,
        flood_window_seconds=1.0,
    )
    result = validation_result(ValidationReason.SEQUENCE_DUPLICATE)

    assert classifier.classify(result) is AttackType.REPLAY
    now[0] += 0.1
    assert classifier.classify(result) is AttackType.REPLAY
    now[0] += 0.1
    assert classifier.classify(result) is AttackType.TELEMETRY_FLOODING


def test_classifier_history_expires_by_injected_clock() -> None:
    now = [1.0]
    classifier = AttackClassifier(
        clock=lambda: now[0],
        history_window=5,
        flood_threshold=2,
        flood_window_seconds=0.5,
    )
    result = validation_result(ValidationReason.GPS_JUMP)

    classifier.classify(result)
    now[0] += 1.0

    assert classifier.classify(result) is AttackType.GPS_JUMP


def test_attack_types_have_defined_severity_scores() -> None:
    assert set(AttackType) == {
        AttackType.GPS_SPOOFING,
        AttackType.GPS_JUMP,
        AttackType.ALTITUDE_MANIPULATION,
        AttackType.SPEED_ANOMALY,
        AttackType.BATTERY_ANOMALY,
        AttackType.REPLAY,
        AttackType.TELEMETRY_FLOODING,
        AttackType.MULTI_VECTOR,
        AttackType.UNKNOWN,
    }
    assert all(0.0 <= attack.severity_score <= 1.0 for attack in AttackType)
