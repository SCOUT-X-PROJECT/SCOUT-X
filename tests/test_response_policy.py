"""Table-driven response-policy and trust-boundary regression tests."""

import pytest

from simulation.ml.fusion import fuse_assessment
from simulation.contracts import MlAssessment, ResponseDecision, ResponseLevel
from simulation.security.response_engine import decide_response
from simulation.security.trust_engine import TrustPolicy, TrustState


@pytest.mark.parametrize(
    ("trust", "state", "pattern", "severity", "streak", "expected"),
    [
        (0.20, "STANDBY", "NORMAL", "LOW", 0, "ISOLATE_DRONE"),
        (0.21, "PROTECT", "NORMAL", "LOW", 0, "ISOLATE_DRONE"),
        (0.70, "PREPARE", "PERSISTENT_ATTACK", "HIGH", 6, "FORCE_LAND"),
        (0.70, "PREPARE", "PERSISTENT_ATTACK", "LOW", 4, "LIMIT_MOVEMENT"),
        (0.70, "PREPARE", "INTERMITTENT_ATTACK", "MEDIUM", 1, "MONITOR"),
        (0.90, "STANDBY", "NORMAL", "LOW", 0, "NORMAL_OPERATION"),
    ],
)
def test_response_policy_table(
    trust: float,
    state: str,
    pattern: str,
    severity: str,
    streak: int,
    expected: str,
) -> None:
    assert (
        decide_response(
            trust=trust,
            state=state,
            pattern=pattern,
            severity=severity,
            attack_streak=streak,
        )
        == expected
    )


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.20, TrustState.PROTECT),
        (0.200001, TrustState.EVACUATE),
        (0.50, TrustState.PREPARE),
        (0.80, TrustState.STANDBY),
    ],
)
def test_trust_policy_boundaries(score: float, expected: TrustState) -> None:
    assert TrustPolicy().state_for_score(score) is expected


def test_typed_fusion_cannot_make_ml_trigger_protection() -> None:
    decision = ResponseDecision(
        correlation_id="s:1",
        response=ResponseLevel.NORMAL_OPERATION,
        reason="deterministic",
    )
    result = fuse_assessment(
        decision,
        MlAssessment(
            correlation_id="s:1",
            status="ready",
            anomaly=True,
            risk_score=1.0,
        ),
    )

    assert result.response is ResponseLevel.MONITOR
