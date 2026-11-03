"""Contract validation and immutability tests for pipeline boundaries."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from simulation.analysis.attack_classifier import AttackClassifier, AttackType
from simulation.contract_adapters import (
    AttackClassifierAdapter,
    EnforcerAdapter,
    MiddlewareValidatorAdapter,
    ResponseEngineAdapter,
)
from simulation.contracts import (
    EnforcementResult,
    HemStatus,
    MlAssessment,
    Classifier,
    Enforcer,
    ResponseDecision,
    ResponseLevel,
    ResponseEngine as ResponseEngineProtocol,
    SecurityEvent,
    StageError,
    ThreatAssessment,
    TrustUpdate,
    Validator,
)
from simulation.security.enforcer import ResponseEnforcer
from simulation.security.response_engine import ResponseEngine
from simulation.security.telemetry_middleware import SecurityMiddleware


def test_contract_models_are_immutable() -> None:
    assessment = ThreatAssessment(
        correlation_id="session-1:7",
        attack_type=AttackType.GPS_JUMP,
        severity="HIGH",
        pattern="PERSISTENT_ATTACK",
    )

    with pytest.raises(ValidationError):
        assessment.severity = "LOW"


def test_contracts_reject_invalid_security_values() -> None:
    with pytest.raises(ValidationError):
        MlAssessment(
            correlation_id="session-1:7",
            status="ready",
            risk_score=1.1,
        )

    with pytest.raises(ValidationError):
        TrustUpdate(
            correlation_id="session-1:7",
            previous_score=0.5,
            score=-0.1,
            previous_state="STANDBY",
            state="PREPARE",
            trigger_reason="test",
        )


def test_contract_models_round_trip_typed_stage_outputs() -> None:
    decision = ResponseDecision(
        correlation_id="session-1:7",
        response=ResponseLevel.LIMIT_MOVEMENT,
        reason="persistent threat",
    )
    event = SecurityEvent(
        correlation_id=decision.correlation_id,
        timestamp=datetime.now(timezone.utc),
        event_type="RESPONSE",
        severity="HIGH",
        trust=0.4,
        state="PREPARE",
        message=decision.reason,
    )
    result = EnforcementResult(
        correlation_id=event.correlation_id,
        action="RESTRICTED",
    )
    hem = HemStatus(
        correlation_id=result.correlation_id,
        phase="PREPARE",
        destination="BASE",
        moved_bytes=128,
    )
    error = StageError(
        correlation_id=hem.correlation_id,
        stage="hem",
        message="safe failure",
    )

    assert event.correlation_id == hem.correlation_id == error.correlation_id
    assert decision.response is ResponseLevel.LIMIT_MOVEMENT


def test_legacy_adapters_satisfy_stage_protocols() -> None:
    assert isinstance(MiddlewareValidatorAdapter(SecurityMiddleware()), Validator)
    assert isinstance(
        AttackClassifierAdapter(AttackClassifier()),
        Classifier,
    )
    assert isinstance(
        ResponseEngineAdapter(ResponseEngine()),
        ResponseEngineProtocol,
    )
    assert isinstance(EnforcerAdapter(ResponseEnforcer()), Enforcer)
