"""Compatibility adapters from current legacy stages to typed contracts.

These adapters are deliberately side-effect preserving. They let Phase 2 tests
exercise the contracts while the existing receiver remains unchanged until the
orchestrator phase.
"""

from __future__ import annotations

from typing import Any

from simulation.analysis.attack_classifier import AttackClassifier
from simulation.contracts import (
    AnomalyDetector,
    Classifier,
    DataProtector,
    Enforcer,
    EnforcementResult,
    EventSink,
    HemStatus,
    MlAssessment,
    ResponseDecision,
    ResponseLevel,
    ResponseEngine as ResponseEngineProtocol,
    SecurityEvent,
    ThreatAssessment,
    TrustEngine as TrustEngineProtocol,
    TrustUpdate,
    Validator,
)
from simulation.hem.controller import HEMController
from simulation.ml.anomaly_detector import TelemetryAnomalyDetector
from simulation.security.enforcer import ResponseEnforcer
from simulation.security.response_engine import ResponseEngine as LegacyResponseEngine
from simulation.security.telemetry_middleware import SecurityMiddleware
from simulation.security.telemetry_schema import TelemetryPacket, ValidationResult
from simulation.security.trust_engine import TrustScoreEngine


class MiddlewareValidatorAdapter(Validator):
    """Expose the current byte-oriented middleware as a typed validator."""

    def __init__(self, middleware: SecurityMiddleware) -> None:
        self._middleware = middleware

    def validate(self, packet: TelemetryPacket) -> ValidationResult:
        """Validate a packet using the middleware's existing wire path."""
        return self._middleware.validate_telemetry(packet.model_dump_json().encode())


class AttackClassifierAdapter(Classifier):
    """Convert the classifier's enum output into a threat assessment."""

    def __init__(self, classifier: AttackClassifier) -> None:
        self._classifier = classifier

    def classify(self, result: ValidationResult) -> ThreatAssessment:
        """Preserve the classifier decision while adding contract metadata."""
        attack_type = self._classifier.classify(result)
        return ThreatAssessment(
            correlation_id="unassigned",
            attack_type=attack_type,
            severity=("INFO" if attack_type.value == "UNKNOWN" else "HIGH"),
            pattern=attack_type.value,
            evidence=(result.reason_code.value,),
        )


class TrustEngineAdapter(TrustEngineProtocol):
    """Adapt the existing attack/recovery methods to one typed update method."""

    def __init__(self, engine: TrustScoreEngine) -> None:
        self._engine = engine

    def update(self, assessment: ThreatAssessment) -> TrustUpdate:
        """Apply one deterministic update and return before/after state."""
        previous_score = self._engine.score
        previous_state = self._engine.state.value
        if assessment.attack_type.value == "UNKNOWN":
            event = self._engine.recover()
            reason = "clean_packet_recovery"
        else:
            event = self._engine.apply_attack(assessment.attack_type)
            reason = f"attack:{assessment.attack_type.value}"
        return TrustUpdate(
            correlation_id=assessment.correlation_id,
            previous_score=previous_score,
            score=self._engine.score,
            previous_state=previous_state,
            state=self._engine.state.value,
            trigger_reason=event.trigger_reason if event else reason,
            transitioned=event is not None,
        )


class AnomalyDetectorAdapter(AnomalyDetector):
    """Convert the detector's legacy dictionary result into `MlAssessment`."""

    def __init__(self, detector: TelemetryAnomalyDetector) -> None:
        self._detector = detector

    def assess(self, packet: TelemetryPacket) -> MlAssessment:
        """Run the existing detector without changing readiness behavior."""
        result = self._detector.predict(packet.model_dump())
        return MlAssessment(
            correlation_id="unassigned",
            status=str(result["ml_status"]),
            anomaly=bool(result["ml_anomaly"]),
            risk_score=result["ml_score"],
        )


class ResponseEngineAdapter(ResponseEngineProtocol):
    """Keep the current response policy behind the typed response contract."""

    def __init__(self, engine: LegacyResponseEngine) -> None:
        self._engine = engine

    def decide(
        self,
        threat: ThreatAssessment,
        trust: TrustUpdate,
        ml: MlAssessment,
    ) -> ResponseDecision:
        """Delegate response selection and preserve its mutable streak state."""
        response = self._engine.decide(
            {
                "trust_score": trust.score,
                "trust_state": trust.state,
                "pattern": threat.pattern,
                "severity": threat.severity,
            }
        )
        return ResponseDecision(
            correlation_id=trust.correlation_id,
            response=ResponseLevel(response),
            reason=threat.pattern,
            ml_contributed=ml.anomaly,
        )


class EnforcerAdapter(Enforcer):
    """Adapt the in-place simulated enforcer to an immutable result."""

    def __init__(self, enforcer: ResponseEnforcer) -> None:
        self._enforcer = enforcer

    def enforce(self, decision: ResponseDecision) -> EnforcementResult:
        """Apply the existing simulated action mapping."""
        result = self._enforcer.enforce({"response": decision.response.value})
        return EnforcementResult(
            correlation_id=decision.correlation_id,
            action=str(result["enforced"]),
        )


class HemControllerAdapter(DataProtector):
    """Expose HEM's dictionary result as a typed status snapshot."""

    def __init__(self, controller: HEMController) -> None:
        self._controller = controller

    def protect(
        self,
        packet: TelemetryPacket,
        decision: ResponseDecision,
    ) -> HemStatus:
        """Advance HEM using the same packet and response fields as today."""
        data: dict[str, Any] = packet.model_dump()
        data.update(
            {
                "seq": packet.sequence,
                "trust_score": 0.0
                if decision.response is ResponseLevel.ISOLATE_DRONE
                else 1.0,
                "trust_state": (
                    "PROTECT"
                    if decision.response is ResponseLevel.ISOLATE_DRONE
                    else "STANDBY"
                ),
                "response": decision.response.value,
            }
        )
        result = self._controller.on_packet(data)
        return HemStatus(
            correlation_id=decision.correlation_id,
            phase=str(result.get("hem_phase", self._controller.phase)),
            destination=result.get("destination"),
            transfer_status=result.get("transfer_state"),
            moved_bytes=int(result.get("moved", 0)),
            zeroized=bool(result.get("zeroized", False)),
        )


class JsonlEventSinkAdapter(EventSink):
    """Persist typed events through the existing structured JSONL writer."""

    def __init__(self, writer: Any) -> None:
        self._writer = writer

    def publish(self, event: SecurityEvent) -> None:
        """Append one event without exposing the writer to pipeline callers."""
        self._writer.append(
            event_type=event.event_type,
            severity=event.severity,
            details={
                "correlation_id": event.correlation_id,
                "message": event.message,
            },
            trust=event.trust,
            state=event.state,
        )
