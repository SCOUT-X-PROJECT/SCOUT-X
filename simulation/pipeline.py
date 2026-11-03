"""Central orchestration for the existing SCOUT-X security stages."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
import queue
import threading
import time
import uuid
from typing import Any

from simulation.analysis.attack_analyzer import AttackAnalyzer
from simulation.analysis.attack_classifier import AttackType
from simulation.analysis.threat_stats import ThreatStats
from simulation.config import settings
from simulation.contracts import (
    EnforcementResult,
    HemStatus,
    MlAssessment,
    ResponseDecision,
    ResponseLevel,
    SecurityEvent,
    StageError,
    ThreatAssessment,
    TrustUpdate,
)
from simulation.hem.controller import HEMController
from simulation.logging.attack_logger import AttackLogger
from simulation.ml.anomaly_detector import TelemetryAnomalyDetector
from simulation.ml.fusion import fuse_ml_signal
from simulation.security.enforcer import ResponseEnforcer
from simulation.security.response_engine import ResponseEngine
from simulation.security.telemetry_middleware import SecurityMiddleware
from simulation.security.telemetry_schema import (
    TelemetryPacket,
    ValidationReason,
    ValidationResult,
)


@dataclass(frozen=True)
class SystemStateSnapshot:
    """Immutable dashboard/read-model view owned by the pipeline."""

    version: int
    correlation_id: str | None
    trust_score: float
    trust_state: str
    response: str | None
    hem_phase: str | None
    hem_status: str | None
    ml_score: float | None
    updated_at: datetime


class SystemState:
    """Thread-safe, single-writer state store with versioned snapshots."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._snapshot = SystemStateSnapshot(
            version=0,
            correlation_id=None,
            trust_score=settings.trust.default_score,
            trust_state="STANDBY",
            response=None,
            hem_phase="STANDBY",
            hem_status=None,
            ml_score=None,
            updated_at=datetime.now(timezone.utc),
        )

    def snapshot(self) -> SystemStateSnapshot:
        """Return a stable read-only state view for subscribers."""
        with self._lock:
            return self._snapshot

    def update(
        self,
        *,
        correlation_id: str,
        trust_score: float,
        trust_state: str,
        response: str | None,
        hem_phase: str | None,
        hem_status: str | None,
        ml_score: float | None,
    ) -> SystemStateSnapshot:
        """Commit one complete packet result atomically."""
        with self._lock:
            self._snapshot = SystemStateSnapshot(
                version=self._snapshot.version + 1,
                correlation_id=correlation_id,
                trust_score=max(0.0, min(1.0, trust_score)),
                trust_state=trust_state,
                response=response,
                hem_phase=hem_phase,
                hem_status=hem_status,
                ml_score=ml_score,
                updated_at=datetime.now(timezone.utc),
            )
            return self._snapshot

    def fail_closed(self, correlation_id: str) -> SystemStateSnapshot:
        """Escalate state when a stage fails instead of leaving stale trust active."""
        return self.update(
            correlation_id=correlation_id,
            trust_score=0.0,
            trust_state="PROTECT",
            response=ResponseLevel.ISOLATE_DRONE.value,
            hem_phase="PROTECT",
            hem_status="stage_error",
            ml_score=None,
        )


class EventBus:
    """Non-blocking bounded fan-out for immutable security events."""

    def __init__(
        self, queue_capacity: int = 256, subscriber_capacity: int = 32
    ) -> None:
        if queue_capacity <= 0 or subscriber_capacity <= 0:
            raise ValueError("event bus capacities must be positive")
        self.queue_capacity = queue_capacity
        self.subscriber_capacity = subscriber_capacity
        self._lock = threading.RLock()
        self._subscribers: set[queue.Queue[SecurityEvent]] = set()
        self.dropped_events = 0

    def subscribe(self) -> queue.Queue[SecurityEvent]:
        """Create a bounded subscriber queue."""
        with self._lock:
            if len(self._subscribers) >= self.subscriber_capacity:
                raise RuntimeError("event subscriber capacity reached")
            subscriber: queue.Queue[SecurityEvent] = queue.Queue(
                maxsize=self.queue_capacity
            )
            self._subscribers.add(subscriber)
            return subscriber

    def unsubscribe(self, subscriber: queue.Queue[SecurityEvent]) -> None:
        """Remove a subscriber without affecting other consumers."""
        with self._lock:
            self._subscribers.discard(subscriber)

    def publish(self, event: SecurityEvent) -> None:
        """Publish without blocking; drop the oldest event for slow consumers."""
        with self._lock:
            subscribers = tuple(self._subscribers)
        for subscriber in subscribers:
            try:
                subscriber.put_nowait(event)
            except queue.Full:
                try:
                    subscriber.get_nowait()
                    subscriber.put_nowait(event)
                except queue.Empty:
                    self.dropped_events += 1


@dataclass(frozen=True)
class PipelineResult:
    """All available outputs for one packet and its committed state snapshot."""

    correlation_id: str
    validation: ValidationResult
    threat: ThreatAssessment | None
    trust: TrustUpdate | None
    ml: MlAssessment | None
    response: ResponseDecision | None
    enforcement: EnforcementResult | None
    hem: HemStatus | None
    stage_error: StageError | None
    state: SystemStateSnapshot
    legacy_packet: dict[str, Any] | None = None


class SecurityPipeline:
    """Own the order and failure policy for the security stages."""

    def __init__(
        self,
        *,
        security: SecurityMiddleware,
        analyzer: AttackAnalyzer,
        ml_detector: TelemetryAnomalyDetector,
        response_engine: ResponseEngine,
        enforcer: ResponseEnforcer,
        hem: HEMController,
        logger: AttackLogger | None = None,
        stats: ThreatStats | None = None,
        state: SystemState | None = None,
        event_bus: EventBus | None = None,
        session_id: str | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Inject every collaborator so the pipeline has one explicit owner."""
        self.security = security
        self.analyzer = analyzer
        self.ml_detector = ml_detector
        self.response_engine = response_engine
        self.enforcer = enforcer
        self.hem = hem
        self.logger = logger
        self.stats = stats
        self.state = state or SystemState()
        self.event_bus = event_bus or EventBus()
        self.session_id = session_id or uuid.uuid4().hex
        self.clock = clock
        self._training_packets: list[dict[str, Any]] = []
        self._ml_trained = False
        self.active_scenario: str | None = None

    def process(self, packet: TelemetryPacket) -> PipelineResult:
        """Validate and process one packet through every owned stage."""
        validation = self.security.validate_telemetry(
            packet.model_dump_json().encode("utf-8")
        )
        return self.process_validation(validation)

    def process_validation(self, validation: ValidationResult) -> PipelineResult:
        """Process an already authenticated validation result from UDP intake."""
        packet = validation.packet
        sequence = packet.sequence if packet is not None else -1
        correlation_id = f"{self.session_id}:{sequence}"
        if not validation.accepted or packet is None:
            self._publish(
                correlation_id,
                "VALIDATION_REJECTED",
                "HIGH",
                self.security.trust_score,
                self.security.trust_state.value,
                validation.reason_code.value,
            )
            return PipelineResult(
                correlation_id=correlation_id,
                validation=validation,
                threat=None,
                trust=None,
                ml=None,
                response=None,
                enforcement=None,
                hem=None,
                stage_error=None,
                state=self.state.snapshot(),
            )

        legacy_packet = self._packet_dict(packet, validation)
        try:
            threat = self._threat(legacy_packet, validation, correlation_id)
            trust = self._trust(validation, threat, correlation_id)
            ml = self._ml(legacy_packet, validation, correlation_id)
            deterministic = self.response_engine.decide(
                {
                    **legacy_packet,
                    "pattern": threat.pattern,
                    "severity": threat.severity,
                }
            )
            fusion = fuse_ml_signal(
                deterministic,
                {
                    "ml_status": ml.status,
                    "ml_anomaly": ml.anomaly,
                    "ml_score": ml.risk_score,
                },
            )
            response = ResponseDecision(
                correlation_id=correlation_id,
                response=ResponseLevel(str(fusion["response"])),
                reason=str(fusion["fusion_reason"]),
                ml_contributed=bool(fusion["ml_escalated"]),
            )
            legacy_packet.update(
                {
                    "deterministic_response": deterministic,
                    "ml_fusion": fusion,
                    "response": response.response.value,
                }
            )
            enforced = self.enforcer.enforce(legacy_packet)
            enforcement = EnforcementResult(
                correlation_id=correlation_id,
                action=str(enforced["enforced"]),
            )
            legacy_packet.update(enforced)
            hem_raw = self.hem.on_packet(legacy_packet)
            hem = HemStatus(
                correlation_id=correlation_id,
                phase=str(hem_raw.get("hem_phase", self.hem.phase)),
                destination=hem_raw.get("destination"),
                transfer_status=hem_raw.get("transfer_state"),
                moved_bytes=int(hem_raw.get("moved", 0)),
                zeroized=bool(hem_raw.get("zeroized", False)),
            )
            legacy_packet["hem"] = hem_raw
            if self.stats is not None:
                self.stats.update(legacy_packet)
                self.stats.display()
            if self.logger is not None:
                self.logger.log(
                    legacy_packet,
                    {"pattern": threat.pattern, "severity": threat.severity},
                    response.response.value,
                )
            snapshot = self.state.update(
                correlation_id=correlation_id,
                trust_score=trust.score,
                trust_state=trust.state,
                response=response.response.value,
                hem_phase=hem.phase,
                hem_status=hem.transfer_status,
                ml_score=ml.risk_score,
            )
            self._publish(
                correlation_id,
                "SECURITY_RESULT",
                threat.severity,
                trust.score,
                trust.state,
                response.response.value,
            )
            return PipelineResult(
                correlation_id,
                validation,
                threat,
                trust,
                ml,
                response,
                enforcement,
                hem,
                None,
                snapshot,
                legacy_packet,
            )
        except Exception as exc:
            stage = "pipeline"
            error = StageError(
                correlation_id=correlation_id,
                stage=stage,
                message=f"{type(exc).__name__} in security stage",
            )
            snapshot = self.state.fail_closed(correlation_id)
            self._publish(
                correlation_id,
                "STAGE_ERROR",
                "CRITICAL",
                0.0,
                "PROTECT",
                error.message,
            )
            return PipelineResult(
                correlation_id,
                validation,
                None,
                None,
                None,
                None,
                None,
                None,
                error,
                snapshot,
                legacy_packet,
            )

    def reset_scenario(
        self,
        *,
        hem: HEMController,
        analyzer: AttackAnalyzer,
        response_engine: ResponseEngine,
        enforcer: ResponseEnforcer,
        scenario: str,
        stats: ThreatStats,
    ) -> None:
        """Replace scenario-local mutable collaborators without replacing the pipeline."""
        self.hem = hem
        self.analyzer = analyzer
        self.response_engine = response_engine
        self.enforcer = enforcer
        self.stats = stats
        self.active_scenario = scenario
        self._training_packets.clear()
        self._ml_trained = False

    def _packet_dict(
        self,
        packet: TelemetryPacket,
        validation: ValidationResult,
    ) -> dict[str, Any]:
        data = packet.model_dump()
        data.update(
            {
                "seq": packet.sequence,
                "gps": {"lat": packet.lat, "lon": packet.lon},
                "trust_score": self.security.trust_score,
                "trust_state": self.security.trust_state.value,
                "flagged": False,
                "validation": {
                    "is_anomalous": validation.reason_code
                    is not ValidationReason.ACCEPTED,
                    "flags": (
                        ["SEQUENCE_GAP"]
                        if validation.reason_code is ValidationReason.SEQUENCE_GAP
                        else []
                    ),
                    "result": validation.to_dict(),
                },
                "classified_attack": validation.classification,
            }
        )
        if self.active_scenario is not None:
            data["scenario"] = self.active_scenario
        return data

    def _threat(
        self,
        packet: dict[str, Any],
        validation: ValidationResult,
        correlation_id: str,
    ) -> ThreatAssessment:
        pattern = self.analyzer.analyze(packet)
        attack_name = validation.classification or "UNKNOWN"
        try:
            attack_type = AttackType(attack_name)
        except ValueError:
            attack_type = AttackType.UNKNOWN
        return ThreatAssessment(
            correlation_id=correlation_id,
            attack_type=attack_type,
            severity=pattern["severity"],
            pattern=pattern["pattern"],
            evidence=(validation.reason_code.value,),
        )

    def _trust(
        self,
        validation: ValidationResult,
        threat: ThreatAssessment,
        correlation_id: str,
    ) -> TrustUpdate:
        score = self.security.trust_score
        state = self.security.trust_state.value
        return TrustUpdate(
            correlation_id=correlation_id,
            previous_score=score,
            score=score,
            previous_state=state,
            state=state,
            trigger_reason=validation.reason_code.value,
            transitioned=False,
        )

    def _ml(
        self,
        packet: dict[str, Any],
        validation: ValidationResult,
        correlation_id: str,
    ) -> MlAssessment:
        if (
            not self._ml_trained
            and validation.reason_code is ValidationReason.ACCEPTED
            and validation.classification in (None, "UNKNOWN")
        ):
            self._training_packets.append(packet)
            if len(self._training_packets) >= settings.ml.training_window:
                self.ml_detector.train(self._training_packets)
                self._ml_trained = True
        result = self.ml_detector.predict(packet)
        return MlAssessment(
            correlation_id=correlation_id,
            status=str(result["ml_status"]),
            anomaly=bool(result["ml_anomaly"]),
            risk_score=result["ml_score"],
        )

    def _publish(
        self,
        correlation_id: str,
        event_type: str,
        severity: str,
        trust: float,
        state: str,
        message: str,
    ) -> None:
        self.event_bus.publish(
            SecurityEvent(
                correlation_id=correlation_id,
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                severity=severity,
                trust=trust,
                state=state,
                message=message,
            )
        )
