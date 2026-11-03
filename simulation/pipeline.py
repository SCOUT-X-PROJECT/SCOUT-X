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
from simulation.ml.fusion import fuse_assessment
from simulation.security.enforcer import ResponseEnforcer
from simulation.security.response_engine import ResponseEngine
from simulation.security.telemetry_middleware import SecurityMiddleware
from simulation.security.telemetry_schema import (
    TelemetryPacket,
    ValidationReason,
    ValidationResult,
)
from simulation.security.trust_engine import TrustState, TrustTransitionEvent


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

    def emergency_fail_closed(self, correlation_id: str) -> SystemStateSnapshot:
        """Commit a conservative snapshot without relying on a failed stage hook."""
        with self._lock:
            self._snapshot = SystemStateSnapshot(
                version=self._snapshot.version + 1,
                correlation_id=correlation_id,
                trust_score=0.0,
                trust_state="PROTECT",
                response=ResponseLevel.ISOLATE_DRONE.value,
                hem_phase="PROTECT",
                hem_status="stage_error",
                ml_score=None,
                updated_at=datetime.now(timezone.utc),
            )
            return self._snapshot


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
        self._sink_threads: list[threading.Thread] = []
        self._sink_stops: list[threading.Event] = []
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

    def subscribe_sink(self, handler: Callable[[SecurityEvent], None]) -> None:
        """Run a bounded subscriber worker so persistence cannot block producers."""
        subscriber = self.subscribe()
        stop = threading.Event()
        self._sink_stops.append(stop)

        def consume() -> None:
            while not stop.is_set():
                try:
                    event = subscriber.get(timeout=0.1)
                except queue.Empty:
                    continue
                try:
                    handler(event)
                except Exception:
                    self.dropped_events += 1

        worker = threading.Thread(target=consume, daemon=True)
        self._sink_threads.append(worker)
        worker.start()

    def close(self) -> None:
        """Stop subscriber workers during ordered application shutdown."""
        for stop in self._sink_stops:
            stop.set()
        for worker in self._sink_threads:
            worker.join(timeout=1.0)


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
        self._last_packet: dict[str, Any] | None = None
        if self.logger is not None:
            self.event_bus.subscribe_sink(self._persist_event)

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
            return self._process_rejection(validation, correlation_id)

        legacy_packet = self._packet_dict(packet, validation)
        self._last_packet = legacy_packet
        stage = "classify"
        try:
            threat = self._threat(legacy_packet, validation, correlation_id)
            stage = "trust"
            trust = self._trust(validation, threat, correlation_id)
            stage = "ml"
            ml = self._ml(legacy_packet, validation, correlation_id)
            stage = "respond"
            deterministic = self.response_engine.decide(
                {
                    **legacy_packet,
                    "pattern": threat.pattern,
                    "severity": threat.severity,
                }
            )
            response = ResponseDecision(
                correlation_id=correlation_id,
                response=ResponseLevel(deterministic),
                reason="deterministic",
            )
            response = fuse_assessment(response, ml)
            fusion = {
                "response": response.response.value,
                "fusion_reason": response.reason,
                "ml_escalated": response.ml_contributed,
            }
            legacy_packet.update(
                {
                    "deterministic_response": deterministic,
                    "ml_fusion": fusion,
                    "response": response.response.value,
                }
            )
            stage = "enforce"
            enforced = self.enforcer.enforce(legacy_packet)
            enforcement = EnforcementResult(
                correlation_id=correlation_id,
                action=str(enforced["enforced"]),
            )
            legacy_packet.update(enforced)
            stage = "hem"
            hem_raw = self.hem.on_packet(legacy_packet, now=self.clock())
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
            stage = "state"
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
                details={"packet": legacy_packet},
            )
            self._publish(
                correlation_id,
                "HEM_STATUS",
                threat.severity,
                trust.score,
                hem.phase,
                hem.transfer_status or hem.phase,
                details={"hem": hem.model_dump()},
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
            error = StageError(
                correlation_id=correlation_id,
                stage=stage,
                message=f"{type(exc).__name__} in security stage",
            )
            try:
                snapshot = self.state.fail_closed(correlation_id)
            except Exception:
                snapshot = self.state.emergency_fail_closed(correlation_id)
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
        self._last_packet = None

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

    def _process_rejection(
        self,
        validation: ValidationResult,
        correlation_id: str,
    ) -> PipelineResult:
        """Fail closed for rejected input while retaining the last safe coordinates."""
        base = dict(self._last_packet or {})
        base.setdefault("seq", -1)
        base.setdefault("gps", [0.0, 0.0])
        base["trust_score"] = self.security.trust_score
        base["trust_state"] = self.security.trust_state.value
        base["response"] = (
            ResponseLevel.ISOLATE_DRONE.value
            if self.security.trust_state.value == "PROTECT"
            else "MONITOR"
        )
        base["validation"] = {"is_anomalous": True}
        threat = ThreatAssessment(
            correlation_id=correlation_id,
            attack_type=AttackType(validation.classification)
            if validation.classification in {item.value for item in AttackType}
            else AttackType.UNKNOWN,
            severity=validation.severity.value.upper(),
            pattern="REJECTED_TELEMETRY",
            evidence=(validation.reason_code.value,),
        )
        trust = TrustUpdate(
            correlation_id=correlation_id,
            previous_score=self.security.trust_score,
            score=self.security.trust_score,
            previous_state=self.security.trust_state.value,
            state=self.security.trust_state.value,
            trigger_reason=validation.reason_code.value,
        )
        response = ResponseDecision(
            correlation_id=correlation_id,
            response=ResponseLevel(base["response"]),
            reason=validation.reason_code.value,
        )
        enforced = self.enforcer.enforce(base)
        enforcement = EnforcementResult(
            correlation_id=correlation_id,
            action=str(enforced["enforced"]),
        )
        base.update(enforced)
        hem_raw = self.hem.on_packet(base, now=self.clock())
        hem = HemStatus(
            correlation_id=correlation_id,
            phase=str(hem_raw.get("hem_phase", self.hem.phase)),
            destination=hem_raw.get("destination"),
            transfer_status=hem_raw.get("transfer_state"),
            moved_bytes=int(hem_raw.get("moved", 0)),
            zeroized=bool(hem_raw.get("zeroized", False)),
        )
        snapshot = self.state.update(
            correlation_id=correlation_id,
            trust_score=trust.score,
            trust_state=trust.state,
            response=response.response.value,
            hem_phase=hem.phase,
            hem_status=hem.transfer_status,
            ml_score=None,
        )
        self._publish(
            correlation_id,
            "VALIDATION_REJECTED",
            "HIGH",
            trust.score,
            trust.state,
            validation.reason_code.value,
            details={"packet": base, "hem": hem.model_dump()},
        )
        return PipelineResult(
            correlation_id,
            validation,
            threat,
            trust,
            MlAssessment(
                correlation_id=correlation_id,
                status="not_run",
                anomaly=False,
            ),
            response,
            enforcement,
            hem,
            None,
            snapshot,
            base,
        )

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
        *,
        details: dict[str, object] | None = None,
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
                details=details or {},
            )
        )

    def _persist_event(self, event: SecurityEvent) -> None:
        """Persist event-bus records through the existing structured logger."""
        if self.logger is None:
            return
        if event.event_type == "TRUST_TRANSITION":
            details = event.details
            try:
                self.logger.log_trust_transition(
                    TrustTransitionEvent(
                        old_state=TrustState(str(details["old_state"])),
                        new_state=TrustState(str(details["new_state"])),
                        trust=float(details["trust"]),
                        trigger_reason=str(details["trigger_reason"]),
                        timestamp=float(details["timestamp"]),
                    )
                )
            except (KeyError, TypeError, ValueError):
                return
            return
        if event.event_type != "SECURITY_RESULT":
            return
        packet = event.details.get("packet")
        if not isinstance(packet, dict):
            return
        self.logger.log(
            packet,
            {
                "pattern": packet.get("pattern"),
                "severity": event.severity,
            },
            str(packet.get("response") or event.message),
            correlation_id=event.correlation_id,
        )
