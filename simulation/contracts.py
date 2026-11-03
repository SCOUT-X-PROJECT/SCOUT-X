"""Typed contracts for the security pipeline boundaries.

The existing runtime stages still use their legacy entry points in this phase.
These contracts define the stable vocabulary that the orchestrator will adopt
without changing current security decisions.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from simulation.security.telemetry_schema import (
    TelemetryPacket,
    ValidationResult,
)


def coerce_risk_score(value: object) -> float | None:
    """Convert legacy model output to the contract's optional numeric score."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise TypeError("risk score must not be a boolean")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


class AttackType(str, Enum):
    """Canonical threat vocabulary shared by classifier and pipeline contracts."""

    GPS_SPOOFING = "GPS_SPOOFING"
    GPS_JUMP = "GPS_JUMP"
    ALTITUDE_MANIPULATION = "ALTITUDE_MANIPULATION"
    SPEED_ANOMALY = "SPEED_ANOMALY"
    BATTERY_ANOMALY = "BATTERY_ANOMALY"
    REPLAY = "REPLAY"
    TELEMETRY_FLOODING = "TELEMETRY_FLOODING"
    MULTI_VECTOR = "MULTI_VECTOR"
    UNKNOWN = "UNKNOWN"

    @property
    def severity_score(self) -> float:
        """Expose a stable normalized severity for policy and reporting."""
        return {
            AttackType.GPS_SPOOFING: 0.8,
            AttackType.GPS_JUMP: 0.7,
            AttackType.ALTITUDE_MANIPULATION: 0.8,
            AttackType.SPEED_ANOMALY: 0.6,
            AttackType.BATTERY_ANOMALY: 0.5,
            AttackType.REPLAY: 0.9,
            AttackType.TELEMETRY_FLOODING: 0.9,
            AttackType.MULTI_VECTOR: 1.0,
            AttackType.UNKNOWN: 0.0,
        }[self]


class ContractModel(BaseModel):
    """Make boundary values immutable so downstream stages cannot rewrite them."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class ThreatAssessment(ContractModel):
    """Describe deterministic threat evidence independently of response policy."""

    correlation_id: str = Field(min_length=1, max_length=160)
    attack_type: AttackType
    severity: str = Field(min_length=1, max_length=32)
    pattern: str = Field(min_length=1, max_length=64)
    evidence: tuple[str, ...] = ()


class TrustUpdate(ContractModel):
    """Capture the authoritative trust change produced by the trust engine."""

    correlation_id: str = Field(min_length=1, max_length=160)
    previous_score: float = Field(ge=0, le=1)
    score: float = Field(ge=0, le=1)
    previous_state: str = Field(min_length=1, max_length=32)
    state: str = Field(min_length=1, max_length=32)
    trigger_reason: str = Field(min_length=1, max_length=160)
    transitioned: bool = False


class MlAssessment(ContractModel):
    """Carry the secondary model signal without allowing it to become policy."""

    correlation_id: str = Field(min_length=1, max_length=160)
    status: str = Field(min_length=1, max_length=32)
    anomaly: bool = False
    risk_score: float | None = Field(default=None, ge=0, le=1)


class ResponseLevel(str, Enum):
    """Simulation response labels shared by response and enforcement stages."""

    NORMAL_OPERATION = "NORMAL_OPERATION"
    MONITOR = "MONITOR"
    LIMIT_MOVEMENT = "LIMIT_MOVEMENT"
    ISOLATE_DRONE = "ISOLATE_DRONE"
    FORCE_LAND = "FORCE_LAND"


class ResponseDecision(ContractModel):
    """Record the pure response choice and the evidence used to make it."""

    correlation_id: str = Field(min_length=1, max_length=160)
    response: ResponseLevel
    reason: str = Field(min_length=1, max_length=160)
    ml_contributed: bool = False


class EnforcementResult(ContractModel):
    """Report the simulated enforcement outcome, never a real flight command."""

    correlation_id: str = Field(min_length=1, max_length=160)
    action: str = Field(min_length=1, max_length=64)
    succeeded: bool = True
    detail: str = ""


class HemStatus(ContractModel):
    """Expose HEM progress as a snapshot rather than a mutable result dictionary."""

    correlation_id: str = Field(min_length=1, max_length=160)
    phase: str = Field(min_length=1, max_length=32)
    destination: str | None = None
    transfer_status: str | None = None
    moved_bytes: int = Field(default=0, ge=0)
    zeroized: bool = False


class SecurityEvent(ContractModel):
    """Represent one publishable, correlated security event."""

    correlation_id: str = Field(min_length=1, max_length=160)
    timestamp: datetime
    event_type: str = Field(min_length=1, max_length=128)
    severity: str = Field(min_length=1, max_length=32)
    trust: float | None = Field(default=None, ge=0, le=1)
    state: str | None = Field(default=None, max_length=32)
    message: str = ""
    details: dict[str, object] = Field(default_factory=dict)


class StageError(ContractModel):
    """Describe a stage failure without exposing exception or secret details."""

    correlation_id: str = Field(min_length=1, max_length=160)
    stage: str = Field(min_length=1, max_length=64)
    message: str = Field(min_length=1, max_length=256)
    fail_closed: bool = True


@runtime_checkable
class Validator(Protocol):
    """Validate an authenticated packet before it reaches analysis stages."""

    def validate(self, packet: TelemetryPacket) -> ValidationResult:
        """Return structured validation evidence."""


@runtime_checkable
class Classifier(Protocol):
    """Classify a validation result using bounded history."""

    def classify(self, result: ValidationResult) -> ThreatAssessment:
        """Return a typed threat assessment."""


@runtime_checkable
class TrustEngine(Protocol):
    """Apply deterministic trust updates and expose the current state."""

    def update(self, assessment: ThreatAssessment) -> TrustUpdate:
        """Return the new authoritative trust state."""


@runtime_checkable
class AnomalyDetector(Protocol):
    """Produce a secondary ML assessment."""

    def assess(self, packet: TelemetryPacket) -> MlAssessment:
        """Return model readiness and calibrated risk."""


@runtime_checkable
class ResponseEngine(Protocol):
    """Choose a response from typed threat and trust evidence."""

    def decide(
        self,
        threat: ThreatAssessment,
        trust: TrustUpdate,
        ml: MlAssessment,
    ) -> ResponseDecision:
        """Return a policy decision without performing side effects."""


@runtime_checkable
class Enforcer(Protocol):
    """Apply a simulated response decision."""

    def enforce(self, decision: ResponseDecision) -> EnforcementResult:
        """Return the simulated enforcement outcome."""


@runtime_checkable
class DataProtector(Protocol):
    """Protect simulated mission data after enforcement requests it."""

    def protect(
        self,
        packet: TelemetryPacket,
        decision: ResponseDecision,
    ) -> HemStatus:
        """Return the current HEM status."""


@runtime_checkable
class EventSink(Protocol):
    """Consume immutable security events without controlling the pipeline."""

    def publish(self, event: SecurityEvent) -> None:
        """Accept one event for logging, reporting, or dashboard delivery."""
