"""Phase 3 orchestration, state-store, and bounded event-bus tests."""

from datetime import datetime, timezone
from queue import Empty

import pytest

from simulation.pipeline import EventBus, SystemState
from simulation.pipeline import SecurityPipeline
from simulation.security.telemetry_middleware import SecurityMiddleware
from simulation.security.telemetry_schema import TelemetryPacket


def test_system_state_snapshots_are_versioned_and_atomic() -> None:
    state = SystemState()
    initial = state.snapshot()
    updated = state.update(
        correlation_id="session:1",
        trust_score=0.4,
        trust_state="PREPARE",
        response="MONITOR",
        hem_phase="PREPARE",
        hem_status="PARTIAL",
        ml_score=0.2,
    )

    assert updated.version == initial.version + 1
    assert state.snapshot() == updated
    with pytest.raises(Exception):
        updated.trust_score = 0.1


def test_event_bus_drops_oldest_for_slow_subscriber() -> None:
    bus = EventBus(queue_capacity=1)
    subscriber = bus.subscribe()
    first = object()
    second = object()

    # SecurityEvent values are only checked by the queue; use a tiny fake
    # because this test targets bounded delivery rather than model validation.
    bus.publish(first)  # type: ignore[arg-type]
    bus.publish(second)  # type: ignore[arg-type]

    assert subscriber.get_nowait() is second
    with pytest.raises(Empty):
        subscriber.get_nowait()


def test_event_bus_sink_is_bounded_and_asynchronous() -> None:
    import time

    received: list[object] = []
    bus = EventBus(queue_capacity=2)
    bus.subscribe_sink(received.append)  # type: ignore[arg-type]
    first = object()
    bus.publish(first)  # type: ignore[arg-type]

    for _ in range(20):
        if received:
            break
        time.sleep(0.01)
    bus.close()

    assert received == [first]


def _packet(sequence: int = 1, speed: float = 10.0) -> dict[str, object]:
    return {
        "drone_id": "pipeline-test",
        "sequence": sequence,
        "timestamp": datetime.now(timezone.utc).timestamp(),
        "lat": 12.0,
        "lon": 77.0,
        "altitude": 100.0,
        "speed": speed,
        "battery": 90.0,
        "heading": 0.0,
    }


class _TraceAnalyzer:
    def __init__(self, trace: list[str], fail: bool = False) -> None:
        self.trace = trace
        self.fail = fail

    def analyze(self, packet: dict[str, object]) -> dict[str, str]:
        self.trace.append("classify")
        if self.fail:
            raise RuntimeError("injected analyzer failure")
        return {"pattern": "NORMAL", "severity": "LOW"}


class _TraceMl:
    def __init__(self, trace: list[str]) -> None:
        self.trace = trace

    def predict(self, packet: dict[str, object]) -> dict[str, object]:
        self.trace.append("ml")
        return {"ml_status": "model_not_ready", "ml_anomaly": False, "ml_score": None}


class _TraceResponse:
    def __init__(self, trace: list[str]) -> None:
        self.trace = trace

    def decide(self, packet: dict[str, object]) -> str:
        self.trace.append("respond")
        return "NORMAL_OPERATION"


class _TraceEnforcer:
    def __init__(self, trace: list[str]) -> None:
        self.trace = trace

    def enforce(self, packet: dict[str, object]) -> dict[str, object]:
        self.trace.append("enforce")
        return {"enforced": "NONE"}


class _TraceHem:
    phase = "STANDBY"

    def __init__(self, trace: list[str]) -> None:
        self.trace = trace

    def on_packet(
        self,
        packet: dict[str, object],
        now: float | None = None,
    ) -> dict[str, object]:
        self.trace.append("hem")
        return {"hem_phase": "STANDBY", "moved": 0, "zeroized": False}


def test_pipeline_executes_stages_and_publishes_correlated_result() -> None:
    trace: list[str] = []
    bus = EventBus()
    events = bus.subscribe()
    pipeline = SecurityPipeline(
        security=SecurityMiddleware(),
        analyzer=_TraceAnalyzer(trace),
        ml_detector=_TraceMl(trace),
        response_engine=_TraceResponse(trace),
        enforcer=_TraceEnforcer(trace),
        hem=_TraceHem(trace),
        session_id="test-session",
        event_bus=bus,
    )

    result = pipeline.process(TelemetryPacket.model_validate(_packet()))

    assert result.correlation_id == "test-session:1"
    assert trace == ["classify", "ml", "respond", "enforce", "hem"]
    assert events.get_nowait().correlation_id == result.correlation_id
    assert pipeline.state.snapshot().correlation_id == result.correlation_id


def test_pipeline_stage_failure_fails_closed_and_keeps_running() -> None:
    pipeline = SecurityPipeline(
        security=SecurityMiddleware(),
        analyzer=_TraceAnalyzer([], fail=True),
        ml_detector=_TraceMl([]),
        response_engine=_TraceResponse([]),
        enforcer=_TraceEnforcer([]),
        hem=_TraceHem([]),
        session_id="fault-session",
    )

    result = pipeline.process(TelemetryPacket.model_validate(_packet()))

    assert result.stage_error is not None
    assert result.state.trust_state == "PROTECT"
    assert result.state.response == "ISOLATE_DRONE"


@pytest.mark.parametrize(
    "stage",
    ["classify", "trust", "ml", "respond", "enforce", "hem", "state"],
)
def test_each_stage_failure_emits_stage_error_and_keeps_pipeline_alive(
    stage: str,
) -> None:
    pipeline = SecurityPipeline(
        security=SecurityMiddleware(),
        analyzer=_TraceAnalyzer([]),
        ml_detector=_TraceMl([]),
        response_engine=_TraceResponse([]),
        enforcer=_TraceEnforcer([]),
        hem=_TraceHem([]),
        session_id=f"fault-{stage}",
    )
    if stage == "classify":
        pipeline._threat = lambda *_args: (_ for _ in ()).throw(  # type: ignore[method-assign]
            RuntimeError("classify")
        )
    elif stage == "trust":
        pipeline._trust = lambda *_args: (_ for _ in ()).throw(  # type: ignore[method-assign]
            RuntimeError("trust")
        )
    elif stage == "ml":
        pipeline._ml = lambda *_args: (_ for _ in ()).throw(  # type: ignore[method-assign]
            RuntimeError("ml")
        )
    elif stage == "respond":
        pipeline.response_engine.decide = lambda *_args: (_ for _ in ()).throw(  # type: ignore[method-assign]
            RuntimeError("respond")
        )
    elif stage == "enforce":
        pipeline.enforcer.enforce = lambda *_args: (_ for _ in ()).throw(  # type: ignore[method-assign]
            RuntimeError("enforce")
        )
    elif stage == "hem":
        pipeline.hem.on_packet = lambda *_args, **_kwargs: (_ for _ in ()).throw(  # type: ignore[method-assign]
            RuntimeError("hem")
        )
    else:
        pipeline.state.update = lambda **_kwargs: (_ for _ in ()).throw(  # type: ignore[method-assign]
            RuntimeError("state")
        )

    result = pipeline.process(TelemetryPacket.model_validate(_packet()))

    assert result.stage_error is not None
    assert result.stage_error.stage == stage
    assert result.state.trust_state == "PROTECT"

    follow_up = pipeline.process(
        TelemetryPacket.model_validate(_packet(sequence=2, speed=0.0))
    )
    assert follow_up.stage_error is not None
