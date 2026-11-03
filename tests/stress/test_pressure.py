"""Opt-in pressure, malicious-input, fault, and concurrency regression tests."""

from __future__ import annotations

from datetime import datetime, timezone
import threading

import pytest

from simulation.contracts import SecurityEvent
from simulation.pipeline import EventBus
from simulation.security.telemetry_middleware import SecurityMiddleware
from simulation.security.telemetry_schema import TelemetryPacket
from tests.stress.stress_harness import (
    build_pipeline,
    measure_load,
    packet,
    run_concurrency,
    run_malicious_traffic,
    run_soak,
)


pytestmark = [pytest.mark.stress, pytest.mark.timeout(120)]


@pytest.mark.asyncio
async def test_load_rates_are_bounded_and_receiver_processes_traffic() -> None:
    """The receiver must stay live and expose measured shedding under pressure."""
    result = await measure_load(10, duration=0.15)
    assert result.sent > 0
    assert result.processed > 0
    assert result.peak_memory_bytes < 32 * 1024 * 1024


@pytest.mark.asyncio
async def test_malicious_traffic_is_not_accepted_as_valid() -> None:
    """Malformed, oversized, replayed, and forged frames must not become telemetry."""
    result = await run_malicious_traffic()
    assert result["valid"] == 1
    assert result["malformed"] == 1
    assert result["oversized"] == 1
    assert result["replay"] == 1
    assert result["forged_hmac"] == 1


def test_accelerated_soak_has_bounded_state() -> None:
    """Thirty simulated minutes must not create unbounded pipeline state."""
    result = run_soak(120)
    assert result["simulated_seconds"] == 1800
    assert result["event_bus_queue_capacity"] == 256
    assert result["event_bus_subscribers"] <= 256
    assert result["threads_before"] == result["threads_after"]


def test_concurrent_state_reads_are_consistent() -> None:
    """Concurrent readers must observe versioned snapshots without deadlock."""
    result = run_concurrency(40)
    assert result["state_reads"] == 40
    assert result["final_version"] > 0


def test_nan_ml_result_fails_closed() -> None:
    """An invalid ML score must not produce a success-shaped security result."""
    pipeline = build_pipeline()
    pipeline._ml = lambda *_args: (_ for _ in ()).throw(  # type: ignore[method-assign]
        ValueError("NaN score")
    )
    result = pipeline.process(TelemetryPacket.model_validate(packet(1)))
    assert result.stage_error is not None
    assert result.state.trust_state == "PROTECT"


def test_hung_subscriber_cannot_block_pipeline() -> None:
    """A subscriber that never returns must not hold the pipeline stage."""
    pipeline = build_pipeline()
    entered = threading.Event()
    release = threading.Event()

    def hung(_event: object) -> None:
        entered.set()
        release.wait(5)

    pipeline.event_bus.subscribe_sink(hung)  # type: ignore[arg-type]
    result = pipeline.process(TelemetryPacket.model_validate(packet(1)))
    assert result.state.version == 1
    assert entered.wait(1)
    release.set()
    pipeline.event_bus.close()


@pytest.mark.parametrize(
    "stage",
    ["classify", "trust", "ml", "respond", "enforce", "hem"],
)
def test_each_stage_fault_fails_closed_and_recovers(stage: str) -> None:
    """Every injected stage exception must yield PROTECT without crashing later work."""
    pipeline = build_pipeline()
    if stage == "classify":
        pipeline._threat = lambda *_args: (_ for _ in ()).throw(RuntimeError(stage))  # type: ignore[method-assign]
    elif stage == "trust":
        pipeline._trust = lambda *_args: (_ for _ in ()).throw(RuntimeError(stage))  # type: ignore[method-assign]
    elif stage == "ml":
        pipeline._ml = lambda *_args: (_ for _ in ()).throw(RuntimeError(stage))  # type: ignore[method-assign]
    elif stage == "respond":
        pipeline.response_engine.decide = lambda *_args: (_ for _ in ()).throw(RuntimeError(stage))  # type: ignore[method-assign]
    elif stage == "enforce":
        pipeline.enforcer.enforce = lambda *_args: (_ for _ in ()).throw(RuntimeError(stage))  # type: ignore[method-assign]
    else:
        pipeline.hem.on_packet = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError(stage))  # type: ignore[method-assign]

    failed = pipeline.process(TelemetryPacket.model_validate(packet(1)))
    assert failed.stage_error is not None
    assert failed.state.trust_state == "PROTECT"

    recovered = build_pipeline().process(TelemetryPacket.model_validate(packet(1)))
    assert recovered.stage_error is None


def test_log_sink_failure_does_not_allow_pipeline_success_to_crash() -> None:
    """A full/unwritable log sink is isolated from packet protection."""
    bus = EventBus()
    failures: list[str] = []
    bus.subscribe_sink(lambda _event: (_ for _ in ()).throw(OSError("disk full")))
    bus.publish(
        SecurityEvent(
            correlation_id="disk:1",
            timestamp=datetime.now(timezone.utc),
            event_type="TEST",
            severity="CRITICAL",
        )
    )
    import time

    time.sleep(0.05)
    failures.append(str(bus.dropped_events))
    bus.close()
    assert failures == ["1"]


def test_clock_jump_does_not_create_success_from_invalid_time() -> None:
    """Backward timestamps are rejected by the actual telemetry boundary."""
    middleware = SecurityMiddleware()
    first = middleware.validate_telemetry(
        __import__("json").dumps(packet(1)).encode()
    )
    second_data = packet(2)
    second_data["timestamp"] = second_data["timestamp"] - 3600
    second = middleware.validate_telemetry(
        __import__("json").dumps(second_data).encode()
    )
    assert first.accepted
    assert not second.accepted


def test_ten_pipeline_events_change_with_input_and_keep_correlation_ids() -> None:
    """Ten changed packets produce ten distinct correlated pipeline results."""
    pipeline = build_pipeline()
    results = [
        pipeline.process(
            TelemetryPacket.model_validate(
                packet(index, battery=90.0 - index)
            )
        )
        for index in range(1, 11)
    ]
    assert len({result.correlation_id for result in results}) == 10
    assert [result.state.correlation_id for result in results] == [
        result.correlation_id for result in results
    ]
    assert len({result.legacy_packet["battery"] for result in results}) == 10
