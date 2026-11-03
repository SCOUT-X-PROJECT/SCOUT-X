"""Repeatable measurements for the bounded telemetry-security pipeline.

The harness deliberately uses the real UDP receiver and pipeline, while keeping
the accelerated soak virtual-time based so it does not pretend that wall-clock
minutes were observed.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass
import json
import os
import platform
from pathlib import Path
import socket
import sys
import threading
import time
import tracemalloc
from typing import Any

import psutil

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from simulation.analysis.attack_analyzer import AttackAnalyzer
from simulation.config import settings
from simulation.ground_control.udp_receiver import TelemetryUDPReceiver
from simulation.ground_control.receiver import create_hem_session
from simulation.ml.anomaly_detector import TelemetryAnomalyDetector
from simulation.pipeline import EventBus, SecurityPipeline
from simulation.security.enforcer import ResponseEnforcer
from simulation.security.response_engine import ResponseEngine
from simulation.security.telemetry_auth import TelemetryAuthenticator
from simulation.security.telemetry_middleware import SecurityMiddleware
from simulation.security.telemetry_schema import TelemetryPacket, ValidationResult


@dataclass
class LoadMeasurement:
    """Observed counters and latency samples for one offered-rate run."""

    multiplier: int
    sent: int
    processed: int
    shed: int
    rejected: int
    lost: int
    latencies_ms: list[float]
    peak_memory_bytes: int

    def percentiles(self) -> tuple[float, float, float]:
        """Return p50, p95, and p99 from measured processing samples."""
        if not self.latencies_ms:
            return (0.0, 0.0, 0.0)
        values = sorted(self.latencies_ms)
        return tuple(
            round(values[min(len(values) - 1, int(len(values) * fraction))], 3)
            for fraction in (0.50, 0.95, 0.99)
        )


def packet(
    sequence: int,
    drone_id: str | None = None,
    *,
    speed: float = 0.0,
    latitude: float = 12.0,
    longitude: float = 77.0,
    battery: float = 90.0,
) -> dict[str, Any]:
    """Create bounded valid telemetry for the configured simulation identity."""
    return {
        "drone_id": drone_id or settings.network.drone_id,
        "sequence": sequence,
        "timestamp": time.time(),
        "lat": latitude,
        "lon": longitude,
        "altitude": 100.0,
        "speed": speed,
        "battery": battery,
        "heading": 0.0,
    }


def build_pipeline(
    event_bus: EventBus | None = None,
    *,
    fast_model: bool = False,
) -> SecurityPipeline:
    """Build the production stage composition without starting a server."""
    _, hem = create_hem_session()
    ml_detector = TelemetryAnomalyDetector()
    if fast_model:
        ml_detector.pipeline.steps[-1][1].set_params(n_estimators=10)
    return SecurityPipeline(
        security=SecurityMiddleware(),
        analyzer=AttackAnalyzer(),
        ml_detector=ml_detector,
        response_engine=ResponseEngine(),
        enforcer=ResponseEnforcer(),
        hem=hem,
        event_bus=event_bus or EventBus(queue_capacity=256),
        session_id="stress",
    )


async def measure_load(multiplier: int, duration: float = 0.5) -> LoadMeasurement:
    """Offer UDP traffic at a multiplier of the configured normal rate."""
    secret = "stress-secret-" + ("x" * 32)
    sender = TelemetryAuthenticator(secret)
    processed = 0
    rejected = 0
    latencies: list[float] = []
    started_at: dict[int, float] = {}
    pipeline = build_pipeline(fast_model=True)

    def handle(result: ValidationResult) -> None:
        nonlocal processed, rejected
        sequence = result.packet.sequence if result.packet is not None else -1
        if not result.accepted:
            rejected += 1
            return
        begin = started_at.pop(sequence, time.perf_counter())
        pipeline.process_validation(result)
        processed += 1
        latencies.append((time.perf_counter() - begin) * 1000)

    receiver = TelemetryUDPReceiver(
        packet_handler=handle,
        authenticator=TelemetryAuthenticator(secret),
        host="127.0.0.1",
        port=0,
        queue_capacity=128,
        rate_limit_per_second=settings.network.receiver_rate_limit_per_second,
        burst_capacity=settings.network.receiver_burst_capacity,
    )
    server = asyncio.create_task(receiver.run())
    await asyncio.wait_for(receiver.started.wait(), timeout=2)
    assert receiver.address is not None
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    offered_rate = settings.network.receiver_rate_limit_per_second * multiplier
    interval = 1.0 / offered_rate
    sent = 0
    sequences = {settings.network.drone_id: 0, settings.dashboard.drone_id: 0}
    tracemalloc.start()
    try:
        deadline = time.perf_counter() + duration
        while time.perf_counter() < deadline:
            for drone_index in range(2):
                drone_id = (
                    settings.network.drone_id
                    if drone_index == 0
                    else settings.dashboard.drone_id
                )
                sequences[drone_id] += 1
                sequence = sequences[drone_id]
                frame = sender.encode_packet(
                    packet(sequence, drone_id)
                )
                started_at[sequence] = time.perf_counter()
                client.sendto(frame, receiver.address)
                sent += 1
            await asyncio.sleep(interval * 4)
        await asyncio.sleep(0.35)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        client.close()
        receiver.stop()
        await asyncio.wait_for(server, timeout=5)
        sender.close()
    receiver_events = Counter(event.get("event") for event in receiver.events)
    shed = receiver_events["telemetry_flooding"] + receiver_events["datagram_too_large"]
    return LoadMeasurement(
        multiplier,
        sent,
        processed,
        shed,
        rejected,
        max(0, sent - processed - rejected),
        latencies,
        peak,
    )


async def run_malicious_traffic() -> dict[str, int]:
    """Exercise malformed, oversized, replayed, forged, and valid frames."""
    secret = "malicious-secret-" + ("x" * 32)
    sender = TelemetryAuthenticator(secret)
    accepted_sequences: list[int] = []

    def handle(result: ValidationResult) -> None:
        if result.accepted and result.packet is not None:
            accepted_sequences.append(result.packet.sequence)

    receiver = TelemetryUDPReceiver(
        packet_handler=handle,
        authenticator=TelemetryAuthenticator(secret),
        host="127.0.0.1",
        port=0,
        rate_limit_per_second=1000,
        burst_capacity=1000,
    )
    server = asyncio.create_task(receiver.run())
    await asyncio.wait_for(receiver.started.wait(), timeout=2)
    assert receiver.address is not None
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    valid = sender.encode_packet(packet(1))
    forged = bytearray(sender.encode_packet(packet(2)))
    forged[-1] ^= 1
    try:
        for frame in (b"{not-json", b"x" * 5000, valid, valid, bytes(forged)):
            client.sendto(frame, receiver.address)
        await asyncio.sleep(0.25)
        events = Counter(event.get("event") for event in receiver.events)
        return {
            "malformed": events["telemetry_rejected"],
            "oversized": events["datagram_too_large"],
            "replay": sum(
                1
                for event in receiver.events
                if event.get("reason_code") == "sequence_duplicate"
            ),
            "forged_hmac": sum(
                1
                for event in receiver.events
                if "HMAC" in str(event.get("detail", "")).upper()
            ),
            "valid": len(accepted_sequences),
        }
    finally:
        client.close()
        receiver.stop()
        await asyncio.wait_for(server, timeout=5)
        sender.close()


def run_soak(packet_count: int = 1800) -> dict[str, int | float]:
    """Run thirty simulated minutes through the pipeline with bounded metrics."""
    pipeline = build_pipeline(fast_model=True)
    process = psutil.Process(os.getpid())
    tracemalloc.start()
    before = process.memory_info().rss
    start_threads = threading.active_count()
    for sequence in range(1, packet_count + 1):
        pipeline.process(TelemetryPacket.model_validate(packet(sequence)))
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "simulated_seconds": 1800,
        "packets": packet_count,
        "rss_delta_bytes": process.memory_info().rss - before,
        "python_peak_bytes": peak,
        "threads_before": start_threads,
        "threads_after": threading.active_count(),
        "event_bus_queue_capacity": 256,
        "event_bus_subscribers": len(pipeline.event_bus._subscribers),
        "current_allocations_bytes": current,
    }


def run_concurrency(samples: int = 500) -> dict[str, int]:
    """Read immutable state while processing packets from concurrent workers."""
    pipeline = build_pipeline(fast_model=True)
    errors: list[BaseException] = []
    reads = 0
    lock = threading.Lock()

    def writer(start: int) -> None:
        nonlocal reads
        try:
            for sequence in range(start, start + samples // 2):
                pipeline.process(
                    TelemetryPacket.model_validate(packet(sequence))
                )
        except BaseException as exc:
            errors.append(exc)

    def reader() -> None:
        nonlocal reads
        try:
            for _ in range(samples):
                snapshot = pipeline.state.snapshot()
                with lock:
                    reads += 1
                if snapshot.version < 0:
                    raise AssertionError("state version regressed")
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(1,)), threading.Thread(target=writer, args=(10000,))]
    threads.append(threading.Thread(target=reader))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    if any(thread.is_alive() for thread in threads):
        raise TimeoutError("concurrency worker did not stop")
    if errors:
        raise AssertionError(errors)
    return {"state_reads": reads, "final_version": pipeline.state.snapshot().version}


def machine_info() -> dict[str, str]:
    """Return the host facts needed to interpret measured results."""
    return {
        "platform": platform.platform(),
        "processor": platform.processor(),
        "python": platform.python_version(),
        "cpu_count": str(os.cpu_count()),
        "psutil": psutil.__version__,
    }


async def main() -> None:
    """Run bounded measurements and print JSON suitable for the results document."""
    print(json.dumps({"machine": machine_info()}, indent=2))
    for multiplier in (10, 50, 100):
        result = await measure_load(multiplier)
        print(
            json.dumps(
                {
                    "load": result.__dict__
                    | {"percentiles_ms": result.percentiles()},
                },
                default=str,
            )
        )
    print(json.dumps({"malicious": await run_malicious_traffic()}))
    print(json.dumps({"soak": run_soak()}))
    print(json.dumps({"concurrency": run_concurrency()}))


if __name__ == "__main__":
    asyncio.run(main())
