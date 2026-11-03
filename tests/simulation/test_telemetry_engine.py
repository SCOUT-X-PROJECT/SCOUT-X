import random

from simulation.telemetry.telemetry_engine import TelemetryEngine


def test_telemetry_engine_emits_bounded_monotonic_samples(
    monkeypatch,
) -> None:
    now = [1_800_000_000.0]
    monkeypatch.setattr(
        "simulation.telemetry.telemetry_engine.time.time",
        lambda: now[0],
    )
    random.seed(2026)
    engine = TelemetryEngine()
    initial_battery = engine.battery
    initial_latitude = engine.lat

    packets = []
    for _ in range(10):
        now[0] += 1.0
        packets.append(engine.update())

    assert [packet["sequence"] for packet in packets] == list(range(1, 11))
    assert all(packet["timestamp"] > 0 for packet in packets)
    assert all(-90 <= packet["lat"] <= 90 for packet in packets)
    assert all(-180 <= packet["lon"] <= 180 for packet in packets)
    assert all(packet["speed"] >= 0 for packet in packets)
    assert all(packet["altitude"] >= 0 for packet in packets)
    assert all(
        left["battery"] >= right["battery"]
        for left, right in zip([{"battery": initial_battery}, *packets], packets)
    )
    assert packets[-1]["battery"] < initial_battery
    assert packets[-1]["lat"] != initial_latitude
    assert all(0 <= packet["heading"] < 360 for packet in packets)
