"""Reusable deterministic telemetry attack scenarios and evaluation runner."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import math
from pathlib import Path
import random
import tempfile
import time
from typing import Sequence

from simulation.config import PROJECT_ROOT, settings
from simulation.hem import DataVault, HEMController, PeerRegistry, SimTransport
from simulation.hem.vault import CRITICAL, ROUTINE, SENSITIVE, PRIORITY_NAMES
from simulation.security.response_engine import ResponseEngine
from simulation.security.enforcer import ResponseEnforcer
from simulation.analysis.attack_analyzer import AttackAnalyzer
from simulation.security.telemetry_middleware import SecurityMiddleware
from simulation.security.telemetry_schema import (
    ValidationReason,
)
from simulation.security.trust_engine import TrustState
from simulation.ml.anomaly_detector import TelemetryAnomalyDetector
from simulation.pipeline import SecurityPipeline


@dataclass(frozen=True)
class AttackInjection:
    """Describe one active injection window and its per-packet strength."""

    type: str
    start_seconds: float
    stop_seconds: float
    intensity: float = 1.0
    ground_truth_attack: bool = True

    def active_at(self, elapsed_seconds: float) -> bool:
        """Use half-open windows so packet labels are unambiguous at boundaries."""
        return self.start_seconds <= elapsed_seconds < self.stop_seconds


@dataclass(frozen=True)
class ScenarioDefinition:
    """Hold declarative timing, injection, seed, and packet-level ground truth."""

    name: str
    duration_seconds: float
    seed: int
    attacks: tuple[AttackInjection, ...]
    ground_truth_labels: tuple[tuple[str, ...], ...]
    expected_end_state: str
    minimum_detection_rate: float = 0.0
    maximum_false_positive_rate: float = 1.0


@dataclass(frozen=True)
class ScenarioMetrics:
    """Report measurable outcomes without retaining live simulator objects."""

    name: str
    seed: int
    total_packets: int
    attack_packets: int
    detections: int
    false_positives: int
    detection_rate: float
    false_positive_rate: float
    detected_attack_types: tuple[str, ...]
    time_to_detect_seconds: float | None
    time_to_protect_seconds: float | None
    data_protected_before_compromise: dict[str, int]
    state_flap_count: int
    final_state: str
    final_trust: float


_DEFAULT_SEED = 4200
_PRIORITY_CLASS_NAMES = ("CRITICAL", "SENSITIVE", "ROUTINE")


def _packets_in_duration(duration_seconds: float) -> int:
    """Include the initial sample while keeping duration and cadence aligned."""
    interval = settings.network.telemetry_interval_seconds
    return max(1, int(math.floor(duration_seconds / interval)) + 1)


def _ground_truth_for(
    duration_seconds: float,
    attacks: tuple[AttackInjection, ...],
) -> tuple[tuple[str, ...], ...]:
    """Build packet labels once so evaluators and mutations share exact windows."""
    interval = settings.network.telemetry_interval_seconds
    labels: list[tuple[str, ...]] = []
    for packet_index in range(_packets_in_duration(duration_seconds)):
        elapsed = packet_index * interval
        active = [
            attack.type
            for attack in attacks
            if attack.ground_truth_attack and attack.active_at(elapsed)
        ]
        if active and active[0] == "intermittent_attack":
            period_packets = max(2, int(round(4.0 / interval)))
            if packet_index % period_packets != 0:
                active = []
        labels.append(tuple(active))
    return tuple(labels)


def _scenario(
    name: str,
    duration_seconds: float,
    seed: int,
    attacks: tuple[AttackInjection, ...],
    expected_end_state: str,
    *,
    minimum_detection_rate: float = 0.0,
    maximum_false_positive_rate: float = 1.0,
) -> ScenarioDefinition:
    """Keep the built-in scenario catalog declarative and table-driven."""
    return ScenarioDefinition(
        name=name,
        duration_seconds=duration_seconds,
        seed=seed,
        attacks=attacks,
        ground_truth_labels=_ground_truth_for(duration_seconds, attacks),
        expected_end_state=expected_end_state,
        minimum_detection_rate=minimum_detection_rate,
        maximum_false_positive_rate=maximum_false_positive_rate,
    )


SCENARIOS: dict[str, ScenarioDefinition] = {
    "normal": _scenario(
        "normal",
        24.0,
        _DEFAULT_SEED + 1,
        (),
        "STANDBY",
        maximum_false_positive_rate=0.0,
    ),
    "gps_spoofing": _scenario(
        "gps_spoofing",
        28.0,
        _DEFAULT_SEED + 2,
        (AttackInjection("gps_jump", 6.0, 17.0, 1.0),),
        "PROTECT",
        minimum_detection_rate=0.8,
    ),
    "command_injection": _scenario(
        "command_injection",
        25.0,
        _DEFAULT_SEED + 3,
        (AttackInjection("command_injection", 5.0, 15.0, 1.0),),
        "PROTECT",
        minimum_detection_rate=0.8,
    ),
    "critical": _scenario(
        "critical",
        30.0,
        _DEFAULT_SEED + 4,
        (
            AttackInjection("gps_jump", 5.0, 21.0, 1.5),
            AttackInjection("battery_spoofing", 5.0, 21.0, 1.0),
        ),
        "PROTECT",
        minimum_detection_rate=0.8,
    ),
    "slow_gps_drift": _scenario(
        "slow_gps_drift",
        32.0,
        _DEFAULT_SEED + 5,
        (AttackInjection("slow_gps_drift", 6.0, 33.0, 1.0),),
        "STANDBY",
        maximum_false_positive_rate=0.05,
    ),
    "replay_attack": _scenario(
        "replay_attack",
        26.0,
        _DEFAULT_SEED + 6,
        (AttackInjection("replay", 6.0, 18.0, 1.0),),
        "PROTECT",
        minimum_detection_rate=0.8,
    ),
    "telemetry_flooding": _scenario(
        "telemetry_flooding",
        24.0,
        _DEFAULT_SEED + 7,
        (AttackInjection("telemetry_flooding", 6.0, 18.0, 1.0),),
        "PROTECT",
        minimum_detection_rate=0.8,
    ),
    "battery_spoofing": _scenario(
        "battery_spoofing",
        25.0,
        _DEFAULT_SEED + 8,
        (AttackInjection("battery_spoofing", 6.0, 19.0, 1.0),),
        "PROTECT",
        minimum_detection_rate=0.8,
    ),
    "multi_vector": _scenario(
        "multi_vector",
        27.0,
        _DEFAULT_SEED + 9,
        (
            AttackInjection("gps_jump", 6.0, 20.0, 1.2),
            AttackInjection("battery_spoofing", 6.0, 20.0, 1.0),
        ),
        "PROTECT",
        minimum_detection_rate=0.8,
    ),
    "intermittent_attack": _scenario(
        "intermittent_attack",
        44.0,
        _DEFAULT_SEED + 10,
        (AttackInjection("intermittent_attack", 6.0, 39.0, 1.0),),
        "PROTECT",
        minimum_detection_rate=0.5,
    ),
    "false_alarm": _scenario(
        "false_alarm",
        32.0,
        _DEFAULT_SEED + 11,
        (
            AttackInjection(
                "benign_noisy_telemetry",
                5.0,
                29.0,
                1.0,
                ground_truth_attack=False,
            ),
        ),
        "STANDBY",
        maximum_false_positive_rate=0.05,
    ),
}


def _make_vault() -> DataVault:
    """Use a stable inventory so HEM outcomes can be compared between runs."""
    vault = DataVault()
    vault.add("critical-image", CRITICAL, b"simulated critical image payload")
    vault.add("sensitive-route", SENSITIVE, b"simulated sensitive route payload")
    vault.add("routine-weather", ROUTINE, b"simulated routine weather payload")
    return vault


def _baseline_packet(
    sequence: int,
    timestamp: float,
    base_latitude: float,
    base_longitude: float,
) -> dict[str, int | float | str]:
    """Create smooth, physically consistent nominal telemetry for each sample."""
    interval = settings.network.telemetry_interval_seconds
    speed = min(8.0, settings.validation.max_speed)
    northward_distance = (sequence - 1) * speed * interval
    latitude = base_latitude + math.degrees(
        northward_distance / settings.validation.earth_radius_meters
    )
    battery = max(
        settings.validation.battery_minimum,
        85.0 - (sequence - 1) * settings.validation.battery_drain_minimum,
    )
    return {
        "drone_id": settings.network.drone_id,
        "sequence": sequence,
        "timestamp": timestamp,
        "lat": latitude,
        "lon": base_longitude,
        "altitude": 30.0,
        "speed": speed,
        "battery": battery,
        "heading": 0.0,
    }


def _apply_injections(
    packet: dict[str, int | float | str],
    injections: tuple[AttackInjection, ...],
    active_labels: tuple[str, ...],
    packet_index: int,
    previous_packet: dict[str, int | float | str] | None,
    interval: float,
    rng: random.Random,
) -> tuple[dict[str, int | float | str], str | None]:
    """Mutate one telemetry sample and return receiver-level attack evidence."""
    updated = dict(packet)
    active = [
        injection
        for injection in injections
        if (not injection.ground_truth_attack or injection.type in active_labels)
        and injection.active_at(packet_index * interval)
    ]
    if not active:
        return updated, None

    injection = active[0]
    if injection.type == "intermittent_attack":
        period_packets = max(2, int(round(4.0 / interval)))
        if packet_index % period_packets:
            return updated, None
        injection = AttackInjection(
            "gps_jump",
            injection.start_seconds,
            injection.stop_seconds,
            injection.intensity,
        )

    # When two vectors overlap, alternate their payload manifestation. Both
    # remain active and labeled during the same interval; this keeps the strict
    # validator's first-failure reason observable for each vector in turn.
    if len(active) > 1:
        injection = active[packet_index % len(active)]

    if injection.type == "gps_jump":
        if previous_packet is not None:
            northward_jump = (
                settings.validation.gps_jump_limit_m + 10.0 * injection.intensity
            )
            updated["lat"] = float(previous_packet["lat"]) + math.degrees(
                northward_jump / settings.validation.earth_radius_meters
            )
            updated["lon"] = float(previous_packet["lon"])
            updated["speed"] = northward_jump / interval
    elif injection.type == "slow_gps_drift":
        drift_meters = 1.5 * injection.intensity
        start_index = int(round(injection.start_seconds / interval))
        updated["lat"] = float(updated["lat"]) + math.degrees(
            drift_meters
            * max(0, packet_index - start_index)
            / settings.validation.earth_radius_meters
        )
    elif injection.type == "replay":
        if previous_packet is not None:
            updated["sequence"] = int(previous_packet["sequence"])
    elif injection.type == "battery_spoofing":
        if previous_packet is not None:
            updated["battery"] = min(
                settings.validation.battery_maximum,
                float(previous_packet["battery"]) + max(1.0, injection.intensity),
            )
    elif injection.type in {"altitude_manipulation", "command_injection"}:
        updated["altitude"] = settings.validation.max_altitude + injection.intensity
    elif injection.type == "telemetry_flooding":
        return updated, "telemetry_flooding"
    elif injection.type == "benign_noisy_telemetry":
        latitude_noise = rng.uniform(-0.4, 0.4)
        altitude_noise = rng.uniform(-0.5, 0.5)
        updated["lat"] = float(updated["lat"]) + math.degrees(
            latitude_noise / settings.validation.earth_radius_meters
        )
        updated["altitude"] = float(updated["altitude"]) + altitude_noise
    return updated, None


def _state_flaps(states: list[TrustState]) -> int:
    """Count direction reversals, not monotonic trust-state escalations."""
    severity = {
        TrustState.STANDBY: 0,
        TrustState.PREPARE: 1,
        TrustState.EVACUATE: 2,
        TrustState.PROTECT: 3,
    }
    previous_direction = 0
    flaps = 0
    for old_state, new_state in zip(states, states[1:]):
        direction = severity[new_state] - severity[old_state]
        if direction == 0:
            continue
        if previous_direction and direction != previous_direction:
            flaps += 1
        previous_direction = direction
    return flaps


def run_scenario(
    scenario: ScenarioDefinition,
    *,
    seed: int | None = None,
    headless: bool = True,
) -> ScenarioMetrics:
    """Run a fresh deterministic policy/HEM stack for one declarative scenario."""
    effective_seed = scenario.seed if seed is None else seed
    rng = random.Random(effective_seed)
    interval = settings.network.telemetry_interval_seconds
    packet_count = _packets_in_duration(scenario.duration_seconds)
    ground_truth = (
        scenario.ground_truth_labels
        if len(scenario.ground_truth_labels) == packet_count
        else _ground_truth_for(scenario.duration_seconds, scenario.attacks)
    )
    virtual_clock = [0.0]
    middleware = SecurityMiddleware(clock=lambda: virtual_clock[0])
    response_engine = ResponseEngine()
    vault = _make_vault()
    seed_secret = hashlib.sha256(
        f"SCOUT-X scenario HEM seed {effective_seed}".encode("utf-8")
    ).digest()
    with tempfile.TemporaryDirectory(prefix="scoutx-scenario-") as log_directory:
        hem = HEMController(
            vault,
            PeerRegistry(),
            SimTransport(seed=effective_seed),
            base_secret=seed_secret,
            log_path=Path(log_directory) / "hem.jsonl",
        )
        base_time = time.time()
        pipeline = SecurityPipeline(
            security=middleware,
            analyzer=AttackAnalyzer(),
            ml_detector=TelemetryAnomalyDetector(),
            response_engine=response_engine,
            enforcer=ResponseEnforcer(),
            hem=hem,
            session_id=f"scenario-{effective_seed}",
            clock=lambda: base_time + virtual_clock[0],
        )
        base_latitude = settings.dashboard.aircraft_center_latitude
        base_longitude = settings.dashboard.aircraft_center_longitude
        previous_accepted: dict[str, int | float | str] | None = None
        detections: list[bool] = []
        detected_attack_types: set[str] = set()
        truth_values: list[bool] = []
        states: list[TrustState] = []
        protected_before = {name: 0 for name in _PRIORITY_CLASS_NAMES}
        first_attack_index: int | None = None
        time_to_protect: float | None = None

        for index in range(packet_count):
            elapsed = index * interval
            virtual_clock[0] = elapsed
            expected_labels = ground_truth[index]
            is_attack = bool(expected_labels)
            if is_attack and first_attack_index is None:
                first_attack_index = index
                for item in vault.items:
                    if item.status in {"SEALED", "TRANSFERRED"}:
                        priority_name = PRIORITY_NAMES.get(item.priority, "ROUTINE")
                        protected_before[priority_name] += item.size

            packet = _baseline_packet(
                index + 1,
                base_time + elapsed,
                base_latitude,
                base_longitude,
            )
            packet, receiver_event = _apply_injections(
                packet,
                scenario.attacks,
                expected_labels,
                index,
                previous_accepted,
                interval,
                rng,
            )
            if receiver_event == "telemetry_flooding":
                validation_result = middleware.report_receiver_event(
                    ValidationReason.TELEMETRY_FLOODING,
                    detail="Scenario generated authenticated receiver flood evidence.",
                )
            else:
                validation_result = middleware.validate_telemetry(packet)

            pipeline_result = pipeline.process_validation(validation_result)
            detected = not validation_result.accepted
            if detected and validation_result.classification is not None:
                detected_attack_types.add(validation_result.classification)
            detections.append(detected)
            truth_values.append(is_attack)
            trust_state = TrustState(pipeline_result.state.trust_state)
            states.append(trust_state)

            safe_packet = (
                validation_result.packet.model_dump()
                if validation_result.accepted and validation_result.packet is not None
                else (previous_accepted or packet)
            )
            if validation_result.accepted and validation_result.packet is not None:
                previous_accepted = validation_result.packet.model_dump()

            trust_score = pipeline_result.state.trust_score
            hem_result = pipeline_result.hem.model_dump() if pipeline_result.hem else {}
            if (
                is_attack
                and time_to_protect is None
                and (
                    trust_state is TrustState.PROTECT
                    or hem_result.get("hem_phase") == TrustState.PROTECT.value
                )
            ):
                time_to_protect = elapsed - (
                    first_attack_index * interval
                    if first_attack_index is not None
                    else elapsed
                )

            if not headless:
                time.sleep(interval)

        if first_attack_index is not None:
            attack_start_time = first_attack_index * interval
            detection_index = next(
                (
                    index
                    for index, (truth, detected) in enumerate(
                        zip(truth_values, detections)
                    )
                    if truth and detected
                ),
                None,
            )
            time_to_detect = (
                detection_index * interval - attack_start_time
                if detection_index is not None
                else None
            )
        else:
            time_to_detect = None

        attack_count = sum(truth_values)
        clean_count = len(truth_values) - attack_count
        detections_count = sum(
            int(truth and detected) for truth, detected in zip(truth_values, detections)
        )
        false_positives = sum(
            int(not truth and detected)
            for truth, detected in zip(truth_values, detections)
        )
        return ScenarioMetrics(
            name=scenario.name,
            seed=effective_seed,
            total_packets=packet_count,
            attack_packets=attack_count,
            detections=detections_count,
            false_positives=false_positives,
            detection_rate=(detections_count / attack_count if attack_count else 0.0),
            false_positive_rate=(false_positives / clean_count if clean_count else 0.0),
            detected_attack_types=tuple(sorted(detected_attack_types)),
            time_to_detect_seconds=time_to_detect,
            time_to_protect_seconds=time_to_protect,
            data_protected_before_compromise=protected_before,
            state_flap_count=_state_flaps(states),
            final_state=middleware.trust_state.value,
            final_trust=middleware.trust_score,
        )


def _seed_for(seed: int, scenario: ScenarioDefinition) -> int:
    """Derive a stable per-scenario seed without Python's randomized hash()."""
    digest = hashlib.sha256(f"{seed}:{scenario.name}".encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big")


def _render_table(results: Sequence[ScenarioMetrics]) -> str:
    """Format stable results for console and the Markdown artifact."""
    header = (
        "| Scenario | Seed | Detect | FPR | TTD | TTP | "
        "Protected before compromise (C/S/R bytes) | Flaps | End state |"
    )
    separator = "|---|---:|---:|---:|---:|---:|---|---:|---|"
    rows = []
    for result in results:
        protected = result.data_protected_before_compromise
        protected_text = "/".join(
            str(protected[name]) for name in _PRIORITY_CLASS_NAMES
        )
        ttd = (
            "n/a"
            if result.time_to_detect_seconds is None
            else f"{result.time_to_detect_seconds:.1f}s"
        )
        ttp = (
            "n/a"
            if result.time_to_protect_seconds is None
            else f"{result.time_to_protect_seconds:.1f}s"
        )
        rows.append(
            f"| {result.name} | {result.seed} | "
            f"{result.detection_rate:.1%} | {result.false_positive_rate:.1%} | "
            f"{ttd} | {ttp} | {protected_text} | "
            f"{result.state_flap_count} | {result.final_state} |"
        )
    return "\n".join((header, separator, *rows))


def run_scenarios(
    scenario_names: Sequence[str] | None = None,
    *,
    seed: int | None = None,
    headless: bool = True,
    write_results: bool = True,
    results_path: str | Path | None = None,
) -> list[ScenarioMetrics]:
    """Execute selected scenarios, print metrics, and optionally save the table."""
    selected_names = list(scenario_names or SCENARIOS)
    unknown = sorted(set(selected_names) - SCENARIOS.keys())
    if unknown:
        raise ValueError(f"Unknown scenario(s): {', '.join(unknown)}")
    results = []
    for name in selected_names:
        scenario = SCENARIOS[name]
        scenario_seed = scenario.seed if seed is None else _seed_for(seed, scenario)
        results.append(
            run_scenario(
                scenario,
                seed=scenario_seed,
                headless=headless,
            )
        )

    table = _render_table(results)
    print(table)
    if write_results:
        output_path = (
            Path(results_path)
            if results_path is not None
            else PROJECT_ROOT / "docs" / "scenario_results.md"
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            "\n".join(
                [
                    "# SCOUT-X Scenario Evaluation",
                    "",
                    f"Generated: {datetime.now(timezone.utc).isoformat()}",
                    "",
                    "Runs use deterministic per-scenario seeds. `Detect` is the share of "
                    "ground-truth attack packets rejected by validation; `FPR` is the share "
                    "of clean packets rejected. TTD and TTP are measured from the first "
                    "ground-truth attack packet. `Protected before compromise` reports bytes "
                    "sealed or transferred before the first labeled attack packet, grouped "
                    "Critical/Sensitive/Routine. HEM receives trust-state signals but only "
                    "validated telemetry coordinates, so rejected coordinates are not trusted.",
                    "",
                    table,
                    "",
                    "This is a deterministic software simulation, not a real flight-control "
                    "or cryptographic-erasure performance claim.",
                    "",
                ]
            ),
            encoding="utf-8",
        )
    return results


def run_demo() -> None:
    """Retain the README entry point while routing the demo through scenarios."""
    run_scenarios(
        ("normal", "gps_spoofing", "command_injection", "critical"),
        headless=False,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Parse reproducibility and CI options for the reusable scenario runner."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario",
        action="append",
        choices=sorted(SCENARIOS),
        help="scenario to run; repeat to select multiple (default: all)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        help="override built-in seeds with reproducible derived scenario seeds",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="run without real-time pacing for CI and automated evaluation",
    )
    parser.add_argument(
        "--results",
        type=Path,
        default=PROJECT_ROOT / "docs" / "scenario_results.md",
        help="Markdown results output path",
    )
    args = parser.parse_args(argv)
    run_scenarios(
        args.scenario,
        seed=args.seed,
        headless=args.headless,
        results_path=args.results,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
