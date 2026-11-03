from pathlib import Path

import pytest

from simulation.demo.run_scenarios import (
    SCENARIOS,
    _packets_in_duration,
    run_scenarios,
)


def test_scenario_catalog_has_packet_level_ground_truth() -> None:
    assert {
        "normal",
        "gps_spoofing",
        "command_injection",
        "critical",
        "slow_gps_drift",
        "replay_attack",
        "telemetry_flooding",
        "battery_spoofing",
        "multi_vector",
        "intermittent_attack",
        "false_alarm",
    } <= SCENARIOS.keys()

    for scenario in SCENARIOS.values():
        assert scenario.duration_seconds > 0
        assert scenario.seed >= 0
        assert len(scenario.ground_truth_labels) == _packets_in_duration(
            scenario.duration_seconds
        )
        assert all(
            attack.start_seconds < attack.stop_seconds and attack.intensity > 0
            for attack in scenario.attacks
        )


def test_all_scenarios_headless_meet_expected_outcomes_and_repeat() -> None:
    first_run = run_scenarios(
        seed=4200,
        headless=True,
        write_results=False,
    )
    second_run = run_scenarios(
        seed=4200,
        headless=True,
        write_results=False,
    )

    assert first_run == second_run
    by_name = {result.name: result for result in first_run}
    for name, scenario in SCENARIOS.items():
        result = by_name[name]
        assert result.final_state == scenario.expected_end_state
        assert result.detection_rate >= scenario.minimum_detection_rate
        assert result.false_positive_rate <= scenario.maximum_false_positive_rate
        assert 0 <= result.final_trust <= 1
        assert result.state_flap_count >= 0
        assert set(result.data_protected_before_compromise) == {
            "CRITICAL",
            "SENSITIVE",
            "ROUTINE",
        }
        assert all(
            amount >= 0 for amount in result.data_protected_before_compromise.values()
        )

    assert by_name["normal"].final_state == "STANDBY"
    assert by_name["false_alarm"].false_positive_rate == 0
    assert by_name["slow_gps_drift"].detection_rate == 0
    assert by_name["telemetry_flooding"].detected_attack_types == (
        "TELEMETRY_FLOODING",
    )
    assert "REPLAY" in by_name["replay_attack"].detected_attack_types
    assert "MULTI_VECTOR" in by_name["multi_vector"].detected_attack_types
    assert by_name["intermittent_attack"].time_to_protect_seconds is not None


def test_cli_runner_writes_markdown_results(tmp_path: Path) -> None:
    output = tmp_path / "scenario-results.md"
    results = run_scenarios(
        ("normal", "false_alarm"),
        seed=123,
        headless=True,
        results_path=output,
    )

    report = output.read_text(encoding="utf-8")
    assert len(results) == 2
    assert "SCOUT-X Scenario Evaluation" in report
    assert "| false_alarm |" in report
    assert "Protected before compromise" in report


def test_unknown_scenario_fails_explicitly() -> None:
    with pytest.raises(ValueError, match="Unknown scenario"):
        run_scenarios(("does_not_exist",), write_results=False)
