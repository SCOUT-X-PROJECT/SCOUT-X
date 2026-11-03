from simulation.analysis.attack_analyzer import AttackAnalyzer


def test_clean_startup_packets_are_not_classified_as_attacks() -> None:
    for window_size in (1, 2):
        analyzer = AttackAnalyzer(window_size=window_size)

        assert analyzer.analyze({"seq": 1, "validation": {}}) == {
            "pattern": "NORMAL",
            "severity": "LOW",
        }


def test_anomaly_ratio_uses_ceiling_at_small_window_boundaries() -> None:
    analyzer = AttackAnalyzer(window_size=2)

    assert (
        analyzer.analyze({"seq": 1, "validation": {"is_anomalous": False}})["pattern"]
        == "NORMAL"
    )
    assert (
        analyzer.analyze({"seq": 2, "validation": {"is_anomalous": True}})["pattern"]
        == "INTERMITTENT_ATTACK"
    )
    assert (
        analyzer.analyze({"seq": 3, "validation": {"is_anomalous": True}})["pattern"]
        == "PERSISTENT_ATTACK"
    )
