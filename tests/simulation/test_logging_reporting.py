from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import time

import pytest
from pydantic import SecretStr, ValidationError

from simulation.config import Settings, settings
from simulation.logging.jsonl import JsonlEventWriter, LogEvent, verify_log
from simulation.reporting.report_generator import ReportGenerator


def test_log_event_requires_utc_and_bounded_trust() -> None:
    event = {
        "timestamp": "2026-11-02T15:00:00+00:00",
        "event_id": "event-1",
        "drone_id": "drone-1",
        "event_type": "TELEMETRY",
        "severity": "LOW",
        "trust": 0.8,
        "state": "STANDBY",
        "details": {},
    }

    assert LogEvent.model_validate(event).trust == 0.8
    with pytest.raises(ValidationError, match="UTC"):
        LogEvent.model_validate(
            {
                **event,
                "timestamp": "2026-11-02T16:00:00+01:00",
            }
        )
    with pytest.raises(ValidationError):
        LogEvent.model_validate({**event, "trust": 1.1})
    with pytest.raises(ValidationError):
        LogEvent.model_validate({**event, "unexpected": True})


def test_log_total_capacity_reserves_integrity_metadata() -> None:
    with pytest.raises(ValidationError, match="integrity anchor"):
        Settings(
            _env_file=None,
            logging={
                "max_file_bytes": 1024,
                "max_total_bytes": 1200,
            },
        )


def test_writer_redacts_and_appends_json_lines(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "events.jsonl"
    writer = JsonlEventWriter(path)
    monkeypatch.setattr(
        settings.network,
        "telemetry_shared_secret",
        SecretStr("private-sentinel"),
    )

    writer.append(
        event_type="TEST",
        severity="INFO",
        details={
            "api_key": "do-not-log",
            "message": "possible copy: private-sentinel",
        },
        timestamp=datetime(2026, 11, 2, tzinfo=timezone.utc),
    )
    writer.append(
        event_type="TEST",
        severity="INFO",
        details={"message": "next"},
        timestamp=datetime(2026, 11, 2, 0, 0, 1, tzinfo=timezone.utc),
    )

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["details"]["api_key"] == "[REDACTED]"
    assert json.loads(lines[0])["details"]["message"] == ("possible copy: [REDACTED]")
    assert verify_log(path).valid


def test_size_rotation_keeps_chain_valid_and_disk_bounded(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    writer = JsonlEventWriter(
        path,
        max_file_bytes=450,
        max_total_bytes=1350,
        backup_count=5,
    )

    for index in range(12):
        writer.append(
            event_type="TEST",
            severity="INFO",
            details={"index": index, "padding": "x" * 24},
        )

    retained = [
        candidate
        for candidate in tmp_path.glob("events.jsonl*")
        if candidate.suffix != ".json"
    ]
    log_files = [
        candidate
        for candidate in [path, *tmp_path.glob("events.jsonl.[0-9]*")]
        if candidate.is_file()
    ]
    assert path.with_name("events.jsonl.1").exists()
    log_usage = sum(candidate.stat().st_size for candidate in log_files)
    anchor_usage = path.with_name("events.jsonl.integrity.json").stat().st_size
    assert log_usage + anchor_usage <= 1350
    assert verify_log(path).valid
    assert verify_log(path).entries < 12
    assert retained


def test_time_rotation_preserves_integrity_chain(tmp_path: Path) -> None:
    path = tmp_path / "timed.jsonl"
    writer = JsonlEventWriter(
        path,
        max_file_bytes=4096,
        max_total_bytes=8192,
        backup_count=2,
        rotate_interval_seconds=0.01,
    )
    writer.append(event_type="TEST", severity="INFO", details={"index": 1})
    time.sleep(0.02)
    writer.append(event_type="TEST", severity="INFO", details={"index": 2})

    assert path.with_name("timed.jsonl.1").exists()
    assert verify_log(path).valid


@pytest.mark.parametrize("tamper", ["edit", "delete", "reorder"])
def test_verifier_detects_tampered_log_entries(
    tmp_path: Path,
    tamper: str,
) -> None:
    path = tmp_path / "tampered.jsonl"
    writer = JsonlEventWriter(path)
    for index in range(3):
        writer.append(
            event_type="TEST",
            severity="INFO",
            details={"index": index},
        )

    lines = path.read_text(encoding="utf-8").splitlines()
    if tamper == "edit":
        entry = json.loads(lines[1])
        entry["details"]["index"] = 99
        lines[1] = json.dumps(entry, separators=(",", ":"), sort_keys=True)
    elif tamper == "delete":
        lines.pop(1)
    else:
        lines[0], lines[1] = lines[1], lines[0]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_log(path)
    assert not result.valid


def test_concurrent_writer_calls_preserve_one_chain(tmp_path: Path) -> None:
    path = tmp_path / "concurrent.jsonl"
    writer = JsonlEventWriter(path)

    def append(index: int) -> None:
        writer.append(
            event_type="CONCURRENT_TEST",
            severity="INFO",
            details={"index": index},
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(append, range(80)))

    result = verify_log(path)
    assert result.valid
    assert result.entries == 80


def test_failed_anchor_commit_rolls_back_the_unanchored_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "rollback.jsonl"
    writer = JsonlEventWriter(path)
    writer.append(event_type="TEST", severity="INFO", details={"index": 1})
    write_anchor = writer._write_anchor
    calls = 0

    def fail_final_commit(anchor: dict[str, str | int]) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise PermissionError("simulated transient file lock")
        write_anchor(anchor)

    monkeypatch.setattr(writer, "_write_anchor", fail_final_commit)
    with pytest.raises(PermissionError, match="simulated transient"):
        writer.append(event_type="TEST", severity="INFO", details={"index": 2})

    result = verify_log(path)
    assert result.valid
    assert result.entries == 1
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1


def test_report_generator_writes_markdown_html_and_trust_graph(tmp_path: Path) -> None:
    log_path = tmp_path / "fixture.jsonl"
    writer = JsonlEventWriter(log_path)
    first = datetime(2026, 11, 2, 15, tzinfo=timezone.utc)
    fixture_events = [
        {
            "pattern": "GPS_SPOOFING",
            "severity": "HIGH",
            "trust_score": 0.7,
            "flagged": False,
            "deterministic_detected": False,
            "ml_anomaly": False,
            "trust_state": "PREPARE",
        },
        {
            "pattern": "GPS_SPOOFING",
            "severity": "HIGH",
            "trust_score": 0.4,
            "flagged": True,
            "deterministic_detected": True,
            "ml_anomaly": True,
            "trust_state": "EVACUATE",
            "hem": {"transfer_state": "DELIVERED", "hem_phase": "EVACUATE"},
        },
        {
            "pattern": "GPS_SPOOFING",
            "severity": "CRITICAL",
            "trust_score": 0.2,
            "flagged": True,
            "deterministic_detected": True,
            "ml_anomaly": True,
            "trust_state": "PROTECT",
        },
    ]
    for index, details in enumerate(fixture_events):
        writer.append(
            event_type="TELEMETRY",
            severity=str(details["severity"]),
            trust=float(details["trust_score"]),
            state=str(details["trust_state"]),
            details=details,
            timestamp=first + timedelta(seconds=index),
        )

    artifacts = ReportGenerator(log_path, tmp_path / "reports").generate()

    assert artifacts.event_count == 3
    assert artifacts.markdown.is_file()
    assert artifacts.html.is_file()
    assert artifacts.trust_graph.is_file()
    markdown = artifacts.markdown.read_text(encoding="utf-8")
    assert "Time to detect: 1.000 s" in markdown
    assert "Time to PROTECT: 2.000 s" in markdown
    assert "GPS_SPOOFING" in markdown
    assert "ML detections" in markdown


def test_report_refuses_an_unverifiable_log(tmp_path: Path) -> None:
    log_path = tmp_path / "edited.jsonl"
    writer = JsonlEventWriter(log_path)
    writer.append(event_type="TELEMETRY", severity="LOW", details={"pattern": "NORMAL"})
    entry = json.loads(log_path.read_text(encoding="utf-8"))
    entry["details"]["pattern"] = "GPS_SPOOFING"
    log_path.write_text(json.dumps(entry) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="unverifiable log"):
        ReportGenerator(log_path, tmp_path / "reports").generate()
