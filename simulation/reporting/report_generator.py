"""Generate bounded Markdown and HTML summaries from structured event logs."""

from __future__ import annotations

import html
import json
import math
from collections import Counter
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pydantic import ValidationError

from simulation.config import PROJECT_ROOT, settings
from simulation.logging.jsonl import JsonLogEntry, iter_log_paths, verify_log
from simulation.contracts import SecurityEvent


_CLEAN_PATTERNS = {"", "NORMAL", "CLEAN", "NONE", "UNKNOWN", "TELEMETRY"}


@dataclass(frozen=True)
class ReportArtifacts:
    """Paths written together so callers can surface or distribute the report."""

    markdown: Path
    html: Path
    trust_graph: Path
    event_count: int


def _read_events(log_file: str | Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for path in iter_log_paths(log_file):
        with path.open("r", encoding="utf-8") as file:
            for line in file:
                if not line.strip():
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(raw, dict):
                    continue
                if "details" in raw and "previous_hash" in raw:
                    try:
                        entry = JsonLogEntry.model_validate(raw)
                    except ValidationError:
                        continue
                    flattened = dict(entry.details)
                    flattened.update(
                        {
                            "timestamp": entry.timestamp,
                            "event_id": entry.event_id,
                            "drone_id": entry.drone_id,
                            "event_type": entry.event_type,
                            "severity": flattened.get("severity", entry.severity),
                            "trust_score": (
                                flattened.get("trust_score")
                                if flattened.get("trust_score") is not None
                                else entry.trust
                            ),
                            "state": entry.state,
                        }
                    )
                    events.append(flattened)
                else:
                    events.append(raw)
    return events


def _event_datetime(event: dict[str, Any]) -> datetime | None:
    timestamp = event.get("timestamp")
    if not isinstance(timestamp, str):
        return None
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _event_sort_key(event: dict[str, Any]) -> tuple[bool, datetime]:
    timestamp = _event_datetime(event)
    return (
        timestamp is None,
        timestamp or datetime.max.replace(tzinfo=timezone.utc),
    )


def _pattern(event: dict[str, Any]) -> str:
    return str(event.get("pattern") or "NORMAL").upper()


def _is_attack(event: dict[str, Any]) -> bool:
    return _pattern(event) not in _CLEAN_PATTERNS


def _is_deterministic_detection(event: dict[str, Any]) -> bool:
    validation = event.get("validation")
    validation_anomaly = isinstance(validation, dict) and bool(
        validation.get("is_anomalous")
    )
    return bool(
        event.get("deterministic_detected")
        or event.get("flagged")
        or validation_anomaly
        or event.get("flags")
    )


def _is_protect(event: dict[str, Any]) -> bool:
    hem = event.get("hem")
    hem_phase = hem.get("hem_phase") if isinstance(hem, dict) else None
    return (
        str(event.get("state") or event.get("trust_state") or hem_phase).upper()
        == "PROTECT"
    )


def _duration_metrics(
    events: list[dict[str, Any]],
) -> tuple[float | None, float | None]:
    attack_starts = [event for event in events if _is_attack(event)]
    if not attack_starts:
        return None, None
    first_attack_time = _event_datetime(attack_starts[0])
    if first_attack_time is None:
        return None, None

    detection_time: datetime | None = None
    protect_time: datetime | None = None
    for event in events:
        event_time = _event_datetime(event)
        if event_time is None or event_time < first_attack_time:
            continue
        if detection_time is None and _is_deterministic_detection(event):
            detection_time = event_time
        if protect_time is None and _is_protect(event):
            protect_time = event_time
    detection_seconds = (
        max(0.0, (detection_time - first_attack_time).total_seconds())
        if detection_time is not None
        else None
    )
    protect_seconds = (
        max(0.0, (protect_time - first_attack_time).total_seconds())
        if protect_time is not None
        else None
    )
    return detection_seconds, protect_seconds


def _format_seconds(value: float | None) -> str:
    return "Not observed" if value is None else f"{value:.3f} s"


def _markdown_cell(value: object) -> str:
    return str(value).replace("\r", " ").replace("\n", " ").replace("|", "&#124;")


def _write_trust_graph(events: list[dict[str, Any]], output: Path) -> None:
    points: list[tuple[int, float]] = []
    for index, event in enumerate(events, start=1):
        trust = event.get("trust_score", event.get("trust"))
        try:
            score = float(trust)
        except (TypeError, ValueError):
            continue
        if math.isfinite(score):
            points.append((index, score))

    figure, axis = plt.subplots(figsize=(10, 4))
    if points:
        x_values, y_values = zip(*points)
        axis.plot(
            x_values, y_values, color="#2563eb", linewidth=1.8, marker=".", markersize=4
        )
    else:
        axis.text(0.5, 0.5, "No trust-score samples", ha="center", va="center")
    axis.axhspan(settings.trust.standby_threshold, 1, color="#16a34a", alpha=0.08)
    axis.axhspan(
        settings.trust.evacuate_threshold,
        settings.trust.prepare_threshold,
        color="#f59e0b",
        alpha=0.08,
    )
    axis.axhspan(
        settings.trust.protect_threshold,
        settings.trust.evacuate_threshold,
        color="#f97316",
        alpha=0.08,
    )
    axis.axhspan(0, settings.trust.protect_threshold, color="#dc2626", alpha=0.08)
    axis.axhline(
        settings.trust.standby_threshold,
        color="#16a34a",
        linestyle="--",
        linewidth=1,
        label="STANDBY",
    )
    axis.axhline(
        settings.trust.evacuate_threshold,
        color="#f59e0b",
        linestyle="--",
        linewidth=1,
        label="EVACUATE",
    )
    axis.axhline(
        settings.trust.protect_threshold,
        color="#dc2626",
        linestyle="--",
        linewidth=1,
        label="PROTECT",
    )
    axis.set(title="Trust score by event", xlabel="Event index", ylabel="Trust")
    axis.set_ylim(-0.02, 1.02)
    axis.grid(alpha=0.2)
    axis.legend(loc="lower right")
    figure.tight_layout()
    figure.savefig(output, dpi=140)
    plt.close(figure)


class ReportGenerator:
    """Create reproducible reports without loading unbounded log arrays."""

    def __init__(
        self,
        file: str | Path | None = None,
        output_directory: str | Path | None = None,
    ) -> None:
        """Select log and output paths explicitly for fixture-based validation."""
        log_directory = PROJECT_ROOT / settings.logging.directory
        self.file = (
            Path(file)
            if file is not None
            else log_directory / settings.logging.attack_log
        )
        self.require_integrity = file is not None
        self.log_files = (
            (self.file,)
            if file is not None
            else (
                self.file,
                log_directory / settings.logging.trust_log,
                log_directory / settings.logging.hem_log,
            )
        )
        self.output_directory = (
            Path(output_directory)
            if output_directory is not None
            else PROJECT_ROOT
            / settings.logging.directory
            / settings.logging.report_directory
        )
        self._live_events: deque[SecurityEvent] = deque(
            maxlen=settings.dashboard.event_tail_limit
        )

    def consume_event(self, event: SecurityEvent) -> None:
        """Receive live events without making report generation control the pipeline."""
        self._live_events.append(event)

    def generate(self) -> ReportArtifacts:
        """Write both human-readable formats and the graph as a single report set."""
        events: list[dict[str, Any]] = []
        warnings: list[str] = []
        for log_file in self.log_files:
            retained_paths = iter_log_paths(log_file)
            anchor_path = log_file.with_name(log_file.name + ".integrity.json")
            if retained_paths or anchor_path.exists():
                if not anchor_path.exists():
                    if self.require_integrity:
                        raise ValueError(f"log has no integrity anchor: {log_file}")
                    warnings.append(f"Unanchored legacy log skipped: {log_file.name}")
                    continue
                verification = verify_log(log_file)
                if not verification.valid:
                    raise ValueError(
                        f"refusing to report from unverifiable log "
                        f"{log_file}: {verification.message}"
                    )
                events.extend(_read_events(log_file))
        events.sort(key=_event_sort_key)
        self.output_directory.mkdir(parents=True, exist_ok=True)
        markdown_path = self.output_directory / "report.md"
        html_path = self.output_directory / "report.html"
        graph_path = self.output_directory / "trust_score.png"
        _write_trust_graph(events, graph_path)

        attacks = Counter(_pattern(event) for event in events if _is_attack(event))
        hem_outcomes: Counter[str] = Counter()
        ml_count = 0
        deterministic_count = 0
        both_count = 0
        ml_only = 0
        deterministic_only = 0
        for event in events:
            hem = event.get("hem")
            if isinstance(hem, dict):
                outcome = str(
                    hem.get("transfer_state")
                    or hem.get("hem_phase")
                    or event.get("hem_phase")
                    or "UNREPORTED"
                )
                hem_outcomes[outcome] += 1
            elif event.get("transfer_state") or event.get("event"):
                hem_outcomes[
                    str(event.get("transfer_state") or event.get("event"))
                ] += 1
            elif event.get("hem_phase"):
                hem_outcomes[str(event["hem_phase"])] += 1
            ml_detected = bool(event.get("ml_anomaly"))
            deterministic = _is_deterministic_detection(event)
            ml_count += int(ml_detected)
            deterministic_count += int(deterministic)
            both_count += int(ml_detected and deterministic)
            ml_only += int(ml_detected and not deterministic)
            deterministic_only += int(deterministic and not ml_detected)

        detection_seconds, protect_seconds = _duration_metrics(events)
        timeline_rows = [
            "| {timestamp} | {event_type} | {pattern} | {severity} | {trust} | {state} |".format(
                timestamp=_markdown_cell(event.get("timestamp") or ""),
                event_type=_markdown_cell(event.get("event_type") or "TELEMETRY"),
                pattern=_markdown_cell(_pattern(event)),
                severity=_markdown_cell(event.get("severity") or "INFO"),
                trust=_markdown_cell(event.get("trust_score", event.get("trust", ""))),
                state=_markdown_cell(
                    event.get("state") or event.get("trust_state") or ""
                ),
            )
            for event in events[-settings.dashboard.event_tail_limit :]
        ]
        attack_rows = [
            f"| {_markdown_cell(name)} | {count} |"
            for name, count in sorted(attacks.items())
        ] or ["| None reported | 0 |"]
        hem_rows = [
            f"| {_markdown_cell(name)} | {count} |"
            for name, count in sorted(hem_outcomes.items())
        ] or ["| None reported | 0 |"]

        markdown = "\n".join(
            [
                "# SCOUT-X Security Report",
                "",
                f"Generated: {datetime.now(timezone.utc).isoformat()}",
                "",
                f"Events analyzed: {len(events)}",
                "",
                "## Attack breakdown",
                "",
                "| Attack type | Events |",
                "|---|---:|",
                *attack_rows,
                "",
                "## Trust-score graph",
                "",
                "![Trust score by event](trust_score.png)",
                "",
                "## HEM outcomes",
                "",
                "| Outcome | Events |",
                "|---|---:|",
                *hem_rows,
                "",
                "## ML vs. deterministic detection",
                "",
                "| Measure | Events |",
                "|---|---:|",
                f"| ML detections | {ml_count} |",
                f"| Deterministic detections | {deterministic_count} |",
                f"| Both | {both_count} |",
                f"| ML only | {ml_only} |",
                f"| Deterministic only | {deterministic_only} |",
                "",
                "## Response timing",
                "",
                "Timing is measured from the first event classified as an attack to the first "
                "deterministic detection and first PROTECT state. These are aggregate, "
                "single-flight metrics, not per-attack benchmark claims.",
                "",
                f"- Time to detect: {_format_seconds(detection_seconds)}",
                f"- Time to PROTECT: {_format_seconds(protect_seconds)}",
                "",
                "## Event timeline",
                "",
                "| Timestamp | Event | Pattern | Severity | Trust | State |",
                "|---|---|---|---|---:|---|",
                *(timeline_rows or ["| No events | | | | | |"]),
                "",
                "Tamper-evidence validates retained JSONL entries against their local hash-chain "
                "anchor. It is not tamper-proof against an actor who can rewrite both logs and "
                "anchors.",
                *(
                    [
                        "",
                        "## Input warnings",
                        "",
                        *[f"- {warning}" for warning in warnings],
                    ]
                    if warnings
                    else []
                ),
                "",
            ]
        )
        markdown_path.write_text(markdown, encoding="utf-8")

        timeline_html = (
            "".join(
                "<tr>"
                + "".join(
                    f"<td>{html.escape(str(value), quote=True)}</td>"
                    for value in (
                        event.get("timestamp", ""),
                        event.get("event_type", "TELEMETRY"),
                        _pattern(event),
                        event.get("severity", "INFO"),
                        event.get("trust_score", event.get("trust", "")),
                        event.get("state", event.get("trust_state", "")),
                    )
                )
                + "</tr>"
                for event in events[-settings.dashboard.event_tail_limit :]
            )
            or '<tr><td colspan="6">No events</td></tr>'
        )
        attack_html = (
            "".join(
                f"<tr><td>{html.escape(name, quote=True)}</td><td>{count}</td></tr>"
                for name, count in sorted(attacks.items())
            )
            or "<tr><td>None reported</td><td>0</td></tr>"
        )
        hem_html = (
            "".join(
                f"<tr><td>{html.escape(name, quote=True)}</td><td>{count}</td></tr>"
                for name, count in sorted(hem_outcomes.items())
            )
            or "<tr><td>None reported</td><td>0</td></tr>"
        )
        html_document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>SCOUT-X Security Report</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{{font:16px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#172033}}
table{{border-collapse:collapse;width:100%;margin:1rem 0 2rem}}th,td{{border:1px solid #cbd5e1;padding:.5rem;text-align:left}}
th{{background:#f1f5f9}}img{{max-width:100%;height:auto}}</style></head>
<body><h1>SCOUT-X Security Report</h1>
<p>Generated: {html.escape(datetime.now(timezone.utc).isoformat(), quote=True)}; events analyzed: {len(events)}</p>
<h2>Attack breakdown</h2><table><thead><tr><th>Attack type</th><th>Events</th></tr></thead><tbody>{attack_html}</tbody></table>
<h2>Trust-score graph</h2><img src="trust_score.png" alt="Trust score by event">
<h2>HEM outcomes</h2><table><thead><tr><th>Outcome</th><th>Events</th></tr></thead><tbody>{hem_html}</tbody></table>
<h2>ML vs. deterministic detection</h2>
<p>ML: {ml_count}; deterministic: {deterministic_count}; both: {both_count};
ML only: {ml_only}; deterministic only: {deterministic_only}.</p>
<h2>Response timing</h2><p>Time to detect: {html.escape(_format_seconds(detection_seconds))};
time to PROTECT: {html.escape(_format_seconds(protect_seconds))}.</p>
<p>Timing starts at the first event classified as an attack and ends at the first deterministic
detection or PROTECT state; these are aggregate single-flight metrics.</p>
<h2>Event timeline</h2><table><thead><tr><th>Timestamp</th><th>Event</th><th>Pattern</th>
<th>Severity</th><th>Trust</th><th>State</th></tr></thead><tbody>{timeline_html}</tbody></table>
<p>Hash-chain verification is tamper-evident, not tamper-proof against an actor able to
rewrite both logs and anchors.</p></body></html>"""
        if warnings:
            warning_html = "".join(
                f"<li>{html.escape(warning, quote=True)}</li>" for warning in warnings
            )
            html_document = html_document.replace(
                "</body>",
                f"<h2>Input warnings</h2><ul>{warning_html}</ul></body>",
            )
        html_path.write_text(html_document, encoding="utf-8")
        return ReportArtifacts(markdown_path, html_path, graph_path, len(events))


def generate_report(
    log_file: str | Path | None = None,
    output_directory: str | Path | None = None,
) -> ReportArtifacts:
    """Expose a concise function API for scripts and command-line callers."""
    return ReportGenerator(log_file, output_directory).generate()


if __name__ == "__main__":
    artifacts = generate_report()
    print(f"Markdown report: {artifacts.markdown}")
    print(f"HTML report: {artifacts.html}")
    print(f"Trust graph: {artifacts.trust_graph}")
