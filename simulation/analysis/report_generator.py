"""Compatibility exports for the structured report implementation."""

from simulation.reporting.report_generator import (
    ReportArtifacts,
    ReportGenerator,
    generate_report,
)

__all__ = ["ReportArtifacts", "ReportGenerator", "generate_report"]
