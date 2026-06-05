"""Helpers for combining standalone tool reports."""

from __future__ import annotations

import json
from pathlib import Path

from audit_hunter_common.reporting import build_report_envelope, write_tool_report


class CombineError(RuntimeError):
    """Raised when a combined report cannot be produced."""


def combine_tool_reports(*, run_id: str, reports_dir: Path) -> Path:
    """Combine per-tool JSON reports for one run."""
    run_dir = reports_dir / run_id
    report_paths = sorted(
        path for path in run_dir.glob("*.report.json")
        if path.name != "audit-hunter.report.json"
    )
    if not report_paths:
        raise CombineError(f"no tool reports found under {run_dir}")

    payload = build_report_envelope(
        run_id=run_id,
        report_paths=report_paths,
        target=_first_target(report_paths),
    )
    return write_tool_report(
        payload,
        reports_dir=reports_dir,
        run_id=run_id,
        tool_name="audit-hunter",
    )


def _first_target(report_paths: list[Path]) -> dict:
    for path in report_paths:
        payload = json.loads(path.read_text())
        target = payload.get("target")
        if isinstance(target, dict):
            return target
    return {}
