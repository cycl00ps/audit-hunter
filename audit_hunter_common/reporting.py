"""Shared report-file helpers and combined report envelope."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


def tool_report_path(reports_dir: Path, run_id: str, tool_name: str) -> Path:
    return reports_dir / run_id / f"{tool_name}.report.json"


def write_tool_report(
    payload: dict[str, Any],
    *,
    reports_dir: Path,
    run_id: str,
    tool_name: str,
) -> Path:
    out_path = tool_report_path(reports_dir, run_id, tool_name)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return out_path


def build_report_envelope(
    *,
    run_id: str,
    report_paths: list[Path],
    target: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reports = []
    total_findings = 0
    by_tool: dict[str, int] = {}

    for path in report_paths:
        payload = json.loads(path.read_text())
        tool = str(payload.get("tool") or path.name.replace(".report.json", ""))
        summary = payload.get("summary") or {}
        count = int(summary.get("total", 0))
        total_findings += count
        by_tool[tool] = by_tool.get(tool, 0) + count
        reports.append({
            "tool": tool,
            "path": str(path),
            "summary": summary,
        })

    return {
        "schema_version": "1.0",
        "tool": "audit-hunter",
        "run_id": run_id,
        "generated_at": time.time(),
        "target": target or {},
        "summary": {
            "total": total_findings,
            "by_tool": by_tool,
        },
        "reports": reports,
    }
