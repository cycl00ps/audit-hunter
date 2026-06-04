"""Master CLI for combining independently-produced tool reports."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console

from audit_hunter_common.paths import project_paths
from audit_hunter_common.reporting import build_report_envelope, write_tool_report


console = Console()


@click.group()
def main() -> None:
    """audit-hunter — master flow scaffold for individual audit tools."""


@main.command("tools")
def tools() -> None:
    """List expected standalone tool entrypoints."""
    for name in ("vuln-hunter", "secret-hunter"):
        click.echo(name)


@main.command("combine")
@click.option("--run-id", required=True, help="Run identifier to combine.")
@click.option("--reports-dir", type=click.Path(file_okay=False), default=None,
              help="Directory containing per-tool reports.")
def combine(run_id: str, reports_dir: str | None) -> None:
    """Combine per-tool JSON reports into audit-hunter.report.json."""
    paths = project_paths(reports_dir=reports_dir)
    run_dir = paths.reports_dir / run_id
    report_paths = sorted(
        path for path in run_dir.glob("*.report.json")
        if path.name != "audit-hunter.report.json"
    )
    if not report_paths:
        console.print(f"[red]no tool reports found under {run_dir}[/red]")
        sys.exit(1)

    target = _first_target(report_paths)
    payload = build_report_envelope(
        run_id=run_id,
        report_paths=report_paths,
        target=target,
    )
    out_path = write_tool_report(
        payload,
        reports_dir=paths.reports_dir,
        run_id=run_id,
        tool_name="audit-hunter",
    )
    console.print(f"[green]done[/green] run_id={run_id} report={out_path}")


def _first_target(report_paths: list[Path]) -> dict:
    for path in report_paths:
        payload = json.loads(path.read_text())
        target = payload.get("target")
        if isinstance(target, dict):
            return target
    return {}


if __name__ == "__main__":
    main()
