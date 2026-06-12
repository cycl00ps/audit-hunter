"""CLI for the standalone secret-hunter tool."""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

import click
from rich.console import Console

from audit_hunter_common.paths import project_paths
from secret_hunter.scanner import scan_repository


console = Console()


@click.group()
def main() -> None:
    """secret-hunter — standalone secret discovery."""


@main.command("scan")
@click.option("--repo", type=click.Path(exists=True, file_okay=False), required=True,
              help="Path to the target source-code repo or directory.")
@click.option("--run-id", default=None, help="Run identifier (default: random).")
@click.option("--bin-dir", type=click.Path(file_okay=False), default=None,
              help="Directory containing user-managed scanner binaries.")
@click.option("--scratch-dir", type=click.Path(file_okay=False), default=None,
              help="Scratch directory for cloned repos and raw artifacts.")
@click.option("--reports-dir", type=click.Path(file_okay=False), default=None,
              help="Directory for final machine-readable reports.")
@click.option("--trufflehog", "trufflehog_path", type=click.Path(dir_okay=False), default=None,
              help="Explicit trufflehog binary path.")
@click.option("--gitleaks", "gitleaks_path", type=click.Path(dir_okay=False), default=None,
              help="Explicit gitleaks binary path.")
@click.option("--ai-analysis/--no-ai-analysis", default=True,
              help="Use Codex for false-positive analysis when available.")
@click.option("--verify/--no-verify", default=True,
              help="Allow scanners that support verification to verify candidate secrets.")
def scan(
    repo: str,
    run_id: str | None,
    bin_dir: str | None,
    scratch_dir: str | None,
    reports_dir: str | None,
    trufflehog_path: str | None,
    gitleaks_path: str | None,
    ai_analysis: bool,
    verify: bool,
) -> None:
    """Run TruffleHog and Gitleaks and write secret-hunter.report.json."""
    paths = project_paths(
        bin_dir=bin_dir,
        scratch_dir=scratch_dir,
        reports_dir=reports_dir,
    )
    run_id = run_id or f"secrets_{uuid.uuid4().hex[:8]}"

    try:
        repo_path = Path(repo).resolve()
        report_path = scan_repository(
            repo_path=repo_path,
            run_id=run_id,
            paths=paths,
            trufflehog_path=trufflehog_path,
            gitleaks_path=gitleaks_path,
            ai_analysis=ai_analysis,
            verify=verify,
        )
    except Exception as e:
        console.print(f"[red]failed[/red] {type(e).__name__}: {e}")
        sys.exit(1)

    console.print(f"[green]done[/green] run_id={run_id} report={report_path}")


if __name__ == "__main__":
    main()
