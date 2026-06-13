"""Master CLI for combining and orchestrating audit-hunter tools."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from audit_hunter.assessment import (
    AssessmentError,
    SecretScanOptions,
    VulnRunOptions,
    default_run_id,
    run_assessment,
)
from audit_hunter.combine import CombineError, combine_tool_reports
from audit_hunter.threat_model import (
    AI_PASS_MODES,
    AI_REASONING_EFFORTS,
    DEFAULT_AI_REASONING_EFFORT,
    DEFAULT_AI_RENDER_MODEL,
    DEFAULT_AI_TIMEOUT_SECONDS,
    DEFAULT_AI_UNDERSTANDING_MODEL,
    DEFAULT_THREAT_MODEL_MODE,
    THREAT_MODEL_MODES,
    AIThreatModelOptions,
    ThreatModelError,
    ThreatModelOptions,
    generate_threat_model,
)
from audit_hunter_common.paths import project_paths


console = Console()


@click.group()
def main() -> None:
    """audit-hunter — local assessment orchestration and reporting."""


@main.command("tools")
def tools() -> None:
    """List expected standalone tool entrypoints."""
    for name in ("vuln-hunter", "secret-hunter"):
        click.echo(name)


@main.command("threat-model")
@click.option("--repo", required=True, type=click.Path(exists=True, file_okay=False),
              help="Path to the target source-code repo.")
@click.option("--run-id", default=None,
              help="Run identifier for report copies (default: random).")
@click.option("--mode", type=click.Choice(list(THREAT_MODEL_MODES)),
              default=DEFAULT_THREAT_MODEL_MODE, show_default=True,
              help="Threat-model generation mode.")
@click.option("--edit-threat-model", is_flag=True,
              help="Open the generated threat model in $VISUAL/$EDITOR before copying to reports.")
@click.option("--scratch-dir", type=click.Path(file_okay=False), default=None,
              help="Scratch directory for raw AI threat-model artifacts.")
@click.option("--reports-dir", type=click.Path(file_okay=False), default=None,
              help="Directory for copied threat-model artifacts.")
@click.option("--ai-passes", type=click.Choice(list(AI_PASS_MODES)), default="two",
              show_default=True, help="Use one or two Codex calls for AI mode.")
@click.option("--ai-understanding-model", default=DEFAULT_AI_UNDERSTANDING_MODEL,
              show_default=True, help="Codex model for the AI understanding pass.")
@click.option("--ai-render-model", default=DEFAULT_AI_RENDER_MODEL,
              show_default=True, help="Codex model for the AI render pass.")
@click.option("--ai-reasoning-effort", type=click.Choice(list(AI_REASONING_EFFORTS)),
              default=DEFAULT_AI_REASONING_EFFORT, show_default=True,
              help="OpenAI reasoning effort for AI threat-model Codex calls.")
@click.option("--ai-timeout", type=click.IntRange(min=1),
              default=DEFAULT_AI_TIMEOUT_SECONDS, show_default=True,
              help="Timeout in seconds for each AI threat-model Codex call.")
@click.option("--codex-path", type=click.Path(dir_okay=False), default=None,
              help="Explicit Codex CLI path for AI threat-model mode.")
def threat_model_command(
    repo: str,
    run_id: str | None,
    mode: str,
    edit_threat_model: bool,
    scratch_dir: str | None,
    reports_dir: str | None,
    ai_passes: str,
    ai_understanding_model: str,
    ai_render_model: str,
    ai_reasoning_effort: str,
    ai_timeout: int,
    codex_path: str | None,
) -> None:
    """Generate STRIDE threat-model artifacts for a local repo."""
    paths = project_paths(scratch_dir=scratch_dir, reports_dir=reports_dir)
    effective_run_id = run_id or default_run_id()
    try:
        artifacts = generate_threat_model(
            repo_path=Path(repo),
            run_id=effective_run_id,
            reports_dir=paths.reports_dir,
            options=_threat_model_options(
                mode=mode,
                edit=edit_threat_model,
                ai_passes=ai_passes,
                ai_understanding_model=ai_understanding_model,
                ai_render_model=ai_render_model,
                ai_reasoning_effort=ai_reasoning_effort,
                ai_timeout=ai_timeout,
                codex_path=codex_path,
                artifact_dir=paths.artifacts_dir / effective_run_id / "audit-hunter",
            ),
        )
    except ThreatModelError as e:
        console.print(f"[red]failed[/red] {e}")
        sys.exit(1)

    console.print(
        "[green]done[/green] "
        f"run_id={effective_run_id} "
        f"threat_model={artifacts.threat_model_path} "
        f"security_config={artifacts.security_config_path}"
    )


@main.command("assess")
@click.option("--repo", required=True, type=click.Path(exists=True, file_okay=False),
              help="Path to the already-cloned target source-code repo.")
@click.option("--run-id", default=None,
              help="Run identifier shared across all tools (default: random).")
@click.option("--skip-threat-model", is_flag=True,
              help="Reuse existing .audit-hunter threat-model artifacts in the target repo.")
@click.option("--threat-model-mode", type=click.Choice(list(THREAT_MODEL_MODES)),
              default=DEFAULT_THREAT_MODEL_MODE, show_default=True,
              help="Threat-model generation mode when --skip-threat-model is not set.")
@click.option("--edit-threat-model", is_flag=True,
              help="Open the threat model in $VISUAL/$EDITOR before downstream stages.")
@click.option("--bin-dir", type=click.Path(file_okay=False), default=None,
              help="Directory containing user-managed scanner binaries.")
@click.option("--scratch-dir", type=click.Path(file_okay=False), default=None,
              help="Scratch directory for raw artifacts and generated scope notes.")
@click.option("--reports-dir", type=click.Path(file_okay=False), default=None,
              help="Directory for final machine-readable reports.")
@click.option("--trufflehog", "trufflehog_path", type=click.Path(dir_okay=False), default=None,
              help="Explicit trufflehog binary path.")
@click.option("--gitleaks", "gitleaks_path", type=click.Path(dir_okay=False), default=None,
              help="Explicit gitleaks binary path.")
@click.option("--ai-analysis/--no-ai-analysis", default=True,
              help="Use Codex for secret false-positive analysis when available.")
@click.option("--verify/--no-verify", default=True,
              help="Allow secret scanners that support verification to verify candidates.")
@click.option("--vuln-mode", type=click.Choice(["run", "campaign"]), default="run",
              show_default=True,
              help="Run a single vuln-hunter pass or a multi-run campaign.")
@click.option("--runs", default=None, type=click.IntRange(min=1),
              help="Number of vuln-hunter campaign child runs when --vuln-mode campaign.")
@click.option("--stop-after-empty", default=3, show_default=True,
              type=click.IntRange(min=1),
              help="Campaign stop condition for consecutive runs with no new reachable issues.")
@click.option("--seed-run-id", "seed_run_ids", multiple=True,
              help="Prior vuln-hunter run ID to seed campaign memory. Repeatable.")
@click.option("--threat-scope-runs", default=1, show_default=True,
              type=click.IntRange(min=0),
              help="Number of initial vuln runs that receive generated threat-model targeting.")
@click.option("--max-tokens", default=None, type=click.IntRange(min=1),
              help="Abort vuln-hunter if cumulative input + output tokens reaches this cap.")
@click.option("--max-concurrency", default=None, type=int,
              help="Cap vuln-hunter stage concurrency.")
@click.option("--max-recon-tasks", default=None, type=int,
              help="Cap the number of initial vuln-hunter Recon tasks.")
@click.option("--reasoning-effort", default=None,
              help="Override OpenAI reasoning effort for every vuln-hunter stage.")
@click.option("--target-url", default=None,
              help="Optional live deployment URL for vuln-hunter reproduction.")
@click.option("--target-creds", "target_creds", multiple=True, metavar="KEY=VALUE",
              help="Credentials for the live target. Repeat for each KEY=VALUE pair.")
@click.option("--scope-notes", "scope_notes_path", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="Additional user scope notes for vuln-hunter; in campaign mode these apply to every child run.")
@click.option("--threat-model-ai-passes", type=click.Choice(list(AI_PASS_MODES)),
              default="two", show_default=True,
              help="Use one or two Codex calls for AI threat-model mode.")
@click.option("--threat-model-understanding-model", default=DEFAULT_AI_UNDERSTANDING_MODEL,
              show_default=True, help="Codex model for the AI threat-model understanding pass.")
@click.option("--threat-model-render-model", default=DEFAULT_AI_RENDER_MODEL,
              show_default=True, help="Codex model for the AI threat-model render pass.")
@click.option("--threat-model-reasoning-effort", type=click.Choice(list(AI_REASONING_EFFORTS)),
              default=DEFAULT_AI_REASONING_EFFORT, show_default=True,
              help="OpenAI reasoning effort for AI threat-model Codex calls.")
@click.option("--threat-model-timeout", type=click.IntRange(min=1),
              default=DEFAULT_AI_TIMEOUT_SECONDS, show_default=True,
              help="Timeout in seconds for each AI threat-model Codex call.")
@click.option("--threat-model-codex-path", type=click.Path(dir_okay=False), default=None,
              help="Explicit Codex CLI path for AI threat-model mode.")
@click.option("--config", "config_path", default=None, type=click.Path(),
              help="Override vuln-hunter config/stages.yaml.")
@click.option("--provider", type=click.Choice(["codex", "claude"]), default=None,
              help="Agent provider to use for vuln-hunter.")
@click.option("--allow-api-key", is_flag=True, default=False,
              help="Allow vuln-hunter claude provider to honor ANTHROPIC_API_KEY.")
@click.option("--vuln-command", default=None,
              help="Command prefix for vuln-hunter (default: uv run --project vuln-hunter vuln-hunter).")
def assess(
    repo: str,
    run_id: str | None,
    skip_threat_model: bool,
    threat_model_mode: str,
    edit_threat_model: bool,
    bin_dir: str | None,
    scratch_dir: str | None,
    reports_dir: str | None,
    trufflehog_path: str | None,
    gitleaks_path: str | None,
    ai_analysis: bool,
    verify: bool,
    vuln_mode: str,
    runs: int | None,
    stop_after_empty: int,
    seed_run_ids: tuple[str, ...],
    threat_scope_runs: int,
    max_tokens: int | None,
    max_concurrency: int | None,
    max_recon_tasks: int | None,
    reasoning_effort: str | None,
    target_url: str | None,
    target_creds: tuple[str, ...],
    scope_notes_path: str | None,
    threat_model_ai_passes: str,
    threat_model_understanding_model: str,
    threat_model_render_model: str,
    threat_model_reasoning_effort: str,
    threat_model_timeout: int,
    threat_model_codex_path: str | None,
    config_path: str | None,
    provider: str | None,
    allow_api_key: bool,
    vuln_command: str | None,
) -> None:
    """Run threat-model, secret-hunter, vuln-hunter, then combine reports."""
    paths = project_paths(
        bin_dir=bin_dir,
        scratch_dir=scratch_dir,
        reports_dir=reports_dir,
    )
    effective_run_id = run_id or default_run_id()
    try:
        result = run_assessment(
            repo_path=Path(repo),
            run_id=effective_run_id,
            paths=paths,
            skip_threat_model=skip_threat_model,
            threat_model_options=_threat_model_options(
                mode=threat_model_mode,
                edit=edit_threat_model,
                ai_passes=threat_model_ai_passes,
                ai_understanding_model=threat_model_understanding_model,
                ai_render_model=threat_model_render_model,
                ai_reasoning_effort=threat_model_reasoning_effort,
                ai_timeout=threat_model_timeout,
                codex_path=threat_model_codex_path,
                artifact_dir=paths.artifacts_dir / effective_run_id / "audit-hunter",
            ),
            secret_options=SecretScanOptions(
                trufflehog_path=trufflehog_path,
                gitleaks_path=gitleaks_path,
                ai_analysis=ai_analysis,
                verify=verify,
            ),
            vuln_options=VulnRunOptions(
                vuln_mode=vuln_mode,
                runs=runs,
                stop_after_empty=stop_after_empty,
                seed_run_ids=seed_run_ids,
                threat_scope_runs=threat_scope_runs,
                max_tokens=max_tokens,
                max_concurrency=max_concurrency,
                max_recon_tasks=max_recon_tasks,
                reasoning_effort=reasoning_effort,
                target_url=target_url,
                target_creds=target_creds,
                scope_notes_path=scope_notes_path,
                config_path=config_path,
                provider=provider,
                allow_api_key=allow_api_key,
                vuln_command=vuln_command,
            ),
        )
    except (AssessmentError, CombineError, ThreatModelError) as e:
        console.print(f"[red]failed[/red] {e}")
        sys.exit(1)

    console.print(
        "[green]done[/green] "
        f"run_id={result.run_id} "
        f"scope_notes={result.scope_notes_path or 'none'} "
        f"report={result.combined_report_path}"
    )


@main.command("combine")
@click.option("--run-id", required=True, help="Run identifier to combine.")
@click.option("--reports-dir", type=click.Path(file_okay=False), default=None,
              help="Directory containing per-tool reports.")
def combine(run_id: str, reports_dir: str | None) -> None:
    """Combine per-tool JSON reports into audit-hunter.report.json."""
    paths = project_paths(reports_dir=reports_dir)
    try:
        out_path = combine_tool_reports(run_id=run_id, reports_dir=paths.reports_dir)
    except CombineError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    console.print(f"[green]done[/green] run_id={run_id} report={out_path}")


def _threat_model_options(
    *,
    mode: str,
    edit: bool,
    ai_passes: str,
    ai_understanding_model: str,
    ai_render_model: str,
    ai_reasoning_effort: str,
    ai_timeout: int,
    codex_path: str | None,
    artifact_dir: Path,
) -> ThreatModelOptions:
    return ThreatModelOptions(
        mode=mode,
        edit=edit,
        ai=AIThreatModelOptions(
            passes=ai_passes,
            understanding_model=ai_understanding_model,
            render_model=ai_render_model,
            reasoning_effort=ai_reasoning_effort,
            timeout_seconds=ai_timeout,
            codex_path=codex_path,
        ),
        artifact_dir=artifact_dir,
        progress=_threat_model_progress,
    )


def _threat_model_progress(message: str) -> None:
    console.print(f"[cyan]threat-model[/cyan] {message}")


if __name__ == "__main__":
    main()
