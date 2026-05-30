"""Click-based CLI: auth-check, run, status, report."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import sys
import uuid
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from audit.auth import AuthError, configure_auth
from audit.campaign import run_campaign
from audit.config import VALID_REASONING_EFFORTS, load_config
from audit.orchestrator import CostExceeded, run_pipeline
from audit.state import LegacyDatabaseError, StateDB


def _allow_api_key_from_env_or_flag(flag: bool) -> bool:
    """A user may opt into api_key mode via --allow-api-key OR via
    AUDIT_ALLOW_API_KEY=1 in the env. Either is sufficient."""
    if flag:
        return True
    return os.environ.get("AUDIT_ALLOW_API_KEY", "").strip() not in ("", "0", "false", "False")


def _provider_from_env_or_flag(provider: str | None) -> tuple[str, bool]:
    """Return (provider, explicit) from --provider, AUDIT_PROVIDER, or default."""
    raw = provider or os.environ.get("AUDIT_PROVIDER", "").strip()
    if not raw:
        return "codex", False
    p = raw.lower()
    if p not in {"codex", "claude"}:
        raise click.BadParameter("provider must be 'codex' or 'claude'")
    return p, True


REPO_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = REPO_ROOT / "state.db"
RESULTS_ROOT = REPO_ROOT / "results"

console = Console()


def _open_state_db_or_exit() -> StateDB:
    try:
        return StateDB(DB_PATH)
    except LegacyDatabaseError as e:
        console.print(f"[red]database error:[/red] {e}")
        sys.exit(2)


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True,
                              show_path=False, markup=False)],
    )


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="DEBUG logging.")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """audit — Cloudflare-style 8-stage vulnerability discovery agent."""
    ctx.ensure_object(dict)
    _setup_logging(verbose)


@main.command("auth-check")
@click.option("--provider", type=click.Choice(["codex", "claude"]), default=None,
              help="Agent provider to check (default: AUDIT_PROVIDER or codex).")
@click.option("--allow-api-key", is_flag=True, default=False,
              help="Honor ANTHROPIC_API_KEY for metered Anthropic billing "
                   "when --provider claude (also via AUDIT_ALLOW_API_KEY=1).")
def auth_check(provider: str | None, allow_api_key: bool) -> None:
    """Verify provider auth is configured correctly."""
    allow = _allow_api_key_from_env_or_flag(allow_api_key)
    selected_provider, _ = _provider_from_env_or_flag(provider)
    try:
        status = configure_auth(provider=selected_provider, allow_api_key=allow)
    except AuthError as e:
        console.print(f"[red]auth error:[/red] {e}")
        sys.exit(2)
    if status.provider == "codex":
        if status.auth_mode == "codex_api_key":
            console.print("[green]OK[/green] using OPENAI_API_KEY via Codex CLI")
        else:
            console.print("[green]OK[/green] using stored Codex login/access token")
        console.print(f"codex CLI: {status.codex_cli_path} ({status.codex_cli_version})")
        return

    if status.auth_mode == "oauth_token":
        console.print("[green]OK[/green] using CLAUDE_CODE_OAUTH_TOKEN")
    elif status.auth_mode == "api_key":
        console.print(
            "[green]OK[/green] using ANTHROPIC_API_KEY (metered Anthropic API billing)"
        )
    elif status.auth_mode == "keychain_login":
        console.print(
            f"[green]OK[/green] using stored login from {status.credentials_file}"
        )
    elif status.auth_mode == "gateway":
        console.print(
            f"[green]OK[/green] using LLM gateway at {status.gateway_base_url} "
            "(ANTHROPIC_AUTH_TOKEN)"
        )
        if status.gateway_model:
            console.print(f"          ANTHROPIC_MODEL={status.gateway_model}")
    if status.api_key_scrubbed:
        console.print("[yellow]scrubbed[/yellow] ANTHROPIC_API_KEY removed from env "
                      "(it would have outranked the active auth mode)")
    if status.auth_token_scrubbed:
        console.print("[yellow]scrubbed[/yellow] ANTHROPIC_AUTH_TOKEN removed from env "
                      "(no gateway base URL set — leaving it would outrank subscription)")
    console.print(f"claude CLI: {status.claude_cli_path} ({status.claude_cli_version})")


@main.command("run")
@click.option("--repo", "repo", required=True, type=click.Path(exists=True, file_okay=False),
              help="Path to the target source-code repo.")
@click.option("--run-id", default=None, help="Run identifier (default: random).")
@click.option("--resume", is_flag=True, help="Resume an existing run-id.")
@click.option("--max-cost-usd", default=None, type=float,
              help="Legacy: abort if cumulative dollar cost crosses this threshold.")
@click.option("--max-tokens", default=None, type=click.IntRange(min=1),
              help="Abort if cumulative input + output tokens reaches this cap.")
@click.option("--max-concurrency", default=None, type=int,
              help="Cap every stage's concurrency to this (usage containment).")
@click.option("--max-recon-tasks", default=None, type=int,
              help="Cap the number of initial Hunt tasks Recon may emit.")
@click.option("--reasoning-effort",
              type=click.Choice(VALID_REASONING_EFFORTS),
              default=None,
              help="Override OpenAI reasoning effort for every stage.")
@click.option("--target-url", default=None,
              help="Optional: URL of a live deployment the agents can hit "
                   "to confirm findings (e.g. http://server.local:8888).")
@click.option("--target-creds", "target_creds", multiple=True,
              metavar="KEY=VALUE",
              help="Credentials for the live target. Repeat the flag for "
                   "each KEY=VALUE pair (e.g. --target-creds email=admin@x "
                   "--target-creds password=...).")
@click.option("--scope-notes", "scope_notes_path", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="Optional: path to a text file with target-specific scope "
                   "rules / exclusions; passed verbatim to every stage.")
@click.option("--config", "config_path", default=None, type=click.Path(),
              help="Override config/stages.yaml.")
@click.option("--provider", type=click.Choice(["codex", "claude"]), default=None,
              help="Agent provider to use for every stage "
                   "(default: AUDIT_PROVIDER or codex).")
@click.option("--allow-api-key", is_flag=True, default=False,
              help="Honor ANTHROPIC_API_KEY for metered Anthropic billing "
                   "when --provider claude (also via AUDIT_ALLOW_API_KEY=1).")
def run(repo: str, run_id: str | None, resume: bool, max_cost_usd: float | None,
        max_tokens: int | None,
        max_concurrency: int | None, max_recon_tasks: int | None,
        reasoning_effort: str | None,
        target_url: str | None, target_creds: tuple[str, ...],
        scope_notes_path: str | None,
        config_path: str | None, provider: str | None,
        allow_api_key: bool) -> None:
    """Run the full 8-stage pipeline against a target repo."""
    allow = _allow_api_key_from_env_or_flag(allow_api_key)
    selected_provider, provider_explicit = _provider_from_env_or_flag(provider)
    try:
        configure_auth(provider=selected_provider, allow_api_key=allow)
    except AuthError as e:
        console.print(f"[red]auth error:[/red] {e}")
        sys.exit(2)

    if config_path:
        config = load_config(Path(config_path), default_provider=selected_provider)
    elif selected_provider == "claude":
        config = load_config(REPO_ROOT / "config" / "stages.claude.yaml")
    else:
        config = load_config(default_provider=selected_provider)
    if provider_explicit:
        config.set_provider(selected_provider)
    if max_cost_usd is not None:
        console.print(
            "[yellow]warning:[/yellow] --max-cost-usd is deprecated; use "
            "--max-tokens for provider-independent budget caps."
        )
    if max_concurrency is not None:
        config.cap_concurrency(max_concurrency)
        console.print(f"[cyan]capped concurrency to {max_concurrency} across all stages[/cyan]")
    if reasoning_effort is not None:
        config.set_reasoning_effort(reasoning_effort)
        console.print(f"[cyan]set reasoning effort to {reasoning_effort} across all stages[/cyan]")

    # Live-target plumbing — agents will receive {"url": ..., "credentials": {...}}
    # in their user_input when set.
    live_target: dict | None = None
    if target_url:
        creds: dict[str, str] = {}
        for kv in target_creds:
            if "=" not in kv:
                console.print(f"[red]invalid --target-creds {kv!r} — expected KEY=VALUE[/red]")
                sys.exit(2)
            k, _, v = kv.partition("=")
            creds[k.strip()] = v.strip()
        live_target = {"url": target_url, "credentials": creds}
        console.print(f"[cyan]live target:[/cyan] {target_url} (creds: {sorted(creds)})")
    elif target_creds:
        console.print("[yellow]--target-creds without --target-url is ignored[/yellow]")

    scope_notes: str | None = None
    if scope_notes_path:
        scope_notes = Path(scope_notes_path).read_text()
        console.print(f"[cyan]scope notes loaded:[/cyan] {scope_notes_path} ({len(scope_notes)} chars)")

    run_id = run_id or f"run_{uuid.uuid4().hex[:8]}"
    repo_path = Path(repo).resolve()

    db = _open_state_db_or_exit()
    try:
        report = asyncio.run(run_pipeline(
            repo_path=repo_path,
            run_id=run_id,
            db=db,
            config=config,
            max_cost_usd=max_cost_usd,
            max_tokens=max_tokens,
            resume=resume,
            max_recon_tasks=max_recon_tasks,
            live_target=live_target,
            scope_notes=scope_notes,
        ))
        console.print(f"[green]done[/green] run_id={run_id} report={report}")
    except CostExceeded as e:
        console.print(f"[yellow]aborted[/yellow] {e}")
        sys.exit(3)
    except KeyboardInterrupt:
        db.finish_run(run_id, "aborted")
        console.print(f"[yellow]aborted[/yellow] interrupted run_id={run_id}")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]failed[/red] {type(e).__name__}: {e}")
        raise
    finally:
        db.close()


@main.group("campaign")
def campaign_cmd() -> None:
    """Run and inspect multi-run campaigns."""


@campaign_cmd.command("run")
@click.option("--repo", "repo", required=True, type=click.Path(exists=True, file_okay=False),
              help="Path to the target source-code repo.")
@click.option("--campaign-id", required=True, help="Campaign identifier.")
@click.option("--runs", required=True, type=click.IntRange(min=1),
              help="Maximum child runs to launch.")
@click.option("--max-tokens", default=None, type=click.IntRange(min=1),
              help="Campaign-wide input + output token cap.")
@click.option("--stop-after-empty", default=3, show_default=True,
              type=click.IntRange(min=1),
              help="Stop after this many consecutive child runs add no new reachable issues.")
@click.option("--seed-run-id", "seed_run_ids", multiple=True,
              help="Prior run ID to import into the initial campaign ledger. Repeatable.")
@click.option("--max-concurrency", default=None, type=int,
              help="Cap every stage's concurrency to this (usage containment).")
@click.option("--max-recon-tasks", default=None, type=int,
              help="Cap the number of initial Hunt tasks Recon may emit.")
@click.option("--reasoning-effort",
              type=click.Choice(VALID_REASONING_EFFORTS),
              default=None,
              help="Override OpenAI reasoning effort for every stage.")
@click.option("--target-url", default=None,
              help="Optional: URL of a live deployment the agents can hit "
                   "to confirm findings (e.g. http://server.local:8888).")
@click.option("--target-creds", "target_creds", multiple=True,
              metavar="KEY=VALUE",
              help="Credentials for the live target. Repeat the flag for each KEY=VALUE pair.")
@click.option("--scope-notes", "scope_notes_path", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="Optional: path to target-specific scope rules / exclusions.")
@click.option("--config", "config_path", default=None, type=click.Path(),
              help="Override config/stages.yaml.")
@click.option("--provider", type=click.Choice(["codex", "claude"]), default=None,
              help="Agent provider to use for every stage "
                   "(default: AUDIT_PROVIDER or codex).")
@click.option("--allow-api-key", is_flag=True, default=False,
              help="Honor ANTHROPIC_API_KEY for metered Anthropic billing "
                   "when --provider claude (also via AUDIT_ALLOW_API_KEY=1).")
def campaign_run(repo: str, campaign_id: str, runs: int, max_tokens: int | None,
                 stop_after_empty: int, seed_run_ids: tuple[str, ...],
                 max_concurrency: int | None, max_recon_tasks: int | None,
                 reasoning_effort: str | None,
                 target_url: str | None, target_creds: tuple[str, ...],
                 scope_notes_path: str | None,
                 config_path: str | None, provider: str | None,
                 allow_api_key: bool) -> None:
    """Run the full 8-stage pipeline repeatedly with shared campaign memory."""
    allow = _allow_api_key_from_env_or_flag(allow_api_key)
    selected_provider, provider_explicit = _provider_from_env_or_flag(provider)
    try:
        configure_auth(provider=selected_provider, allow_api_key=allow)
    except AuthError as e:
        console.print(f"[red]auth error:[/red] {e}")
        sys.exit(2)

    if config_path:
        config = load_config(Path(config_path), default_provider=selected_provider)
    elif selected_provider == "claude":
        config = load_config(REPO_ROOT / "config" / "stages.claude.yaml")
    else:
        config = load_config(default_provider=selected_provider)
    if provider_explicit:
        config.set_provider(selected_provider)
    if max_concurrency is not None:
        config.cap_concurrency(max_concurrency)
        console.print(f"[cyan]capped concurrency to {max_concurrency} across all stages[/cyan]")
    if reasoning_effort is not None:
        config.set_reasoning_effort(reasoning_effort)
        console.print(f"[cyan]set reasoning effort to {reasoning_effort} across all stages[/cyan]")

    live_target: dict | None = None
    if target_url:
        creds: dict[str, str] = {}
        for kv in target_creds:
            if "=" not in kv:
                console.print(f"[red]invalid --target-creds {kv!r} — expected KEY=VALUE[/red]")
                sys.exit(2)
            k, _, v = kv.partition("=")
            creds[k.strip()] = v.strip()
        live_target = {"url": target_url, "credentials": creds}
        console.print(f"[cyan]live target:[/cyan] {target_url} (creds: {sorted(creds)})")
    elif target_creds:
        console.print("[yellow]--target-creds without --target-url is ignored[/yellow]")

    scope_notes: str | None = None
    if scope_notes_path:
        scope_notes = Path(scope_notes_path).read_text()
        console.print(f"[cyan]scope notes loaded:[/cyan] {scope_notes_path} ({len(scope_notes)} chars)")

    repo_path = Path(repo).resolve()
    db = _open_state_db_or_exit()
    try:
        report = asyncio.run(run_campaign(
            repo_path=repo_path,
            campaign_id=campaign_id,
            runs=runs,
            max_tokens=max_tokens,
            stop_after_empty=stop_after_empty,
            seed_run_ids=list(seed_run_ids),
            db=db,
            config=config,
            max_recon_tasks=max_recon_tasks,
            live_target=live_target,
            scope_notes=scope_notes,
            results_root=RESULTS_ROOT,
        ))
        row = db.get_campaign(campaign_id)
        stop_reason = row["stop_reason"] if row else "unknown"
        console.print(
            f"[green]done[/green] campaign_id={campaign_id} "
            f"stop_reason={stop_reason} report={report}"
        )
    except KeyboardInterrupt:
        db.finish_campaign(campaign_id, "aborted", "interrupted")
        console.print(f"[yellow]aborted[/yellow] interrupted campaign_id={campaign_id}")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]failed[/red] {type(e).__name__}: {e}")
        raise
    finally:
        db.close()


@campaign_cmd.command("status")
@click.option("--campaign-id", default=None)
def campaign_status(campaign_id: str | None) -> None:
    """Show campaign child runs, token totals, and stop reason."""
    db = _open_state_db_or_exit()
    try:
        if campaign_id is None:
            _show_campaigns_table(db)
            return
        row = db.get_campaign(campaign_id)
        if row is None:
            console.print(f"[red]unknown campaign_id {campaign_id!r}[/red]")
            sys.exit(1)
        _show_campaign_detail(db, campaign_id)
    finally:
        db.close()


@campaign_cmd.command("report")
@click.option("--campaign-id", required=True)
@click.option("--format", "fmt", type=click.Choice(["json", "md"]), default="json")
def campaign_report(campaign_id: str, fmt: str) -> None:
    """Print the consolidated campaign report."""
    report_path = RESULTS_ROOT / campaign_id / "campaign" / "report.json"
    if not report_path.exists():
        console.print(f"[red]no campaign report at {report_path}[/red]")
        sys.exit(1)
    payload = json.loads(report_path.read_text())
    if fmt == "json":
        click.echo(json.dumps(payload, indent=2))
    else:
        click.echo(_render_markdown_report(payload))


@main.command("status")
@click.option("--run-id", default=None)
def status(run_id: str | None) -> None:
    """Show pipeline status: tasks, findings, traces, token usage."""
    db = _open_state_db_or_exit()
    try:
        if run_id is None:
            _show_runs_table(db)
            return
        run = db.get_run(run_id)
        if run is None:
            console.print(f"[red]unknown run_id {run_id!r}[/red]")
            sys.exit(1)
        _show_run_detail(db, run_id)
    finally:
        db.close()


@main.group("db")
def db_cmd() -> None:
    """Manage local audit state."""


@db_cmd.command("reset")
@click.option("--results", "wipe_results", is_flag=True,
              help="Also remove the results/ directory.")
@click.option("--work", "wipe_work", is_flag=True,
              help="Also remove the work/ directory.")
@click.option("--all", "wipe_all", is_flag=True,
              help="Remove state.db, results/, and work/.")
@click.option("--yes", is_flag=True,
              help="Do not prompt before deleting files.")
@click.option("--dry-run", is_flag=True,
              help="Print what would be removed without deleting anything.")
def db_reset(wipe_results: bool, wipe_work: bool, wipe_all: bool,
             yes: bool, dry_run: bool) -> None:
    """Reset local run state so future audits start from a fresh database."""
    targets = [DB_PATH]
    if wipe_results or wipe_all:
        targets.append(RESULTS_ROOT)
    if wipe_work or wipe_all:
        targets.append(REPO_ROOT / "work")

    existing = [p for p in targets if p.exists()]
    if not existing:
        console.print("[cyan]nothing to remove[/cyan]")
        return

    console.print("[yellow]will remove:[/yellow]")
    for path in existing:
        console.print(f"  {path}")
    if dry_run:
        return
    if not yes:
        click.confirm("Remove these files/directories?", abort=True)

    for path in existing:
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
    console.print("[green]reset complete[/green]")


@main.command("report")
@click.option("--run-id", required=True)
@click.option("--format", "fmt", type=click.Choice(["json", "md"]), default="json")
def report(run_id: str, fmt: str) -> None:
    """Print (or generate) the final report."""
    report_path = RESULTS_ROOT / run_id / "report" / "report.json"
    if not report_path.exists():
        console.print(f"[red]no report at {report_path}[/red]")
        sys.exit(1)
    payload = json.loads(report_path.read_text())
    if fmt == "json":
        click.echo(json.dumps(payload, indent=2))
    else:
        click.echo(_render_markdown_report(payload))


def _show_runs_table(db: StateDB) -> None:
    runs = db.list_runs()
    t = Table(title="runs", show_lines=False)
    t.add_column("run_id")
    t.add_column("repo")
    t.add_column("status")
    t.add_column("tokens")
    for r in runs:
        t.add_row(r["run_id"], r["repo_path"], r["status"],
                  str(db.total_tokens(r["run_id"])))
    console.print(t)


def _show_campaigns_table(db: StateDB) -> None:
    campaigns = db.list_campaigns()
    t = Table(title="campaigns", show_lines=False)
    t.add_column("campaign_id")
    t.add_column("repo")
    t.add_column("status")
    t.add_column("runs")
    t.add_column("tokens")
    t.add_column("stop reason")
    for c in campaigns:
        child_runs = db.list_campaign_runs(c["campaign_id"])
        t.add_row(
            c["campaign_id"],
            c["repo_path"],
            c["status"],
            f"{len(child_runs)}/{c['requested_runs']}",
            str(db.campaign_total_tokens(c["campaign_id"])),
            c["stop_reason"] or "",
        )
    console.print(t)


def _show_campaign_detail(db: StateDB, campaign_id: str) -> None:
    campaign = db.get_campaign(campaign_id)
    child_runs = db.list_campaign_runs(campaign_id)

    t = Table(title=f"campaign {campaign_id}", show_lines=False)
    t.add_column("metric"); t.add_column("value")
    t.add_row("repo", campaign["repo_path"])
    t.add_row("status", campaign["status"])
    t.add_row("requested runs", str(campaign["requested_runs"]))
    t.add_row("child runs", str(len(child_runs)))
    t.add_row("max tokens", str(campaign["max_tokens"] or ""))
    t.add_row("tokens", str(db.campaign_total_tokens(campaign_id)))
    t.add_row("stop after empty", str(campaign["stop_after_empty"]))
    t.add_row("stop reason", campaign["stop_reason"] or "")
    console.print(t)

    runs_table = Table(title="child runs", show_lines=False)
    runs_table.add_column("index")
    runs_table.add_column("run_id")
    runs_table.add_column("status")
    runs_table.add_column("tokens")
    runs_table.add_column("new reachable issues")
    for child in child_runs:
        runs_table.add_row(
            str(child["run_index"]),
            child["child_run_id"],
            child["status"],
            str(child["tokens"]),
            str(child["new_reachable_issue_count"]),
        )
    console.print(runs_table)


def _show_run_detail(db: StateDB, run_id: str) -> None:
    tasks = db.get_all_tasks(run_id)
    findings = db.get_findings(run_id)
    confirmed = [f for f in findings if f.validation_status == "confirmed"]
    canonical = [f for f in confirmed if f.is_canonical]
    reachable = db.get_reachable_canonical_findings(run_id)

    t = Table(title=f"run {run_id}", show_lines=False)
    t.add_column("metric"); t.add_column("count")
    t.add_row("tasks (total)", str(len(tasks)))
    t.add_row("tasks (pending)", str(sum(1 for x in tasks if x.status == "pending")))
    t.add_row("tasks (done)", str(sum(1 for x in tasks if x.status == "done")))
    t.add_row("tasks (failed)", str(sum(1 for x in tasks if x.status == "failed")))
    t.add_row("findings (raw)", str(len(findings)))
    t.add_row("findings (confirmed)", str(len(confirmed)))
    t.add_row("findings (canonical)", str(len(canonical)))
    t.add_row("findings (reachable)", str(len(reachable)))
    t.add_row("tokens", str(db.total_tokens(run_id)))
    t.add_row("input tokens", str(db.total_input_tokens(run_id)))
    t.add_row("output tokens", str(db.total_output_tokens(run_id)))
    console.print(t)


def _render_markdown_report(report: dict) -> str:
    lines: list[str] = []
    lines.append(f"# Vulnerability report — `{report['run_id']}`")
    lines.append(f"Target: `{report['target']['repo_path']}`  ")
    s = report["summary"]
    by = s.get("by_severity", {})
    lines.append(f"**Total findings: {s['total']}** — "
                 + ", ".join(f"{k}: {v}" for k, v in by.items()) if by
                 else f"**Total findings: {s['total']}**")
    lines.append("")
    for f in report["findings"]:
        lines.append(f"## {f['title']}")
        lines.append(f"- **Severity**: {f['severity']}  ")
        lines.append(f"- **Class**: {f['vuln_class']}"
                     + (f" ({f['cwe']})" if f.get("cwe") else ""))
        lines.append(f"- **Location**: `{f['file']}:{f['line_start']}-{f['line_end']}`  ")
        lines.append("")
        lines.append(f["description"])
        lines.append("")
        lines.append("```")
        lines.append(f["evidence"])
        lines.append("```")
        lines.append("")
        ep = f["trace"].get("entry_points", [])
        if ep:
            lines.append("**Entry points**:")
            for e in ep:
                lines.append(f"- `{e['kind']}` at `{e['location']}`")
            lines.append("")
        cc = f["trace"].get("call_chain", [])
        if cc:
            lines.append("**Call chain**:")
            for frame in cc:
                lines.append(f"1. `{frame['file']}:{frame['line']}` — `{frame['function']}()`")
            lines.append("")
        lines.append(f"**Recommendation**: {f['recommendation']}")
        lines.append("")
        if f.get("variants"):
            lines.append(f"_Variants_: {', '.join(f['variants'])}")
            lines.append("")
        lines.append("---")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
