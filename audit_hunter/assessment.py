"""One-shot audit-hunter assessment orchestration."""

from __future__ import annotations

import shlex
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

from audit_hunter.combine import combine_tool_reports
from audit_hunter.threat_model import (
    SECURITY_CONFIG_FILENAME,
    THREAT_MODEL_FILENAME,
    ThreatModelArtifacts,
    ThreatModelOptions,
    ensure_threat_artifacts,
)
from audit_hunter_common.paths import PROJECT_ROOT, ProjectPaths
from secret_hunter.scanner import scan_repository


@dataclass(frozen=True)
class SecretScanOptions:
    trufflehog_path: str | None = None
    gitleaks_path: str | None = None
    ai_analysis: bool = True
    verify: bool = True


@dataclass(frozen=True)
class VulnRunOptions:
    vuln_mode: str = "run"
    runs: int | None = None
    stop_after_empty: int = 3
    seed_run_ids: tuple[str, ...] = ()
    threat_scope_runs: int = 1
    max_tokens: int | None = None
    max_concurrency: int | None = None
    max_recon_tasks: int | None = None
    reasoning_effort: str | None = None
    target_url: str | None = None
    target_creds: tuple[str, ...] = ()
    scope_notes_path: str | None = None
    config_path: str | None = None
    provider: str | None = None
    allow_api_key: bool = False
    vuln_command: str | None = None


@dataclass(frozen=True)
class AssessmentResult:
    run_id: str
    threat_artifacts: ThreatModelArtifacts
    scope_notes_path: Path | None
    secret_report_path: Path
    vuln_report_path: Path
    combined_report_path: Path


class AssessmentError(RuntimeError):
    """Raised when the one-shot assessment cannot complete."""


def default_run_id() -> str:
    return f"audit_{uuid.uuid4().hex[:8]}"


def run_assessment(
    *,
    repo_path: Path,
    run_id: str,
    paths: ProjectPaths,
    skip_threat_model: bool,
    secret_options: SecretScanOptions,
    vuln_options: VulnRunOptions,
    threat_model_options: ThreatModelOptions | None = None,
) -> AssessmentResult:
    """Run threat-model, secret-hunter, vuln-hunter, then combine reports."""
    repo_path = repo_path.expanduser().resolve()
    _validate_vuln_options(vuln_options)

    threat_artifacts = ensure_threat_artifacts(
        repo_path=repo_path,
        run_id=run_id,
        reports_dir=paths.reports_dir,
        skip_generation=skip_threat_model,
        options=threat_model_options,
    )

    secret_report_path = scan_repository(
        repo_path=repo_path,
        run_id=run_id,
        paths=paths,
        trufflehog_path=secret_options.trufflehog_path,
        gitleaks_path=secret_options.gitleaks_path,
        ai_analysis=secret_options.ai_analysis,
        verify=secret_options.verify,
    )

    scope_notes_path: Path | None
    if vuln_options.vuln_mode == "campaign":
        scope_notes_path = write_vuln_scope_notes(
            repo_path=repo_path,
            run_id=run_id,
            paths=paths,
            user_scope_notes_path=None,
            include_threat_context=vuln_options.threat_scope_runs > 0,
            filename="threat-scope-notes.md",
        )
        command = build_vuln_campaign_command(
            repo_path=repo_path,
            run_id=run_id,
            paths=paths,
            targeted_scope_notes_path=scope_notes_path,
            options=vuln_options,
        )
    else:
        scope_notes_path = write_vuln_scope_notes(
            repo_path=repo_path,
            run_id=run_id,
            paths=paths,
            user_scope_notes_path=vuln_options.scope_notes_path,
            include_threat_context=vuln_options.threat_scope_runs > 0,
            filename="vuln-scope-notes.md",
        )
        command = build_vuln_command(
            repo_path=repo_path,
            run_id=run_id,
            paths=paths,
            scope_notes_path=scope_notes_path,
            options=vuln_options,
        )
    try:
        completed = subprocess.run(command, check=False)
    except FileNotFoundError as e:
        raise AssessmentError(
            f"could not start vulnerability scan command {command[0]!r}; "
            "install vuln-hunter/uv or pass --vuln-command"
        ) from e
    if completed.returncode != 0:
        raise AssessmentError(
            f"vulnerability scan failed with exit code {completed.returncode}"
        )

    vuln_report_path = _expected_vuln_report_path(
        reports_dir=paths.reports_dir,
        run_id=run_id,
        vuln_mode=vuln_options.vuln_mode,
    )
    if not vuln_report_path.exists():
        raise AssessmentError(
            f"vulnerability scan completed but did not write {vuln_report_path}"
        )

    combined_report_path = combine_tool_reports(
        run_id=run_id,
        reports_dir=paths.reports_dir,
    )
    return AssessmentResult(
        run_id=run_id,
        threat_artifacts=threat_artifacts,
        scope_notes_path=scope_notes_path,
        secret_report_path=secret_report_path,
        vuln_report_path=vuln_report_path,
        combined_report_path=combined_report_path,
    )


def write_vuln_scope_notes(
    *,
    repo_path: Path,
    run_id: str,
    paths: ProjectPaths,
    user_scope_notes_path: str | None,
    include_threat_context: bool = True,
    filename: str = "vuln-scope-notes.md",
) -> Path | None:
    """Write generated and/or user scope notes for vuln-hunter."""
    run_dir = paths.reports_dir / run_id
    threat_model_path = run_dir / THREAT_MODEL_FILENAME
    security_config_path = run_dir / SECURITY_CONFIG_FILENAME
    if include_threat_context and (
        not threat_model_path.exists() or not security_config_path.exists()
    ):
        raise AssessmentError(
            "cannot build vuln scope notes before threat artifacts are available"
        )

    artifact_dir = paths.artifacts_dir / run_id / "audit-hunter"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    scope_path = artifact_dir / filename

    lines: list[str] = []
    if include_threat_context:
        lines.extend([
            "# audit-hunter Generated Vulnerability Scope",
            "",
            "Use this context to prioritize the vulnerability-hunter run. "
            "Honor explicit exclusions and severity thresholds from the security config.",
            "",
            "## Target",
            "",
            f"- Repository: `{repo_path.expanduser().resolve()}`",
            f"- Run ID: `{run_id}`",
            "",
            "## Security Config",
            "",
            "```json",
            security_config_path.read_text().strip(),
            "```",
            "",
            "## Threat Model",
            "",
            threat_model_path.read_text().strip(),
            "",
        ])
    if user_scope_notes_path:
        user_path = Path(user_scope_notes_path).expanduser().resolve()
        if lines:
            lines.extend(["---", ""])
        lines.extend([
            "## User Scope Notes",
            "",
            user_path.read_text().strip(),
            "",
        ])
    if not lines:
        return None

    scope_path.write_text("\n".join(lines))
    return scope_path


def build_vuln_command(
    *,
    repo_path: Path,
    run_id: str,
    paths: ProjectPaths,
    scope_notes_path: Path | None,
    options: VulnRunOptions,
) -> list[str]:
    """Build the existing vuln-hunter run command."""
    command = _base_vuln_command(options.vuln_command)
    command.extend([
        "run",
        "--repo",
        str(repo_path),
        "--run-id",
        run_id,
        "--scratch-dir",
        str(paths.scratch_dir),
        "--reports-dir",
        str(paths.reports_dir),
    ])
    if scope_notes_path:
        command.extend(["--scope-notes", str(scope_notes_path)])
    _append_option(command, "--max-tokens", options.max_tokens)
    _append_option(command, "--max-concurrency", options.max_concurrency)
    _append_option(command, "--max-recon-tasks", options.max_recon_tasks)
    _append_option(command, "--reasoning-effort", options.reasoning_effort)
    _append_option(command, "--target-url", options.target_url)
    for credential in options.target_creds:
        _append_option(command, "--target-creds", credential)
    _append_option(command, "--config", options.config_path)
    _append_option(command, "--provider", options.provider)
    if options.allow_api_key:
        command.append("--allow-api-key")
    return command


def build_vuln_campaign_command(
    *,
    repo_path: Path,
    run_id: str,
    paths: ProjectPaths,
    targeted_scope_notes_path: Path | None,
    options: VulnRunOptions,
) -> list[str]:
    """Build the existing vuln-hunter campaign run command."""
    if options.runs is None:
        raise AssessmentError("--runs is required when --vuln-mode campaign")

    command = _base_vuln_command(options.vuln_command)
    command.extend([
        "campaign",
        "run",
        "--repo",
        str(repo_path),
        "--campaign-id",
        run_id,
        "--runs",
        str(options.runs),
        "--stop-after-empty",
        str(options.stop_after_empty),
        "--scratch-dir",
        str(paths.scratch_dir),
        "--reports-dir",
        str(paths.reports_dir),
    ])
    _append_option(command, "--max-tokens", options.max_tokens)
    _append_option(command, "--max-concurrency", options.max_concurrency)
    _append_option(command, "--max-recon-tasks", options.max_recon_tasks)
    _append_option(command, "--reasoning-effort", options.reasoning_effort)
    _append_option(command, "--target-url", options.target_url)
    for credential in options.target_creds:
        _append_option(command, "--target-creds", credential)
    if options.scope_notes_path:
        _append_option(command, "--scope-notes", options.scope_notes_path)
    if targeted_scope_notes_path:
        _append_option(command, "--targeted-scope-notes", targeted_scope_notes_path)
        _append_option(command, "--targeted-scope-runs", options.threat_scope_runs)
    for seed_run_id in options.seed_run_ids:
        _append_option(command, "--seed-run-id", seed_run_id)
    _append_option(command, "--config", options.config_path)
    _append_option(command, "--provider", options.provider)
    if options.allow_api_key:
        command.append("--allow-api-key")
    return command


def _validate_vuln_options(options: VulnRunOptions) -> None:
    if options.vuln_mode not in {"run", "campaign"}:
        raise AssessmentError("vuln_mode must be 'run' or 'campaign'")
    if options.threat_scope_runs < 0:
        raise AssessmentError("--threat-scope-runs must be >= 0")
    if options.vuln_mode == "run":
        if options.threat_scope_runs > 1:
            raise AssessmentError("--threat-scope-runs cannot exceed 1 in run mode")
        return
    if options.runs is None:
        raise AssessmentError("--runs is required when --vuln-mode campaign")
    if options.threat_scope_runs > options.runs:
        raise AssessmentError("--threat-scope-runs cannot exceed --runs")


def _expected_vuln_report_path(
    *,
    reports_dir: Path,
    run_id: str,
    vuln_mode: str,
) -> Path:
    if vuln_mode == "campaign":
        return reports_dir / run_id / "campaign.report.json"
    return reports_dir / run_id / "vuln-hunter.report.json"


def _base_vuln_command(vuln_command: str | None) -> list[str]:
    if vuln_command:
        command = shlex.split(vuln_command)
        if not command:
            raise AssessmentError("--vuln-command cannot be empty")
        return command
    return [
        "uv",
        "run",
        "--project",
        str(PROJECT_ROOT / "vuln-hunter"),
        "vuln-hunter",
    ]


def _append_option(command: list[str], name: str, value: object | None) -> None:
    if value is not None:
        command.extend([name, str(value)])
