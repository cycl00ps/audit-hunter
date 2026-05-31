"""Run third-party secret scanners and write normalized reports."""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from audit_hunter_common.paths import ProjectPaths, ensure_project_dirs, resolve_tool
from audit_hunter_common.reporting import write_tool_report
from secret_hunter.ai import analyze_findings
from secret_hunter.parsers import dedupe_findings, parse_gitleaks, parse_trufflehog


TOOL_NAME = "secret-hunter"


def scan_repository(
    *,
    repo_path: Path,
    run_id: str,
    paths: ProjectPaths,
    trufflehog_path: str | Path | None = None,
    gitleaks_path: str | Path | None = None,
    ai_analysis: bool = True,
    verify: bool = True,
) -> Path:
    ensure_project_dirs(paths)
    repo_path = repo_path.resolve()
    artifact_dir = paths.artifacts_dir / run_id / TOOL_NAME
    artifact_dir.mkdir(parents=True, exist_ok=True)

    scanner_runs: list[dict[str, Any]] = []
    raw_findings: list[dict[str, Any]] = []

    trufflehog = resolve_tool("trufflehog", explicit_path=trufflehog_path, paths=paths)
    trufflehog_artifact = artifact_dir / "trufflehog.ndjson"
    run = _run_trufflehog(trufflehog, repo_path, trufflehog_artifact, verify=verify)
    scanner_runs.append(run)
    if run["status"] == "success":
        raw_findings.extend(parse_trufflehog(trufflehog_artifact))

    gitleaks = resolve_tool("gitleaks", explicit_path=gitleaks_path, paths=paths)
    gitleaks_artifact = artifact_dir / "gitleaks.json"
    run = _run_gitleaks(gitleaks, repo_path, gitleaks_artifact)
    scanner_runs.append(run)
    if run["status"] == "success":
        raw_findings.extend(parse_gitleaks(gitleaks_artifact))

    findings = dedupe_findings(raw_findings)
    analyze_findings(
        findings,
        repo_path=repo_path,
        artifact_dir=artifact_dir,
        enabled=ai_analysis,
    )

    payload = _build_report(
        run_id=run_id,
        repo_path=repo_path,
        scanner_runs=scanner_runs,
        findings=findings,
    )
    out_path = write_tool_report(
        payload,
        reports_dir=paths.reports_dir,
        run_id=run_id,
        tool_name=TOOL_NAME,
    )
    return out_path


def clone_repo(*, repo_url: str, run_id: str, paths: ProjectPaths) -> Path:
    paths.repos_dir.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^a-zA-Z0-9_.-]+", "-", repo_url.rstrip("/").split("/")[-1])
    if slug.endswith(".git"):
        slug = slug[:-4]
    dest = paths.repos_dir / f"{slug or 'repo'}-{run_id}"
    if dest.exists():
        raise RuntimeError(f"clone target already exists: {dest}")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, str(dest)],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "git clone failed")
    return dest.resolve()


def _run_trufflehog(
    binary: Path | None,
    repo_path: Path,
    artifact_path: Path,
    *,
    verify: bool,
) -> dict[str, Any]:
    if binary is None:
        return _scanner_unavailable("trufflehog")
    cmd = [str(binary), "filesystem", "--json", str(repo_path)]
    if not verify:
        cmd.insert(2, "--no-verification")
    return _run_stdout_scanner(
        scanner="trufflehog",
        cmd=cmd,
        artifact_path=artifact_path,
        acceptable_exit_codes={0},
    )


def _run_gitleaks(binary: Path | None, repo_path: Path, artifact_path: Path) -> dict[str, Any]:
    if binary is None:
        return _scanner_unavailable("gitleaks")
    cmd = [
        str(binary),
        "detect",
        "--source",
        str(repo_path),
        "--report-format",
        "json",
        "--report-path",
        str(artifact_path),
        "--redact",
        "--no-banner",
    ]
    return _run_file_scanner(
        scanner="gitleaks",
        cmd=cmd,
        artifact_path=artifact_path,
        acceptable_exit_codes={0, 1},
    )


def _run_stdout_scanner(
    *,
    scanner: str,
    cmd: list[str],
    artifact_path: Path,
    acceptable_exit_codes: set[int],
) -> dict[str, Any]:
    started = time.time()
    result = subprocess.run(cmd, text=True, capture_output=True, check=False)
    finished = time.time()
    artifact_path.write_text(result.stdout)
    stderr_path = artifact_path.with_suffix(artifact_path.suffix + ".stderr.txt")
    stderr_path.write_text(result.stderr)
    status = "success" if result.returncode in acceptable_exit_codes else "error"
    return {
        "scanner": scanner,
        "status": status,
        "command": _safe_command(cmd),
        "artifact_path": str(artifact_path),
        "stderr_path": str(stderr_path),
        "exit_code": result.returncode,
        "started_at": started,
        "finished_at": finished,
        "error": None if status == "success" else (result.stderr or result.stdout)[:1000],
    }


def _run_file_scanner(
    *,
    scanner: str,
    cmd: list[str],
    artifact_path: Path,
    acceptable_exit_codes: set[int],
) -> dict[str, Any]:
    started = time.time()
    result = subprocess.run(cmd, text=True, capture_output=True, check=False)
    finished = time.time()
    if not artifact_path.exists():
        artifact_path.write_text("[]")
    stdout_path = artifact_path.with_suffix(artifact_path.suffix + ".stdout.txt")
    stderr_path = artifact_path.with_suffix(artifact_path.suffix + ".stderr.txt")
    stdout_path.write_text(result.stdout)
    stderr_path.write_text(result.stderr)
    status = "success" if result.returncode in acceptable_exit_codes else "error"
    return {
        "scanner": scanner,
        "status": status,
        "command": _safe_command(cmd),
        "artifact_path": str(artifact_path),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "exit_code": result.returncode,
        "started_at": started,
        "finished_at": finished,
        "error": None if status == "success" else (result.stderr or result.stdout)[:1000],
    }


def _scanner_unavailable(scanner: str) -> dict[str, Any]:
    now = time.time()
    return {
        "scanner": scanner,
        "status": "unavailable",
        "command": [],
        "artifact_path": None,
        "exit_code": None,
        "started_at": now,
        "finished_at": now,
        "error": f"{scanner} binary not found in explicit path, bin/, or PATH",
    }


def _build_report(
    *,
    run_id: str,
    repo_path: Path,
    scanner_runs: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "tool": TOOL_NAME,
        "run_id": run_id,
        "target": {
            "repo_path": str(repo_path),
            "commit": _git_commit(repo_path),
        },
        "summary": _summary(findings),
        "scanner_runs": scanner_runs,
        "findings": findings,
    }


def _summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    by_verification: dict[str, int] = {}
    by_source: dict[str, int] = {}
    for finding in findings:
        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
        status = finding["verification"]["status"]
        by_verification[status] = by_verification.get(status, 0) + 1
        for source in finding["sources"]:
            by_source[source] = by_source.get(source, 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_verification": by_verification,
        "by_source": by_source,
    }


def _git_commit(repo_path: Path) -> str | None:
    if not (repo_path / ".git").exists() or shutil.which("git") is None:
        return None
    result = subprocess.run(
        ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def _safe_command(cmd: list[str]) -> list[str]:
    return [cmd[0], *cmd[1:]]
