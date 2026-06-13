"""Repository profiling and STRIDE threat-model artifacts."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import threading
import tomllib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable


ARTIFACT_DIR_NAME = ".audit-hunter"
THREAT_MODEL_FILENAME = "threat-model.md"
SECURITY_CONFIG_FILENAME = "security-config.json"
DEFAULT_THREAT_MODEL_MODE = "ai"
THREAT_MODEL_MODES = ("ai", "deterministic")
AI_PASS_MODES = ("one", "two")
AI_REASONING_EFFORTS = ("none", "low", "medium", "high", "xhigh")
DEFAULT_AI_UNDERSTANDING_MODEL = "gpt-5.5"
DEFAULT_AI_RENDER_MODEL = "gpt-5.4-mini"
DEFAULT_AI_REASONING_EFFORT = "xhigh"
DEFAULT_AI_TIMEOUT_SECONDS = 900

ProgressCallback = Callable[[str], None]

_SKIP_DIRS = {
    ".audit-hunter",
    ".git",
    ".hg",
    ".mypy_cache",
    ".next",
    ".nuxt",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
    "venv",
}
_TEXT_SUFFIXES = {
    ".c",
    ".cc",
    ".cs",
    ".css",
    ".go",
    ".h",
    ".html",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".sh",
    ".sql",
    ".swift",
    ".ts",
    ".tsx",
    ".xml",
    ".yaml",
    ".yml",
}
_ENTRY_NAMES = {
    "__main__.py",
    "app.py",
    "asgi.py",
    "cli.py",
    "main.go",
    "main.py",
    "manage.py",
    "server.js",
    "server.ts",
    "wsgi.py",
}
_CONFIG_PATTERNS = (
    "config",
    "settings",
    ".env",
    "secrets",
    "credentials",
    "docker-compose",
    "Dockerfile",
)
_ROUTE_PATTERNS = (
    "api",
    "controller",
    "handler",
    "route",
    "router",
    "view",
)
_DATA_PATTERNS = (
    "database",
    "db",
    "migration",
    "model",
    "repository",
    "schema",
    "store",
)


@dataclass(frozen=True)
class ThreatModelArtifacts:
    threat_model_path: Path
    security_config_path: Path
    report_threat_model_path: Path
    report_security_config_path: Path


@dataclass(frozen=True)
class AIThreatModelOptions:
    passes: str = "two"
    understanding_model: str = DEFAULT_AI_UNDERSTANDING_MODEL
    render_model: str = DEFAULT_AI_RENDER_MODEL
    reasoning_effort: str | None = DEFAULT_AI_REASONING_EFFORT
    timeout_seconds: int = DEFAULT_AI_TIMEOUT_SECONDS
    codex_path: str | None = None


@dataclass(frozen=True)
class ThreatModelOptions:
    mode: str = DEFAULT_THREAT_MODEL_MODE
    edit: bool = False
    editor: str | None = None
    ai: AIThreatModelOptions = field(default_factory=AIThreatModelOptions)
    artifact_dir: Path | None = None
    progress: ProgressCallback | None = field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class RepositoryProfile:
    name: str
    repo_path: Path
    generated_at: str
    files: list[Path]
    tech_stack: list[str]
    entry_points: list[str]
    route_files: list[str]
    config_files: list[str]
    data_files: list[str]
    auth_indicators: list[str]
    excluded_paths: list[str]


class ThreatModelError(RuntimeError):
    """Raised when threat-model artifacts cannot be generated or reused."""


def generate_threat_model(
    *,
    repo_path: Path,
    run_id: str,
    reports_dir: Path,
    options: ThreatModelOptions | None = None,
) -> ThreatModelArtifacts:
    """Generate threat-model artifacts in the target repo and copy them to reports."""
    repo_path = repo_path.expanduser().resolve()
    if not repo_path.is_dir():
        raise ThreatModelError(f"repo path is not a directory: {repo_path}")
    options = _normalize_options(options)

    target_dir = repo_path / ARTIFACT_DIR_NAME
    target_dir.mkdir(parents=True, exist_ok=True)

    threat_model_path = target_dir / THREAT_MODEL_FILENAME
    security_config_path = target_dir / SECURITY_CONFIG_FILENAME
    _emit_progress(options.progress, f"generating threat model with {options.mode} mode")
    if options.mode == "deterministic":
        profile = profile_repository(repo_path)
        threat_model_text = _render_threat_model(profile)
        security_config = _build_security_config(profile)
    elif options.mode == "ai":
        threat_model_text, security_config = _generate_ai_threat_model(
            repo_path=repo_path,
            run_id=run_id,
            reports_dir=reports_dir,
            options=options,
        )
    else:
        raise ThreatModelError(
            f"unknown threat-model mode {options.mode!r}; expected one of {THREAT_MODEL_MODES}"
        )

    _validate_threat_model_markdown(threat_model_text)
    _validate_security_config_payload(security_config)
    threat_model_path.write_text(threat_model_text.rstrip() + "\n")
    security_config_path.write_text(json.dumps(security_config, indent=2) + "\n")
    _maybe_edit_threat_model(
        threat_model_path=threat_model_path,
        options=options,
    )
    return copy_threat_artifacts_to_reports(
        repo_path=repo_path,
        run_id=run_id,
        reports_dir=reports_dir,
    )


def ensure_threat_artifacts(
    *,
    repo_path: Path,
    run_id: str,
    reports_dir: Path,
    skip_generation: bool,
    options: ThreatModelOptions | None = None,
) -> ThreatModelArtifacts:
    """Generate or reuse target threat-model artifacts, then copy them to reports."""
    repo_path = repo_path.expanduser().resolve()
    options = _normalize_options(options)
    if skip_generation:
        _validate_target_artifacts(repo_path)
        _maybe_edit_threat_model(
            threat_model_path=repo_path / ARTIFACT_DIR_NAME / THREAT_MODEL_FILENAME,
            options=options,
        )
        return copy_threat_artifacts_to_reports(
            repo_path=repo_path,
            run_id=run_id,
            reports_dir=reports_dir,
        )
    return generate_threat_model(
        repo_path=repo_path,
        run_id=run_id,
        reports_dir=reports_dir,
        options=options,
    )


def copy_threat_artifacts_to_reports(
    *,
    repo_path: Path,
    run_id: str,
    reports_dir: Path,
) -> ThreatModelArtifacts:
    """Copy target threat-model artifacts into the run reports directory."""
    repo_path = repo_path.expanduser().resolve()
    _validate_target_artifacts(repo_path)

    source_threat = repo_path / ARTIFACT_DIR_NAME / THREAT_MODEL_FILENAME
    source_config = repo_path / ARTIFACT_DIR_NAME / SECURITY_CONFIG_FILENAME
    report_dir = reports_dir / run_id
    report_dir.mkdir(parents=True, exist_ok=True)
    report_threat = report_dir / THREAT_MODEL_FILENAME
    report_config = report_dir / SECURITY_CONFIG_FILENAME
    shutil.copyfile(source_threat, report_threat)
    shutil.copyfile(source_config, report_config)
    return ThreatModelArtifacts(
        threat_model_path=source_threat,
        security_config_path=source_config,
        report_threat_model_path=report_threat,
        report_security_config_path=report_config,
    )


def profile_repository(repo_path: Path) -> RepositoryProfile:
    """Build a lightweight static profile used by the deterministic model."""
    repo_path = repo_path.expanduser().resolve()
    files = _iter_repo_files(repo_path)
    rel_files = [path.relative_to(repo_path) for path in files]
    return RepositoryProfile(
        name=repo_path.name,
        repo_path=repo_path,
        generated_at=datetime.now().astimezone().replace(microsecond=0).isoformat(),
        files=rel_files,
        tech_stack=_detect_tech_stack(repo_path, rel_files),
        entry_points=_detect_entry_points(rel_files),
        route_files=_select_matching_paths(rel_files, _ROUTE_PATTERNS, limit=12),
        config_files=_select_matching_paths(rel_files, _CONFIG_PATTERNS, limit=12),
        data_files=_select_matching_paths(rel_files, _DATA_PATTERNS, limit=12),
        auth_indicators=_detect_auth_indicators(repo_path, rel_files),
        excluded_paths=_detect_excluded_paths(repo_path),
    )


def _validate_target_artifacts(repo_path: Path) -> None:
    missing = [
        path for path in (
            repo_path / ARTIFACT_DIR_NAME / THREAT_MODEL_FILENAME,
            repo_path / ARTIFACT_DIR_NAME / SECURITY_CONFIG_FILENAME,
        )
        if not path.exists()
    ]
    if missing:
        formatted = ", ".join(str(path) for path in missing)
        raise ThreatModelError(
            "missing threat model artifacts; run without --skip-threat-model "
            f"or create them first: {formatted}"
        )

    config_path = repo_path / ARTIFACT_DIR_NAME / SECURITY_CONFIG_FILENAME
    try:
        json.loads(config_path.read_text())
    except json.JSONDecodeError as e:
        raise ThreatModelError(f"invalid security config JSON at {config_path}: {e}") from e


def _normalize_options(options: ThreatModelOptions | None) -> ThreatModelOptions:
    if options is None:
        options = ThreatModelOptions()

    mode = options.mode.strip().lower()
    if mode not in THREAT_MODEL_MODES:
        raise ThreatModelError(
            f"unknown threat-model mode {options.mode!r}; expected one of {THREAT_MODEL_MODES}"
        )

    passes = options.ai.passes.strip().lower()
    if passes not in AI_PASS_MODES:
        raise ThreatModelError(
            f"unknown AI pass mode {options.ai.passes!r}; expected one of {AI_PASS_MODES}"
        )
    reasoning_effort = options.ai.reasoning_effort
    if reasoning_effort is not None:
        reasoning_effort = reasoning_effort.strip().lower()
        if reasoning_effort == "":
            reasoning_effort = None
        elif reasoning_effort not in AI_REASONING_EFFORTS:
            raise ThreatModelError(
                "--ai-reasoning-effort must be one of "
                f"{AI_REASONING_EFFORTS}"
            )
    if options.ai.timeout_seconds < 1:
        raise ThreatModelError("AI threat-model timeout must be at least 1 second")

    return ThreatModelOptions(
        mode=mode,
        edit=options.edit,
        editor=options.editor,
        ai=AIThreatModelOptions(
            passes=passes,
            understanding_model=options.ai.understanding_model,
            render_model=options.ai.render_model,
            reasoning_effort=reasoning_effort,
            timeout_seconds=options.ai.timeout_seconds,
            codex_path=options.ai.codex_path,
        ),
        artifact_dir=options.artifact_dir,
        progress=options.progress,
    )


def _generate_ai_threat_model(
    *,
    repo_path: Path,
    run_id: str,
    reports_dir: Path,
    options: ThreatModelOptions,
) -> tuple[str, dict[str, Any]]:
    profile = profile_repository(repo_path)
    artifact_dir = _ai_artifact_dir(
        reports_dir=reports_dir,
        run_id=run_id,
        options=options,
    )
    artifact_dir.mkdir(parents=True, exist_ok=True)
    seed_context = _profile_to_ai_seed(profile)
    (artifact_dir / "threat-model-profile-seed.json").write_text(
        json.dumps(seed_context, indent=2) + "\n"
    )

    if options.ai.passes == "two":
        _emit_progress(
            options.progress,
            f"AI understanding pass starting with model {options.ai.understanding_model}",
        )
        understanding_text = _run_codex_stage(
            repo_path=repo_path,
            artifact_dir=artifact_dir,
            stage_name="understanding",
            model=options.ai.understanding_model,
            reasoning_effort=options.ai.reasoning_effort,
            timeout_seconds=options.ai.timeout_seconds,
            codex_path=options.ai.codex_path,
            prompt=_build_understanding_prompt(seed_context),
            progress=options.progress,
        )
        understanding = _extract_json_object(understanding_text)
        (artifact_dir / "threat-model-understanding.json").write_text(
            json.dumps(understanding, indent=2, ensure_ascii=False) + "\n"
        )
        render_input: dict[str, Any] = {
            "deterministic_profile": seed_context,
            "ai_understanding": understanding,
        }
        stage_name = "render"
    else:
        render_input = {
            "deterministic_profile": seed_context,
            "ai_understanding": None,
        }
        stage_name = "single-pass"

    _emit_progress(
        options.progress,
        f"AI render pass starting with model {options.ai.render_model}",
    )
    render_text = _run_codex_stage(
        repo_path=repo_path,
        artifact_dir=artifact_dir,
        stage_name=stage_name,
        model=options.ai.render_model,
        reasoning_effort=options.ai.reasoning_effort,
        timeout_seconds=options.ai.timeout_seconds,
        codex_path=options.ai.codex_path,
        prompt=_build_render_prompt(
            repo_name=profile.name,
            generated_at=profile.generated_at,
            render_input=render_input,
        ),
        progress=options.progress,
    )
    payload = _extract_json_object(render_text)
    threat_model_text, security_config = _coerce_ai_render_payload(
        payload=payload,
        generated_at=profile.generated_at,
    )
    (artifact_dir / "threat-model-rendered.json").write_text(
        json.dumps(
            {
                "threat_model_markdown": threat_model_text,
                "security_config": security_config,
            },
            indent=2,
            ensure_ascii=False,
        ) + "\n"
    )
    return threat_model_text, security_config


def _profile_to_ai_seed(profile: RepositoryProfile) -> dict[str, Any]:
    files = [str(path) for path in profile.files]
    return {
        "repo_name": profile.name,
        "generated_at": profile.generated_at,
        "file_count": len(files),
        "files_sample": files[:400],
        "tech_stack": profile.tech_stack,
        "entry_points": profile.entry_points,
        "route_files": profile.route_files,
        "config_files": profile.config_files,
        "data_files": profile.data_files,
        "auth_indicators": profile.auth_indicators,
        "excluded_paths": profile.excluded_paths,
    }


def _ai_artifact_dir(
    *,
    reports_dir: Path,
    run_id: str,
    options: ThreatModelOptions,
) -> Path:
    if options.artifact_dir is not None:
        return options.artifact_dir.expanduser().resolve()
    return reports_dir.expanduser().resolve() / run_id / "audit-hunter-ai"


def _build_understanding_prompt(seed_context: dict[str, Any]) -> str:
    return (
        "# Task\n\n"
        "Inspect this local repository and build a concise security architecture "
        "understanding for a STRIDE threat model. Read as many repository files "
        "as required to understand purpose, entry points, trust boundaries, data "
        "stores, auth, and sensitive assets. Do not modify files. Prefer concrete "
        "file paths, routes, commands, functions, config names, and framework "
        "concepts over generic labels.\n\n"
        "As you work, keep progress updates brief and concrete. Your final answer "
        "must be only a JSON object with this shape:\n\n"
        "{"
        "\"repo_purpose\":\"...\","
        "\"components\":[{\"name\":\"...\",\"purpose\":\"...\",\"security_criticality\":\"HIGH|MEDIUM|LOW\",\"entry_points\":[\"...\"]}],"
        "\"data_flows\":[\"...\"],"
        "\"trust_boundaries\":{\"public\":\"...\",\"authenticated\":\"...\",\"privileged\":\"...\",\"internal\":\"...\"},"
        "\"auth_mechanism\":\"...\","
        "\"sensitive_assets\":[\"...\"],"
        "\"stride_risks\":[{\"category\":\"S|T|R|I|D|E\",\"threat\":\"...\",\"components\":[\"...\"],\"severity\":\"CRITICAL|HIGH|MEDIUM|LOW\",\"evidence\":[\"...\"]}],"
        "\"excluded_paths\":[\"...\"],"
        "\"tech_stack\":[\"...\"],"
        "\"assumptions\":[\"...\"],"
        "\"files_inspected\":[\"...\"]"
        "}.\n\n"
        "# Static seed context\n\n"
        f"```json\n{json.dumps(seed_context, ensure_ascii=False)}\n```\n"
    )


def _build_render_prompt(
    *,
    repo_name: str,
    generated_at: str,
    render_input: dict[str, Any],
) -> str:
    return (
        "# Task\n\n"
        "Generate the final audit-hunter STRIDE threat-model artifacts for this "
        "repository. If ai_understanding is null, first inspect repository files "
        "as needed. Keep the existing output format exactly: same Markdown "
        "section order and same security-config JSON shape. Do not modify files. "
        "Your final answer must be only a JSON object with keys "
        "`threat_model_markdown` and `security_config`.\n\n"
        "# Markdown format\n\n"
        f"# Threat Model for {repo_name}\n\n"
        f"**Generated:** {generated_at}\n"
        "**Version:** 1.0.0\n"
        "**Methodology:** STRIDE\n\n"
        "## 1. System Overview\n\n"
        "Include a 2-3 sentence system description.\n\n"
        "### Key Components\n\n"
        "| Component | Purpose | Security Criticality | Entry Points |\n"
        "|-----------|---------|---------------------|--------------|\n"
        "| ... | ... | HIGH/MEDIUM/LOW | ... |\n\n"
        "### Data Flow\n\n"
        "Describe how data moves from input through processing to storage/output.\n\n"
        "## 2. Trust Boundaries\n\n"
        "**Zone 1 - Public:** ...\n"
        "**Zone 2 - Authenticated:** ...\n"
        "**Zone 3 - Privileged:** ...\n"
        "**Zone 4 - Internal:** ...\n\n"
        "**Auth mechanism:** ...\n\n"
        "## 3. STRIDE Threat Analysis\n\n"
        "For each STRIDE subsection, include either a concrete threat block or "
        "`No material ... threat identified from inspected code.` Concrete "
        "threat blocks must include Threat, Components, Attack vector, Severity, "
        "Existing mitigations, and Gaps.\n\n"
        "### S - Spoofing Identity\n"
        "### T - Tampering with Data\n"
        "### R - Repudiation\n"
        "### I - Information Disclosure\n"
        "### D - Denial of Service\n"
        "### E - Elevation of Privilege\n\n"
        "## 4. Vulnerability Pattern Library\n\n"
        "Include a detected stack heading plus Vulnerable and Safe code blocks.\n\n"
        "## 5. Assumptions & Accepted Risks\n\n"
        "Use a short numbered list.\n\n"
        "# security_config shape\n\n"
        "{"
        "\"version\":\"1.0.0\","
        f"\"generated\":\"{generated_at}\","
        "\"severity_thresholds\":{\"block_merge\":\"CRITICAL\",\"require_review\":\"HIGH\",\"inform\":\"MEDIUM\"},"
        "\"confidence_threshold\":0.8,"
        "\"excluded_paths\":[\"test/\",\"tests/\",\"docs/\",\"scripts/\"],"
        "\"tech_stack\":[\"...\"],"
        "\"artifact_root\":\".audit-hunter\""
        "}\n\n"
        "# Repository context\n\n"
        f"```json\n{json.dumps(render_input, ensure_ascii=False)}\n```\n"
    )


def _run_codex_stage(
    *,
    repo_path: Path,
    artifact_dir: Path,
    stage_name: str,
    model: str,
    reasoning_effort: str | None,
    timeout_seconds: int,
    codex_path: str | None,
    prompt: str,
    progress: ProgressCallback | None,
) -> str:
    codex = codex_path or shutil.which("codex") or "codex"
    safe_stage = stage_name.replace("/", "-")
    output_last_message = artifact_dir / f"threat-model-{safe_stage}.last.txt"
    stdout_path = artifact_dir / f"threat-model-{safe_stage}.stdout.jsonl"
    stderr_path = artifact_dir / f"threat-model-{safe_stage}.stderr.txt"
    command_path = artifact_dir / f"threat-model-{safe_stage}.command.json"
    cmd = [
        codex,
        "exec",
        "--model",
        model,
    ]
    if reasoning_effort is not None:
        cmd.extend(["-c", f'model_reasoning_effort="{reasoning_effort}"'])
    cmd.extend([
        "--json",
        "--output-last-message",
        str(output_last_message),
        "-C",
        str(repo_path),
        "--sandbox",
        "read-only",
        "--skip-git-repo-check",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "-",
    ])
    command_path.write_text(json.dumps({"argv": cmd}, indent=2) + "\n")

    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    events: list[dict[str, Any]] = []
    lock = threading.Lock()
    _emit_progress(progress, f"{stage_name}: launching Codex")
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=repo_path,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as e:
        raise ThreatModelError(
            "Codex CLI was not found; install codex or pass --codex-path, "
            "or use deterministic threat-model mode"
        ) from e

    def read_stdout() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            stdout_chunks.append(line)
            event = _parse_json_line(line)
            if event is None:
                continue
            with lock:
                events.append(event)
            message = _codex_progress_message(event)
            if message:
                _emit_progress(progress, f"{stage_name}: {message}")

    def read_stderr() -> None:
        assert proc.stderr is not None
        for line in proc.stderr:
            stderr_chunks.append(line)

    stdout_thread = threading.Thread(target=read_stdout, daemon=True)
    stderr_thread = threading.Thread(target=read_stderr, daemon=True)
    stdout_thread.start()
    stderr_thread.start()
    assert proc.stdin is not None
    try:
        proc.stdin.write(prompt)
        proc.stdin.close()
        returncode = proc.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as e:
        proc.kill()
        returncode = proc.wait()
        raise ThreatModelError(
            f"Codex {stage_name} pass timed out after {timeout_seconds} seconds"
        ) from e
    finally:
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)
        stdout_path.write_text("".join(stdout_chunks))
        stderr_path.write_text("".join(stderr_chunks))

    if returncode != 0:
        details = "\n".join(
            text for text in ("".join(stderr_chunks).strip(), "".join(stdout_chunks)[-2000:].strip())
            if text
        )
        raise ThreatModelError(
            f"Codex {stage_name} pass failed with exit code {returncode}: "
            f"{details[:1000]}"
        )

    if output_last_message.exists():
        final_text = output_last_message.read_text()
    else:
        final_text = _last_codex_message_text(events) or "".join(stdout_chunks)
    _emit_progress(progress, f"{stage_name}: Codex completed")
    return final_text


def _parse_json_line(line: str) -> dict[str, Any] | None:
    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _codex_progress_message(event: dict[str, Any]) -> str | None:
    for key in ("message", "text", "last_message", "output"):
        value = event.get(key)
        if isinstance(value, str) and value.strip():
            return _shorten(value.strip())
    msg = event.get("msg")
    if isinstance(msg, dict):
        for key in ("message", "text", "output"):
            value = msg.get(key)
            if isinstance(value, str) and value.strip():
                return _shorten(value.strip())
    event_type = event.get("type") or event.get("event") or event.get("kind")
    if isinstance(event_type, str) and event_type.strip():
        return _shorten(event_type.strip().replace("_", " "))
    return None


def _last_codex_message_text(events: list[dict[str, Any]]) -> str | None:
    for event in reversed(events):
        for key in ("message", "text", "last_message", "output"):
            value = event.get(key)
            if isinstance(value, str) and value.strip():
                return value
        msg = event.get("msg")
        if isinstance(msg, dict):
            for key in ("message", "text", "output"):
                value = msg.get(key)
                if isinstance(value, str) and value.strip():
                    return value
    return None


def _extract_json_object(text: str) -> dict[str, Any]:
    text = text.strip()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end < start:
            raise ThreatModelError("AI threat-model output did not contain JSON") from None
        try:
            payload = json.loads(text[start : end + 1])
        except json.JSONDecodeError as e:
            raise ThreatModelError(f"AI threat-model output was invalid JSON: {e}") from e
    if not isinstance(payload, dict):
        raise ThreatModelError("AI threat-model output must be a JSON object")
    return payload


def _coerce_ai_render_payload(
    *,
    payload: dict[str, Any],
    generated_at: str,
) -> tuple[str, dict[str, Any]]:
    threat_model_text = payload.get("threat_model_markdown")
    if not isinstance(threat_model_text, str):
        threat_model_text = payload.get("threat_model")
    if not isinstance(threat_model_text, str):
        threat_model_text = payload.get("markdown")
    if not isinstance(threat_model_text, str) or not threat_model_text.strip():
        raise ThreatModelError("AI output missing threat_model_markdown")

    security_config = payload.get("security_config")
    if not isinstance(security_config, dict):
        security_config = payload.get("security-config")
    if not isinstance(security_config, dict):
        raise ThreatModelError("AI output missing security_config object")
    security_config = dict(security_config)
    security_config.setdefault("version", "1.0.0")
    security_config.setdefault("generated", generated_at)
    security_config["artifact_root"] = ARTIFACT_DIR_NAME
    return threat_model_text, security_config


def _validate_threat_model_markdown(text: str) -> None:
    required = [
        "# Threat Model for ",
        "**Generated:**",
        "**Version:** 1.0.0",
        "**Methodology:** STRIDE",
        "## 1. System Overview",
        "### Key Components",
        "### Data Flow",
        "## 2. Trust Boundaries",
        "## 3. STRIDE Threat Analysis",
        "### S - Spoofing Identity",
        "### T - Tampering with Data",
        "### R - Repudiation",
        "### I - Information Disclosure",
        "### D - Denial of Service",
        "### E - Elevation of Privilege",
        "## 4. Vulnerability Pattern Library",
        "## 5. Assumptions & Accepted Risks",
    ]
    cursor = -1
    for marker in required:
        idx = text.find(marker)
        if idx < 0:
            raise ThreatModelError(f"threat model is missing required section: {marker}")
        if idx < cursor:
            raise ThreatModelError(
                f"threat model section is out of order: {marker}"
            )
        cursor = idx


def _validate_security_config_payload(payload: dict[str, Any]) -> None:
    required = {
        "version",
        "generated",
        "severity_thresholds",
        "confidence_threshold",
        "excluded_paths",
        "tech_stack",
        "artifact_root",
    }
    missing = sorted(required - set(payload))
    if missing:
        raise ThreatModelError(
            "security config missing required field(s): " + ", ".join(missing)
        )
    if payload["artifact_root"] != ARTIFACT_DIR_NAME:
        raise ThreatModelError(
            f"security config artifact_root must be {ARTIFACT_DIR_NAME!r}"
        )
    if not isinstance(payload["severity_thresholds"], dict):
        raise ThreatModelError("security config severity_thresholds must be an object")
    for key in ("block_merge", "require_review", "inform"):
        if not isinstance(payload["severity_thresholds"].get(key), str):
            raise ThreatModelError(
                f"security config severity_thresholds.{key} must be a string"
            )
    if not isinstance(payload["confidence_threshold"], int | float):
        raise ThreatModelError("security config confidence_threshold must be numeric")
    if not 0 <= float(payload["confidence_threshold"]) <= 1:
        raise ThreatModelError("security config confidence_threshold must be between 0 and 1")
    for key in ("excluded_paths", "tech_stack"):
        value = payload[key]
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ThreatModelError(f"security config {key} must be a list of strings")


def _maybe_edit_threat_model(
    *,
    threat_model_path: Path,
    options: ThreatModelOptions,
) -> None:
    if not options.edit:
        return
    editor = options.editor or os.environ.get("VISUAL") or os.environ.get("EDITOR") or "vi"
    command = shlex.split(editor)
    if not command:
        raise ThreatModelError("editor command cannot be empty")
    command.append(str(threat_model_path))
    _emit_progress(options.progress, f"opening editor for {threat_model_path}")
    completed = subprocess.run(command, check=False)
    if completed.returncode != 0:
        raise ThreatModelError(
            f"editor exited with code {completed.returncode}; threat model was not accepted"
        )
    _validate_threat_model_markdown(threat_model_path.read_text())
    _emit_progress(options.progress, "edited threat model accepted")


def _emit_progress(progress: ProgressCallback | None, message: str) -> None:
    if progress is not None:
        progress(message)


def _shorten(text: str, *, limit: int = 160) -> str:
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _iter_repo_files(repo_path: Path, *, limit: int = 5000) -> list[Path]:
    files: list[Path] = []
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [
            dirname for dirname in dirs
            if dirname not in _SKIP_DIRS and not dirname.endswith(".egg-info")
        ]
        for filename in filenames:
            path = Path(root) / filename
            try:
                if path.is_file():
                    files.append(path)
            except OSError:
                continue
            if len(files) >= limit:
                return sorted(files)
    return sorted(files)


def _detect_tech_stack(repo_path: Path, files: list[Path]) -> list[str]:
    tech: list[str] = []
    names = {str(path) for path in files}
    top_names = {path.name for path in files}

    if "pyproject.toml" in top_names or any(path.name.startswith("requirements") for path in files):
        tech.append("Python")
        deps = _python_dependencies(repo_path)
        tech.extend(_dependency_tech(deps, {
            "django": "Django",
            "fastapi": "FastAPI",
            "flask": "Flask",
            "click": "Click CLI",
            "typer": "Typer CLI",
            "sqlalchemy": "SQLAlchemy",
            "pydantic": "Pydantic",
        }))
    if "package.json" in top_names:
        tech.append("Node.js")
        deps = _package_json_dependencies(repo_path / "package.json")
        tech.extend(_dependency_tech(deps, {
            "@nestjs/core": "NestJS",
            "express": "Express",
            "fastify": "Fastify",
            "next": "Next.js",
            "react": "React",
            "vue": "Vue",
        }))
    if "go.mod" in top_names:
        tech.append("Go")
    if "Cargo.toml" in top_names:
        tech.append("Rust")
    if "pom.xml" in top_names:
        tech.append("Java/Maven")
    if "build.gradle" in top_names or "build.gradle.kts" in top_names:
        tech.append("JVM/Gradle")
    if "Gemfile" in top_names:
        tech.append("Ruby")
    if "composer.json" in top_names:
        tech.append("PHP/Composer")
    if "Dockerfile" in top_names or any(name.endswith("/Dockerfile") for name in names):
        tech.append("Docker")
    if any(path.name.startswith("docker-compose") for path in files):
        tech.append("Docker Compose")
    if any(path.suffix == ".tf" for path in files):
        tech.append("Terraform")
    if any(path.suffix == ".csproj" for path in files):
        tech.append(".NET")

    if not tech:
        suffixes = {path.suffix for path in files}
        if ".py" in suffixes:
            tech.append("Python")
        elif ".js" in suffixes or ".ts" in suffixes:
            tech.append("JavaScript/TypeScript")
        elif ".go" in suffixes:
            tech.append("Go")
        else:
            tech.append("Unknown or mixed stack")
    return _dedupe(tech)


def _python_dependencies(repo_path: Path) -> set[str]:
    deps: set[str] = set()
    pyproject = repo_path / "pyproject.toml"
    if pyproject.exists():
        try:
            data = tomllib.loads(pyproject.read_text())
        except (tomllib.TOMLDecodeError, UnicodeDecodeError):
            data = {}
        project = data.get("project", {})
        deps.update(_normalize_dep_name(dep) for dep in project.get("dependencies", []))
        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        if isinstance(poetry_deps, dict):
            deps.update(str(name).lower() for name in poetry_deps)

    for req in repo_path.glob("requirements*.txt"):
        try:
            for line in req.read_text().splitlines():
                cleaned = line.strip()
                if cleaned and not cleaned.startswith("#"):
                    deps.add(_normalize_dep_name(cleaned))
        except UnicodeDecodeError:
            continue
    return deps


def _package_json_dependencies(package_json: Path) -> set[str]:
    try:
        data = json.loads(package_json.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError, FileNotFoundError):
        return set()
    deps: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        value = data.get(key, {})
        if isinstance(value, dict):
            deps.update(str(name).lower() for name in value)
    return deps


def _dependency_tech(deps: set[str], mapping: dict[str, str]) -> list[str]:
    return [label for dep, label in mapping.items() if dep in deps]


def _normalize_dep_name(dep: str) -> str:
    return re.split(r"[<>=!~;\[]", dep, maxsplit=1)[0].strip().lower()


def _detect_entry_points(files: list[Path]) -> list[str]:
    entries: list[str] = []
    for path in files:
        path_text = str(path)
        if path.name in _ENTRY_NAMES:
            entries.append(path_text)
        elif path_text.startswith("cmd/") and path.name == "main.go":
            entries.append(path_text)
        elif path_text.startswith("src/main."):
            entries.append(path_text)
    if not entries:
        entries = [str(path) for path in files[:5]]
    return _dedupe(entries)[:12]


def _select_matching_paths(
    files: list[Path],
    patterns: tuple[str, ...],
    *,
    limit: int,
) -> list[str]:
    matches: list[str] = []
    for path in files:
        text = str(path).lower()
        if any(pattern in text for pattern in patterns):
            matches.append(str(path))
    return _dedupe(matches)[:limit]


def _detect_auth_indicators(repo_path: Path, files: list[Path]) -> list[str]:
    indicators: list[str] = []
    tokens = {
        "api_key": "API keys",
        "auth": "authentication code",
        "jwt": "JWT",
        "login": "login flow",
        "oauth": "OAuth/OIDC",
        "permission": "permission checks",
        "role": "role checks",
        "session": "sessions",
    }
    for path in files:
        path_text = str(path).lower()
        for token, label in tokens.items():
            if token in path_text:
                indicators.append(label)
        if path.suffix not in _TEXT_SUFFIXES:
            continue
        full_path = repo_path / path
        if _too_large(full_path):
            continue
        try:
            text = full_path.read_text(errors="ignore").lower()[:100_000]
        except OSError:
            continue
        for token, label in tokens.items():
            if token in text:
                indicators.append(label)
    return _dedupe(indicators)[:8]


def _detect_excluded_paths(repo_path: Path) -> list[str]:
    defaults = ["test/", "tests/", "docs/", "scripts/"]
    generated = [
        "dist/",
        "build/",
        "target/",
        "node_modules/",
        "vendor/",
        ".venv/",
        "venv/",
    ]
    excluded = [
        path for path in defaults + generated
        if (repo_path / path.rstrip("/")).exists()
    ]
    return excluded or defaults


def _too_large(path: Path, *, max_bytes: int = 1_000_000) -> bool:
    try:
        return path.stat().st_size > max_bytes
    except OSError:
        return True


def _render_threat_model(profile: RepositoryProfile) -> str:
    overview = _system_overview(profile)
    components = _components(profile)
    lines = [
        f"# Threat Model for {profile.name}",
        "",
        f"**Generated:** {profile.generated_at}",
        "**Version:** 1.0.0",
        "**Methodology:** STRIDE",
        "",
        "## 1. System Overview",
        "",
        overview,
        "",
        "### Key Components",
        "",
        "| Component | Purpose | Security Criticality | Entry Points |",
        "|-----------|---------|---------------------|--------------|",
    ]
    for component in components:
        lines.append(
            "| {name} | {purpose} | {criticality} | {entry_points} |".format(
                name=_cell(component["name"]),
                purpose=_cell(component["purpose"]),
                criticality=component["criticality"],
                entry_points=_cell(component["entry_points"]),
            )
        )

    lines.extend([
        "",
        "### Data Flow",
        "",
        _data_flow(profile),
        "",
        "## 2. Trust Boundaries",
        "",
        f"**Zone 1 - Public:** {_public_boundary(profile)}",
        f"**Zone 2 - Authenticated:** {_authenticated_boundary(profile)}",
        f"**Zone 3 - Privileged:** {_privileged_boundary(profile)}",
        f"**Zone 4 - Internal:** {_internal_boundary(profile)}",
        "",
        f"**Auth mechanism:** {_auth_mechanism(profile)}",
        "",
        "## 3. STRIDE Threat Analysis",
        "",
    ])
    lines.extend(_stride_sections(profile))
    lines.extend([
        "## 4. Vulnerability Pattern Library",
        "",
        f"### {_primary_stack(profile)} Patterns",
        "",
        "**Vulnerable:**",
        "```text",
        _vulnerable_pattern(profile),
        "```",
        "",
        "**Safe:**",
        "```text",
        _safe_pattern(profile),
        "```",
        "",
        "## 5. Assumptions & Accepted Risks",
        "",
        "1. This model is based on deterministic static profiling of the local repository.",
        "2. Dependencies, deployment settings, and runtime credentials were not executed or verified.",
        "3. Treat generated exclusions as audit guidance, not as a hard guarantee that those paths are safe.",
        "4. Accepted risk: the generated model is intentionally conservative and should be refined when project-specific context is known.",
        "",
    ])
    return "\n".join(lines)


def _build_security_config(profile: RepositoryProfile) -> dict[str, Any]:
    return {
        "version": "1.0.0",
        "generated": profile.generated_at,
        "severity_thresholds": {
            "block_merge": "CRITICAL",
            "require_review": "HIGH",
            "inform": "MEDIUM",
        },
        "confidence_threshold": 0.8,
        "excluded_paths": profile.excluded_paths,
        "tech_stack": profile.tech_stack,
        "artifact_root": ARTIFACT_DIR_NAME,
    }


def _system_overview(profile: RepositoryProfile) -> str:
    return (
        f"`{profile.name}` is a local repository containing "
        f"{', '.join(profile.tech_stack)} code. Key entry points include "
        f"{_format_paths(profile.entry_points)}. Security review should focus on "
        "how untrusted input, credentials, configuration, and persisted data move "
        "through those entry points."
    )


def _components(profile: RepositoryProfile) -> list[dict[str, str]]:
    components = [
        {
            "name": "Application entry points",
            "purpose": "Start the application, commands, jobs, or services.",
            "criticality": "HIGH",
            "entry_points": _format_paths(profile.entry_points),
        },
        {
            "name": "Configuration and secrets",
            "purpose": "Load runtime settings, credentials, deployment options, and local policy.",
            "criticality": "HIGH",
            "entry_points": _format_paths(profile.config_files),
        },
    ]
    if profile.route_files:
        components.append({
            "name": "HTTP/API surface",
            "purpose": "Accept remote or browser-originated requests.",
            "criticality": "HIGH",
            "entry_points": _format_paths(profile.route_files),
        })
    if profile.data_files:
        components.append({
            "name": "Persistence layer",
            "purpose": "Read, write, migrate, or model persisted data.",
            "criticality": "HIGH",
            "entry_points": _format_paths(profile.data_files),
        })
    components.append({
        "name": "Build and dependency metadata",
        "purpose": "Resolve dependencies, packaging, containers, and automation.",
        "criticality": "MEDIUM",
        "entry_points": _format_paths(_build_files(profile.files)),
    })
    return components


def _data_flow(profile: RepositoryProfile) -> str:
    public = "HTTP/API handlers" if profile.route_files else "CLI arguments, config files, and environment variables"
    persistence = _format_paths(profile.data_files) if profile.data_files else "local files, package metadata, or external services detected at runtime"
    return (
        f"Data enters through {public}, is processed by application entry points "
        f"such as {_format_paths(profile.entry_points)}, and may flow into "
        f"{persistence}. Configuration and secrets influence those flows through "
        f"{_format_paths(profile.config_files)}."
    )


def _public_boundary(profile: RepositoryProfile) -> str:
    if profile.route_files:
        return f"HTTP/API requests handled by {_format_paths(profile.route_files)}."
    return "CLI arguments, files from the working tree, environment variables, and external dependency inputs."


def _authenticated_boundary(profile: RepositoryProfile) -> str:
    if profile.auth_indicators:
        return f"Code paths associated with {', '.join(profile.auth_indicators)}."
    return "No explicit application authentication boundary was detected; treat operator or local-user context as the primary boundary."


def _privileged_boundary(profile: RepositoryProfile) -> str:
    return f"Configuration, deployment, dependency, and secret-bearing files such as {_format_paths(profile.config_files)}."


def _internal_boundary(profile: RepositoryProfile) -> str:
    stores = _format_paths(profile.data_files) if profile.data_files else "local filesystem, package manager, and runtime services"
    return f"Persistence and internal service boundaries represented by {stores}."


def _auth_mechanism(profile: RepositoryProfile) -> str:
    if profile.auth_indicators:
        return (
            f"Indicators found for {', '.join(profile.auth_indicators)}. "
            "Confirm enforcement at route, command, and data-access boundaries."
        )
    return "None clearly detected by static profiling. Confirm whether auth is external, unnecessary, or missing."


def _stride_sections(profile: RepositoryProfile) -> list[str]:
    sections = [
        ("S - Spoofing Identity", _spoofing(profile)),
        ("T - Tampering with Data", _tampering(profile)),
        ("R - Repudiation", _repudiation(profile)),
        ("I - Information Disclosure", _information_disclosure(profile)),
        ("D - Denial of Service", _denial_of_service(profile)),
        ("E - Elevation of Privilege", _elevation_of_privilege(profile)),
    ]
    lines: list[str] = []
    for title, body in sections:
        lines.extend([f"### {title}", "", body, ""])
    return lines


def _spoofing(profile: RepositoryProfile) -> str:
    if profile.auth_indicators:
        return _threat_block(
            "Authentication boundary bypass",
            "auth/session routes and data access paths",
            "Send requests or commands that skip or confuse identity checks, then access user-scoped data.",
            "HIGH",
            "Auth-related code was detected.",
            "Generated model cannot prove every entry point enforces identity consistently.",
        )
    return "No material spoofing threat identified from inspected code; verify external auth assumptions during manual review."


def _tampering(profile: RepositoryProfile) -> str:
    return _threat_block(
        "Configuration or dependency tampering",
        _format_paths(profile.config_files + _build_files(profile.files)),
        "Modify config, dependency metadata, or deployment inputs to alter runtime behavior or redirect sensitive data.",
        "HIGH",
        "Repository metadata and config files are visible for review.",
        "File ownership, CI integrity, dependency pinning, and runtime config provenance were not verified.",
    )


def _repudiation(profile: RepositoryProfile) -> str:
    return _threat_block(
        "Insufficient audit trail for sensitive actions",
        _format_paths(profile.entry_points + profile.route_files),
        "Perform a sensitive command or request and rely on missing or low-cardinality logs to avoid attribution.",
        "MEDIUM",
        "No runtime behavior was executed.",
        "Generated model cannot confirm durable, tamper-resistant, user-attributed audit logging.",
    )


def _information_disclosure(profile: RepositoryProfile) -> str:
    return _threat_block(
        "Secret or sensitive data exposure",
        _format_paths(profile.config_files + profile.data_files),
        "Read logs, reports, configs, generated files, or API responses that accidentally include credentials or private data.",
        "HIGH",
        "Secret scanning runs separately in this workflow.",
        "Static profiling cannot prove redaction, access control, or artifact retention safety.",
    )


def _denial_of_service(profile: RepositoryProfile) -> str:
    target = _format_paths(profile.route_files or profile.entry_points)
    return _threat_block(
        "Unbounded input or expensive processing",
        target,
        "Send large, malformed, repeated, or adversarial inputs through exposed entry points to exhaust CPU, memory, storage, or downstream quotas.",
        "MEDIUM",
        "Entry points were identified for focused testing.",
        "Rate limits, timeouts, queue bounds, and parser limits were not verified.",
    )


def _elevation_of_privilege(profile: RepositoryProfile) -> str:
    if profile.auth_indicators or profile.config_files:
        return _threat_block(
            "Privilege boundary confusion",
            _format_paths(profile.config_files + profile.route_files + profile.entry_points),
            "Reach privileged behavior through a lower-trust interface, unsafe config override, or missing authorization check.",
            "HIGH",
            "Auth and config indicators are included in the generated scope notes.",
            "Authorization semantics require targeted vuln-hunter and manual review.",
        )
    return "No material elevation-of-privilege threat identified from inspected code; verify deployment privileges manually."


def _threat_block(
    threat: str,
    components: str,
    attack_vector: str,
    severity: str,
    mitigations: str,
    gaps: str,
) -> str:
    return "\n".join([
        f"**Threat:** {threat}",
        f"**Components:** {components}",
        f"**Attack vector:** {attack_vector}",
        f"**Severity:** {severity}",
        f"**Existing mitigations:** {mitigations}",
        f"**Gaps:** {gaps}",
    ])


def _primary_stack(profile: RepositoryProfile) -> str:
    return profile.tech_stack[0] if profile.tech_stack else "Repository"


def _vulnerable_pattern(profile: RepositoryProfile) -> str:
    primary = _primary_stack(profile).lower()
    if "python" in primary:
        return "subprocess.run(user_input, shell=True)"
    if "go" in primary:
        return "exec.Command(\"sh\", \"-c\", userInput)"
    if "node" in primary or "javascript" in primary:
        return "db.query(`SELECT * FROM users WHERE id = ${req.query.id}`)"
    return "privileged_action(untrusted_input)"


def _safe_pattern(profile: RepositoryProfile) -> str:
    primary = _primary_stack(profile).lower()
    if "python" in primary:
        return "subprocess.run([\"tool\", validated_arg], shell=False, check=True)"
    if "go" in primary:
        return "exec.Command(\"tool\", validatedArg)"
    if "node" in primary or "javascript" in primary:
        return "db.query(\"SELECT * FROM users WHERE id = ?\", [validatedId])"
    return "privileged_action(validate_and_authorize(input))"


def _build_files(files: list[Path]) -> list[str]:
    matches = []
    for path in files:
        if path.name in {
            "Cargo.toml",
            "Dockerfile",
            "Gemfile",
            "build.gradle",
            "build.gradle.kts",
            "composer.json",
            "go.mod",
            "package.json",
            "pom.xml",
            "pyproject.toml",
        } or path.name.startswith("docker-compose"):
            matches.append(str(path))
    return _dedupe(matches)[:8]


def _format_paths(paths: list[str] | list[Path], *, limit: int = 5) -> str:
    values = [str(path) for path in paths if str(path)]
    if not values:
        return "not clearly detected"
    shown = values[:limit]
    suffix = f", and {len(values) - limit} more" if len(values) > limit else ""
    return ", ".join(f"`{value}`" for value in shown) + suffix


def _cell(value: str) -> str:
    return value.replace("\n", " ").replace("|", "\\|")


def _dedupe(values: list[str] | set[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result
