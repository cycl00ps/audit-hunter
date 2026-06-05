"""Deterministic repository profiling and STRIDE threat-model artifacts."""

from __future__ import annotations

import json
import os
import re
import shutil
import tomllib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


ARTIFACT_DIR_NAME = ".audit-hunter"
THREAT_MODEL_FILENAME = "threat-model.md"
SECURITY_CONFIG_FILENAME = "security-config.json"

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
) -> ThreatModelArtifacts:
    """Generate threat-model artifacts in the target repo and copy them to reports."""
    repo_path = repo_path.expanduser().resolve()
    if not repo_path.is_dir():
        raise ThreatModelError(f"repo path is not a directory: {repo_path}")

    profile = profile_repository(repo_path)
    target_dir = repo_path / ARTIFACT_DIR_NAME
    target_dir.mkdir(parents=True, exist_ok=True)

    threat_model_path = target_dir / THREAT_MODEL_FILENAME
    security_config_path = target_dir / SECURITY_CONFIG_FILENAME
    threat_model_path.write_text(_render_threat_model(profile))
    security_config_path.write_text(
        json.dumps(_build_security_config(profile), indent=2) + "\n"
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
) -> ThreatModelArtifacts:
    """Generate or reuse target threat-model artifacts, then copy them to reports."""
    repo_path = repo_path.expanduser().resolve()
    if skip_generation:
        _validate_target_artifacts(repo_path)
        return copy_threat_artifacts_to_reports(
            repo_path=repo_path,
            run_id=run_id,
            reports_dir=reports_dir,
        )
    return generate_threat_model(
        repo_path=repo_path,
        run_id=run_id,
        reports_dir=reports_dir,
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
