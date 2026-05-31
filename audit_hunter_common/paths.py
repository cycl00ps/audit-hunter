"""Shared filesystem layout for audit-hunter tools."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class ProjectPaths:
    bin_dir: Path
    scratch_dir: Path
    reports_dir: Path

    @property
    def artifacts_dir(self) -> Path:
        return self.scratch_dir / "artifacts"

    @property
    def repos_dir(self) -> Path:
        return self.scratch_dir / "repos"

    @property
    def work_dir(self) -> Path:
        return self.scratch_dir / "work"


def project_paths(
    *,
    bin_dir: str | Path | None = None,
    scratch_dir: str | Path | None = None,
    reports_dir: str | Path | None = None,
) -> ProjectPaths:
    """Resolve shared path defaults with env and CLI overrides."""
    return ProjectPaths(
        bin_dir=_resolve(bin_dir, "AUDIT_BIN_DIR", PROJECT_ROOT / "bin"),
        scratch_dir=_resolve(scratch_dir, "AUDIT_SCRATCH_DIR", PROJECT_ROOT / "scratch"),
        reports_dir=_resolve(reports_dir, "AUDIT_REPORTS_DIR", PROJECT_ROOT / "reports"),
    )


def ensure_project_dirs(paths: ProjectPaths) -> None:
    paths.bin_dir.mkdir(parents=True, exist_ok=True)
    paths.scratch_dir.mkdir(parents=True, exist_ok=True)
    paths.reports_dir.mkdir(parents=True, exist_ok=True)


def resolve_tool(
    tool_name: str,
    *,
    explicit_path: str | Path | None = None,
    paths: ProjectPaths | None = None,
) -> Path | None:
    """Resolve a third-party binary from an explicit path, bin/, then PATH."""
    if explicit_path:
        explicit = Path(explicit_path).expanduser()
        return explicit.resolve() if explicit.exists() else None

    resolved_paths = paths or project_paths()
    candidate = resolved_paths.bin_dir / tool_name
    if candidate.exists():
        return candidate.resolve()

    found = shutil.which(tool_name)
    return Path(found).resolve() if found else None


def _resolve(value: str | Path | None, env_name: str, default: Path) -> Path:
    raw = value if value is not None else os.environ.get(env_name)
    if raw is None or str(raw).strip() == "":
        return default.resolve()
    return Path(raw).expanduser().resolve()
