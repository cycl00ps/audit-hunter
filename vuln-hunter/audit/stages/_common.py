"""Shared helpers for stage modules."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path

from audit.config import HarnessConfig, StageConfig


TOOL_ROOT = Path(__file__).resolve().parent.parent.parent
PROJECT_ROOT = TOOL_ROOT.parent
PROMPTS = TOOL_ROOT / "prompts"
SCHEMAS = TOOL_ROOT / "schemas"
REPORTS = Path(os.environ.get("AUDIT_REPORTS_DIR") or PROJECT_ROOT / "reports").expanduser().resolve()
SCRATCH = Path(os.environ.get("AUDIT_SCRATCH_DIR") or PROJECT_ROOT / "scratch").expanduser().resolve()
RESULTS = REPORTS
ARTIFACTS = SCRATCH / "artifacts"
WORK = SCRATCH / "work"


@dataclass
class StageContext:
    run_id: str
    repo_path: Path
    config: HarnessConfig
    reports_root: Path | None = None
    scratch_root: Path | None = None
    # Optional operator context — when set, downstream prompts use them.
    live_target: dict | None = None    # {"url": "...", "credentials": {...}}
    scope_notes: str | None = None     # verbatim text appended to user_input

    def stage(self, name: str) -> StageConfig:
        return self.config.get(name)

    def extras(self) -> dict:
        """Optional fields merged into every agent's user_input."""
        out: dict = {}
        if self.live_target:
            out["live_target"] = self.live_target
        if self.scope_notes:
            out["scope_notes"] = self.scope_notes
        return out

    def prompt(self, name: str) -> Path:
        path = PROMPTS / f"{name}.md"
        if not path.exists():
            raise FileNotFoundError(f"Missing prompt: {path}")
        return path

    def schema(self, name: str) -> Path:
        path = SCHEMAS / f"{name}.schema.json"
        if not path.exists():
            raise FileNotFoundError(f"Missing schema: {path}")
        return path

    def results_dir(self, stage: str) -> Path:
        d = self.artifacts_root / self.run_id / "vuln-hunter" / stage
        d.mkdir(parents=True, exist_ok=True)
        return d

    def work_dir(self, stage: str, ref: str | None = None) -> Path:
        d = self.work_root / self.run_id / stage / (ref or "default")
        d.mkdir(parents=True, exist_ok=True)
        return d

    @property
    def resolved_reports_root(self) -> Path:
        return (self.reports_root or REPORTS).expanduser().resolve()

    @property
    def resolved_scratch_root(self) -> Path:
        return (self.scratch_root or SCRATCH).expanduser().resolve()

    @property
    def artifacts_root(self) -> Path:
        return self.resolved_scratch_root / "artifacts"

    @property
    def work_root(self) -> Path:
        return self.resolved_scratch_root / "work"

    def report_path(self) -> Path:
        d = self.resolved_reports_root / self.run_id
        d.mkdir(parents=True, exist_ok=True)
        return d / "vuln-hunter.report.json"


def truncated_recon_summary(full: dict, subsystem_filter: str | None = None) -> dict:
    """Pass only the architecture facts downstream agents need."""
    out: dict = {
        "architecture": full.get("architecture", {}),
        "subsystems": full.get("subsystems", []),
    }
    if subsystem_filter is not None:
        match = next(
            (s for s in out["subsystems"] if s.get("name") == subsystem_filter
             or subsystem_filter.startswith(s.get("path", "##nope##"))),
            None,
        )
        out["subsystem_for_task"] = match
    return out
