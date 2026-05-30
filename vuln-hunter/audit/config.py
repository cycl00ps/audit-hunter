"""Load per-stage configuration from config/stages.yaml."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


VALID_REASONING_EFFORTS = ("none", "low", "medium", "high", "xhigh")


@dataclass
class StageConfig:
    name: str
    provider: str
    model: str
    concurrency: int
    tools: list[str]
    max_turns: int
    permission_mode: str
    repair_attempts: int
    reasoning_effort: str | None = None


@dataclass
class HarnessConfig:
    stages: dict[str, StageConfig] = field(default_factory=dict)
    gapfill_iterations: int = 2
    feedback_iterations: int = 1

    def get(self, stage: str) -> StageConfig:
        try:
            return self.stages[stage]
        except KeyError:
            raise KeyError(
                f"Unknown stage {stage!r}. Known: {sorted(self.stages)}"
            ) from None

    def cap_concurrency(self, cap: int) -> None:
        """Mutate every stage's concurrency to min(current, cap). Useful
        for usage-contained test runs."""
        if cap < 1:
            raise ValueError("concurrency cap must be >= 1")
        for sc in self.stages.values():
            sc.concurrency = min(sc.concurrency, cap)

    def set_provider(self, provider: str) -> None:
        """Force every stage onto a provider selected by the CLI/env."""
        provider = provider.strip().lower()
        if provider not in {"codex", "claude"}:
            raise ValueError("provider must be 'codex' or 'claude'")
        for sc in self.stages.values():
            sc.provider = provider

    def set_reasoning_effort(self, effort: str) -> None:
        """Force every stage onto the same OpenAI reasoning effort."""
        effort = _normalize_reasoning_effort(effort)
        for sc in self.stages.values():
            sc.reasoning_effort = effort


def load_config(path: Path | None = None, *, default_provider: str = "codex") -> HarnessConfig:
    if path is None:
        path = Path(__file__).resolve().parent.parent / "config" / "stages.yaml"
    raw = yaml.safe_load(path.read_text())
    defaults = raw.get("defaults", {}) or {}
    default_provider = defaults.get("provider", default_provider)
    default_reasoning_effort = _optional_reasoning_effort(
        defaults.get("reasoning_effort"), "defaults.reasoning_effort"
    )
    stages: dict[str, StageConfig] = {}
    for name, spec in (raw.get("stages") or {}).items():
        reasoning_effort = _optional_reasoning_effort(
            spec.get("reasoning_effort", default_reasoning_effort),
            f"stages.{name}.reasoning_effort",
        )
        stages[name] = StageConfig(
            name=name,
            provider=spec.get("provider", default_provider),
            model=spec["model"],
            concurrency=int(spec["concurrency"]),
            tools=list(spec["tools"]),
            max_turns=int(spec.get("max_turns", defaults.get("max_turns", 25))),
            permission_mode=spec.get(
                "permission_mode", defaults.get("permission_mode", "acceptEdits")
            ),
            repair_attempts=int(
                spec.get("repair_attempts", defaults.get("repair_attempts", 1))
            ),
            reasoning_effort=reasoning_effort,
        )
    loops = raw.get("loops", {}) or {}
    return HarnessConfig(
        stages=stages,
        gapfill_iterations=int(loops.get("gapfill_iterations", 2)),
        feedback_iterations=int(loops.get("feedback_iterations", 1)),
    )


def _optional_reasoning_effort(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be one of {list(VALID_REASONING_EFFORTS)}")
    return _normalize_reasoning_effort(value, field)


def _normalize_reasoning_effort(value: str, field: str = "reasoning_effort") -> str:
    effort = value.strip().lower()
    if effort not in VALID_REASONING_EFFORTS:
        raise ValueError(f"{field} must be one of {list(VALID_REASONING_EFFORTS)}")
    return effort
