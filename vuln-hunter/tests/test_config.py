"""Config loading test — make sure stages.yaml is valid."""

from __future__ import annotations

from pathlib import Path

import pytest

from audit.config import load_config


def test_default_config_loads() -> None:
    cfg = load_config()
    for name in ["recon", "hunt", "validate", "gapfill", "dedupe", "trace",
                 "feedback", "report"]:
        sc = cfg.get(name)
        assert sc.provider == "codex", f"{name}: unexpected provider"
        assert sc.model, f"{name}: missing model"
        assert sc.reasoning_effort in {"medium", "xhigh"}, f"{name}: missing reasoning effort"
        assert sc.concurrency >= 1, f"{name}: invalid concurrency"
        assert sc.tools, f"{name}: missing tools"


def test_hunt_validate_model_diversity() -> None:
    """Hunt and Validate MUST use different models — the blog's
    'deliberate disagreement' rule."""
    cfg = load_config()
    assert cfg.get("hunt").model != cfg.get("validate").model


def test_provider_can_be_forced() -> None:
    cfg = load_config()
    cfg.set_provider("claude")
    assert {sc.provider for sc in cfg.stages.values()} == {"claude"}


def test_reasoning_effort_can_be_forced() -> None:
    cfg = load_config()
    cfg.set_reasoning_effort("high")
    assert {sc.reasoning_effort for sc in cfg.stages.values()} == {"high"}


def test_reasoning_effort_default_and_stage_override(tmp_path: Path) -> None:
    p = tmp_path / "stages.yaml"
    p.write_text("""
defaults:
  provider: codex
  max_turns: 25
  permission_mode: acceptEdits
  repair_attempts: 1
  reasoning_effort: medium
stages:
  recon:
    model: gpt-test
    reasoning_effort: xhigh
    concurrency: 1
    tools: [Read]
  hunt:
    model: gpt-test-mini
    concurrency: 2
    tools: [Read]
""")

    cfg = load_config(p)

    assert cfg.get("recon").reasoning_effort == "xhigh"
    assert cfg.get("hunt").reasoning_effort == "medium"


def test_invalid_reasoning_effort_fails(tmp_path: Path) -> None:
    p = tmp_path / "stages.yaml"
    p.write_text("""
defaults:
  provider: codex
stages:
  recon:
    model: gpt-test
    reasoning_effort: max
    concurrency: 1
    tools: [Read]
""")

    with pytest.raises(ValueError, match="stages.recon.reasoning_effort"):
        load_config(p)
