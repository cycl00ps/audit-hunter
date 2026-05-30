from __future__ import annotations

from pathlib import Path

import pytest

from audit import orchestrator
import audit.stages.gapfill as gapfill
from audit.config import HarnessConfig, StageConfig
from audit.orchestrator import CostExceeded, run_pipeline
from audit.state import StateDB
from audit.stages._common import StageContext


def _config() -> HarnessConfig:
    return HarnessConfig(stages={}, gapfill_iterations=0, feedback_iterations=0)


async def _noop_stage(*args, **kwargs) -> int:
    return 0


def _usage(input_tokens: int, output_tokens: int) -> dict:
    return {"usage": {"input_tokens": input_tokens, "output_tokens": output_tokens}}


def _stage(name: str) -> StageConfig:
    return StageConfig(
        name=name,
        provider="codex",
        model="test",
        concurrency=1,
        tools=["Read"],
        max_turns=1,
        permission_mode="default",
        repair_attempts=0,
    )


@pytest.mark.asyncio
async def test_token_budget_allows_runs_below_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = StateDB(tmp_path / "state.db")
    repo = tmp_path / "repo"
    report = tmp_path / "report.json"
    repo.mkdir()

    async def run_recon(ctx, db, **kwargs):
        db.record_cost(ctx.run_id, "recon", None, _usage(3, 2))
        return {}

    async def run_report(ctx, db):
        report.write_text("{}")
        return report

    monkeypatch.setattr(orchestrator.stages, "run_recon", run_recon)
    monkeypatch.setattr(orchestrator.stages, "run_hunt", _noop_stage)
    monkeypatch.setattr(orchestrator.stages, "run_validate", _noop_stage)
    monkeypatch.setattr(orchestrator.stages, "run_dedupe", _noop_stage)
    monkeypatch.setattr(orchestrator.stages, "run_trace", _noop_stage)
    monkeypatch.setattr(orchestrator.stages, "run_feedback", _noop_stage)
    monkeypatch.setattr(orchestrator.stages, "run_report", run_report)

    try:
        out = await run_pipeline(
            repo_path=repo,
            run_id="below_cap",
            db=db,
            config=_config(),
            max_tokens=6,
        )
        assert out == report
        assert db.get_run("below_cap")["status"] == "completed"
    finally:
        db.close()


@pytest.mark.asyncio
async def test_token_budget_aborts_once_total_reaches_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = StateDB(tmp_path / "state.db")
    repo = tmp_path / "repo"
    repo.mkdir()

    async def run_recon(ctx, db, **kwargs):
        db.record_cost(ctx.run_id, "recon", None, _usage(3, 2))
        return {}

    async def fail_hunt(*args, **kwargs):
        raise AssertionError("hunt should not run after token cap is reached")

    monkeypatch.setattr(orchestrator.stages, "run_recon", run_recon)
    monkeypatch.setattr(orchestrator.stages, "run_hunt", fail_hunt)

    try:
        with pytest.raises(CostExceeded) as exc:
            await run_pipeline(
                repo_path=repo,
                run_id="at_cap",
                db=db,
                config=_config(),
                max_tokens=5,
            )
        message = str(exc.value)
        assert "5 >= 5 tokens" in message
        assert "input=3 output=2" in message
        assert db.get_run("at_cap")["status"] == "aborted"
    finally:
        db.close()


@pytest.mark.asyncio
async def test_token_budget_callback_aborts_inside_hunt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = StateDB(tmp_path / "state.db")
    repo = tmp_path / "repo"
    repo.mkdir()

    async def run_recon(ctx, db, **kwargs):
        return {}

    async def run_hunt(ctx, db, budget_check=None):
        db.record_cost(ctx.run_id, "hunt", "t_1", _usage(4, 3))
        assert budget_check is not None
        budget_check("hunt/t_1")
        return 0

    monkeypatch.setattr(orchestrator.stages, "run_recon", run_recon)
    monkeypatch.setattr(orchestrator.stages, "run_hunt", run_hunt)

    try:
        with pytest.raises(CostExceeded) as exc:
            await run_pipeline(
                repo_path=repo,
                run_id="hunt_cap",
                db=db,
                config=_config(),
                max_tokens=7,
            )
        assert "before hunt/t_1" in str(exc.value)
        assert "7 >= 7 tokens" in str(exc.value)
        assert db.get_run("hunt_cap")["status"] == "aborted"
    finally:
        db.close()


@pytest.mark.asyncio
async def test_gapfill_receives_hunter_gaps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = StateDB(tmp_path / "state.db")
    repo = tmp_path / "repo"
    repo.mkdir()
    rid = db.create_run(str(repo), "gap_run")
    db.add_task(rid, {
        "task_id": "t_1",
        "attack_class": "idor",
        "scope_hint": "path into object lookup",
        "target_files": ["internal/web/api.go"],
        "rationale": "path selector",
        "priority": 1,
        "source": "recon",
    })
    db.record_task_result(rid, "t_1", {
        "task_id": "t_1",
        "findings": [],
        "gaps_observed": [
            {
                "file_or_subsystem": "internal/web/api.go",
                "reason": "socket PoC could not bind",
                "suggested_attack_class": "idor",
            }
        ],
    })
    db.update_task_status(rid, "t_1", "done")
    captured: dict = {}

    class Result:
        payload = {"new_tasks": [], "coverage_analysis": {
            "light_subsystems": [],
            "unattempted_attack_classes": [],
        }}
        raw_result_message = {"usage": {"input_tokens": 1, "output_tokens": 1}}
        artifact_path = tmp_path / "gapfill.jsonl"

    async def fake_run_agent(*, user_input, **kwargs):
        captured["user_input"] = user_input
        return Result()

    monkeypatch.setattr(gapfill, "run_agent", fake_run_agent)
    ctx = StageContext(
        run_id=rid,
        repo_path=repo,
        config=HarnessConfig(stages={"gapfill": _stage("gapfill")}),
    )
    try:
        added = await gapfill.run_gapfill(ctx, db)
    finally:
        db.close()

    assert added == 0
    completed = captured["user_input"]["completed_tasks"]
    assert completed[0]["gaps_observed"][0]["reason"] == "socket PoC could not bind"
