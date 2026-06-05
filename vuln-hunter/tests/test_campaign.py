from __future__ import annotations

import json
from pathlib import Path

import pytest

from audit import campaign
from audit.config import HarnessConfig
from audit.json_utils import validate_schema
from audit.state import StateDB


def _task(task_id: str = "t_1") -> dict:
    return {
        "task_id": task_id,
        "attack_class": "sql_injection",
        "scope_hint": "query parameter reaches SQL",
        "target_files": ["app.py"],
        "rationale": "unsafe SQL construction",
        "priority": 1,
        "source": "recon",
    }


def _finding(
    finding_id: str,
    *,
    file: str = "app.py",
    line: int = 10,
    vuln_class: str = "sql_injection",
    severity: str = "high",
    description: str = "User input is concatenated into SQL before execution.",
) -> dict:
    return {
        "finding_id": finding_id,
        "file": file,
        "line_start": line,
        "line_end": line + 1,
        "vuln_class": vuln_class,
        "severity": severity,
        "description": description,
        "evidence_snippet": "cur.execute('SELECT ' + name)",
        "confidence": 0.9,
    }


def _add_reachable(
    db: StateDB,
    run_id: str,
    *,
    finding_id: str = "f_1",
    file: str = "app.py",
    line: int = 10,
    root_cause: str = "query parameter reaches string-built SQL",
) -> None:
    db.add_task(run_id, _task())
    db.add_finding(run_id, "t_1", _finding(finding_id, file=file, line=line))
    db.set_finding_validation(run_id, finding_id, "confirmed", {
        "finding_id": finding_id,
        "verdict": "confirmed",
        "rationale": "The finding is confirmed because attacker input reaches the sink.",
        "validator_confidence": 0.9,
    })
    db.add_dedupe_group(run_id, {
        "group_id": "g_1",
        "root_cause": root_cause,
        "canonical_finding_id": finding_id,
        "member_finding_ids": [finding_id],
    })
    db.assign_finding_group(run_id, finding_id, "g_1", True)
    db.add_trace(run_id, finding_id, {
        "finding_id": finding_id,
        "reachable": True,
        "confidence": 0.9,
        "rationale": "The HTTP route reaches the sink.",
        "entry_points": [{"kind": "http_route", "location": "app.py:lookup"}],
        "call_chain": [{"file": "app.py", "function": "lookup", "line": line}],
    })


def _usage(tokens: int) -> dict:
    return {"usage": {"input_tokens": tokens, "output_tokens": 0}}


@pytest.mark.asyncio
async def test_campaign_launches_requested_runs_when_each_finds_new_issue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = StateDB(tmp_path / "state.db")
    repo = tmp_path / "repo"
    results = tmp_path / "results"
    repo.mkdir()
    launched: list[str] = []

    async def fake_run_pipeline(*, repo_path, run_id, db, max_tokens, **kwargs):
        launched.append(run_id)
        db.create_run(str(repo_path), run_id)
        index = len(launched)
        _add_reachable(
            db,
            run_id,
            finding_id=f"f_{index}",
            file=f"app{index}.py",
            root_cause=f"distinct root cause {index}",
        )
        db.record_cost(run_id, "recon", None, _usage(5))
        return results / run_id / "report" / "report.json"

    monkeypatch.setattr(campaign, "run_pipeline", fake_run_pipeline)

    try:
        await campaign.run_campaign(
            repo_path=repo,
            campaign_id="camp",
            runs=3,
            max_tokens=100,
            stop_after_empty=2,
            seed_run_ids=[],
            db=db,
            config=HarnessConfig(),
            results_root=results,
        )
        assert launched == ["camp-1", "camp-2", "camp-3"]
        assert db.get_campaign("camp")["stop_reason"] == "requested_runs_completed"
        assert [r["new_reachable_issue_count"] for r in db.list_campaign_runs("camp")] == [1, 1, 1]
    finally:
        db.close()


@pytest.mark.asyncio
async def test_campaign_stops_after_consecutive_empty_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = StateDB(tmp_path / "state.db")
    repo = tmp_path / "repo"
    repo.mkdir()
    launched: list[str] = []

    async def fake_run_pipeline(*, repo_path, run_id, db, **kwargs):
        launched.append(run_id)
        db.create_run(str(repo_path), run_id)
        return tmp_path / "unused.json"

    monkeypatch.setattr(campaign, "run_pipeline", fake_run_pipeline)

    try:
        await campaign.run_campaign(
            repo_path=repo,
            campaign_id="camp",
            runs=5,
            max_tokens=100,
            stop_after_empty=2,
            seed_run_ids=[],
            db=db,
            config=HarnessConfig(),
            results_root=tmp_path / "results",
        )
        assert launched == ["camp-1", "camp-2"]
        assert db.get_campaign("camp")["stop_reason"] == "no_new_reachable_issues_after_2_runs"
    finally:
        db.close()


@pytest.mark.asyncio
async def test_campaign_passes_remaining_tokens_to_child_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = StateDB(tmp_path / "state.db")
    repo = tmp_path / "repo"
    repo.mkdir()
    seen_caps: list[int] = []

    async def fake_run_pipeline(*, repo_path, run_id, db, max_tokens, **kwargs):
        seen_caps.append(max_tokens)
        db.create_run(str(repo_path), run_id)
        index = len(seen_caps)
        _add_reachable(
            db,
            run_id,
            finding_id=f"f_{index}",
            file=f"app{index}.py",
            root_cause=f"distinct root cause {index}",
        )
        db.record_cost(run_id, "recon", None, _usage(7))
        return tmp_path / "unused.json"

    monkeypatch.setattr(campaign, "run_pipeline", fake_run_pipeline)

    try:
        await campaign.run_campaign(
            repo_path=repo,
            campaign_id="camp",
            runs=2,
            max_tokens=25,
            stop_after_empty=2,
            seed_run_ids=[],
            db=db,
            config=HarnessConfig(),
            results_root=tmp_path / "results",
        )
        assert seen_caps == [25, 18]
    finally:
        db.close()


@pytest.mark.asyncio
async def test_campaign_without_token_cap_passes_none_to_child_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = StateDB(tmp_path / "state.db")
    repo = tmp_path / "repo"
    repo.mkdir()
    seen_caps: list[int | None] = []

    async def fake_run_pipeline(*, repo_path, run_id, db, max_tokens, **kwargs):
        seen_caps.append(max_tokens)
        db.create_run(str(repo_path), run_id)
        index = len(seen_caps)
        _add_reachable(
            db,
            run_id,
            finding_id=f"f_{index}",
            file=f"app{index}.py",
            root_cause=f"distinct root cause {index}",
        )
        db.record_cost(run_id, "recon", None, _usage(7))
        return tmp_path / "unused.json"

    monkeypatch.setattr(campaign, "run_pipeline", fake_run_pipeline)

    try:
        await campaign.run_campaign(
            repo_path=repo,
            campaign_id="camp",
            runs=2,
            max_tokens=None,
            stop_after_empty=2,
            seed_run_ids=[],
            db=db,
            config=HarnessConfig(),
            results_root=tmp_path / "results",
        )
        assert seen_caps == [None, None]
        assert db.get_campaign("camp")["max_tokens"] is None
    finally:
        db.close()


@pytest.mark.asyncio
async def test_campaign_stops_before_launch_when_token_budget_exhausted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = StateDB(tmp_path / "state.db")
    repo = tmp_path / "repo"
    repo.mkdir()
    launched: list[str] = []

    async def fake_run_pipeline(*, repo_path, run_id, db, **kwargs):
        launched.append(run_id)
        db.create_run(str(repo_path), run_id)
        _add_reachable(db, run_id)
        db.record_cost(run_id, "recon", None, _usage(10))
        return tmp_path / "unused.json"

    monkeypatch.setattr(campaign, "run_pipeline", fake_run_pipeline)

    try:
        await campaign.run_campaign(
            repo_path=repo,
            campaign_id="camp",
            runs=3,
            max_tokens=10,
            stop_after_empty=3,
            seed_run_ids=[],
            db=db,
            config=HarnessConfig(),
            results_root=tmp_path / "results",
        )
        assert launched == ["camp-1"]
        assert db.get_campaign("camp")["stop_reason"] == "token_budget_exhausted"
    finally:
        db.close()


@pytest.mark.asyncio
async def test_campaign_imports_seed_findings_into_first_scope_notes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = StateDB(tmp_path / "state.db")
    repo = tmp_path / "repo"
    repo.mkdir()
    db.create_run(str(repo), "seed")
    _add_reachable(db, "seed", root_cause="seeded SQL injection root cause")
    captured: dict[str, str | None] = {}

    async def fake_run_pipeline(*, repo_path, run_id, db, scope_notes, **kwargs):
        captured["scope_notes"] = scope_notes
        db.create_run(str(repo_path), run_id)
        return tmp_path / "unused.json"

    monkeypatch.setattr(campaign, "run_pipeline", fake_run_pipeline)

    try:
        await campaign.run_campaign(
            repo_path=repo,
            campaign_id="camp",
            runs=1,
            max_tokens=100,
            stop_after_empty=1,
            seed_run_ids=["seed"],
            db=db,
            config=HarnessConfig(),
            scope_notes="operator scope",
            results_root=tmp_path / "results",
        )
        scope_notes = captured["scope_notes"] or ""
        assert "operator scope" in scope_notes
        assert "Prior Campaign Findings Ledger" in scope_notes
        assert "seeded SQL injection root cause" in scope_notes
        assert "hard avoid" in scope_notes
    finally:
        db.close()


@pytest.mark.asyncio
async def test_campaign_applies_targeted_scope_only_to_initial_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = StateDB(tmp_path / "state.db")
    repo = tmp_path / "repo"
    repo.mkdir()
    captured: list[str] = []

    async def fake_run_pipeline(*, repo_path, run_id, db, scope_notes, **kwargs):
        captured.append(scope_notes or "")
        db.create_run(str(repo_path), run_id)
        return tmp_path / "unused.json"

    monkeypatch.setattr(campaign, "run_pipeline", fake_run_pipeline)

    try:
        await campaign.run_campaign(
            repo_path=repo,
            campaign_id="camp",
            runs=3,
            max_tokens=100,
            stop_after_empty=5,
            seed_run_ids=[],
            db=db,
            config=HarnessConfig(),
            scope_notes="operator scope",
            targeted_scope_notes="generated threat scope",
            targeted_scope_runs=2,
            results_root=tmp_path / "results",
        )

        assert len(captured) == 3
        assert "generated threat scope" in captured[0]
        assert "operator scope" in captured[0]
        assert "generated threat scope" in captured[1]
        assert "operator scope" in captured[1]
        assert "generated threat scope" not in captured[2]
        assert "operator scope" in captured[2]
    finally:
        db.close()


@pytest.mark.asyncio
async def test_campaign_rejects_targeted_scope_runs_above_requested_runs(
    tmp_path: Path,
) -> None:
    db = StateDB(tmp_path / "state.db")
    repo = tmp_path / "repo"
    repo.mkdir()

    try:
        with pytest.raises(ValueError, match="cannot exceed requested runs"):
            await campaign.run_campaign(
                repo_path=repo,
                campaign_id="camp",
                runs=2,
                max_tokens=100,
                stop_after_empty=5,
                seed_run_ids=[],
                db=db,
                config=HarnessConfig(),
                targeted_scope_notes="generated threat scope",
                targeted_scope_runs=3,
                results_root=tmp_path / "results",
            )
    finally:
        db.close()


def _report_finding(
    finding_id: str,
    *,
    title: str,
    severity: str,
    file: str = "app.py",
    line: int = 10,
) -> dict:
    return {
        "finding_id": finding_id,
        "title": title,
        "severity": severity,
        "vuln_class": "sql_injection",
        "cwe": "CWE-89",
        "file": file,
        "line_start": line,
        "line_end": line + 1,
        "description": "User input is concatenated into SQL before execution.",
        "evidence": "cur.execute('SELECT ' + name)",
        "trace": {
            "entry_points": [{"kind": "http_route", "location": "app.py:lookup"}],
            "call_chain": [{"file": "app.py", "function": "lookup", "line": line}],
        },
        "recommendation": "Use parameterized SQL queries for all user-controlled input.",
    }


def _write_child_report(results: Path, run_id: str, findings: list[dict]) -> None:
    report = {
        "run_id": run_id,
        "target": {"repo_path": "/repo"},
        "summary": {"total": len(findings), "by_severity": {}},
        "findings": findings,
    }
    out = results / run_id / "report"
    out.mkdir(parents=True)
    (out / "report.json").write_text(json.dumps(report))


def test_campaign_report_merges_dedupes_and_keeps_highest_severity(tmp_path: Path) -> None:
    results = tmp_path / "results"
    title = "Unauthenticated SQL injection in lookup route"
    _write_child_report(
        results,
        "camp-1",
        [
            _report_finding("f_1", title=title, severity="medium"),
            _report_finding(
                "f_2",
                title="Path traversal in file download route",
                severity="high",
                file="download.py",
                line=20,
            ),
        ],
    )
    _write_child_report(
        results,
        "camp-2",
        [_report_finding("f_3", title=title, severity="critical")],
    )

    report_path = campaign.write_campaign_report(
        campaign_id="camp",
        repo_path=tmp_path / "repo",
        child_run_ids=["camp-1", "camp-2"],
        results_root=results,
    )

    payload = json.loads(report_path.read_text())
    errors = validate_schema(payload, Path("schemas/report.schema.json"))
    assert errors == []
    assert payload["summary"]["total"] == 2
    duplicate = next(f for f in payload["findings"] if f["title"] == title)
    assert duplicate["severity"] == "critical"
    assert duplicate["variants"] == ["camp-1", "camp-2"]
