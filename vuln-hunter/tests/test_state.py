"""StateDB roundtrip tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from audit.state import LegacyDatabaseError, StateDB


def _task(task_id: str = "t_1") -> dict:
    return {
        "task_id": task_id,
        "attack_class": "sqli",
        "scope_hint": "lookup name parameter",
        "target_files": ["app.py"],
        "rationale": "raw string formatting",
        "priority": 1,
        "source": "recon",
    }


def _finding(finding_id: str = "f_1") -> dict:
    return {
        "finding_id": finding_id,
        "file": "a.py",
        "line_start": 1,
        "line_end": 2,
        "vuln_class": "sqli",
        "severity": "high",
        "description": "x",
        "evidence_snippet": "y",
        "confidence": 0.9,
    }


def test_run_and_task_lifecycle(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = db.create_run("/some/repo", "test_run")
    assert db.get_run(rid)["status"] == "running"

    assert db.add_task(rid, _task())
    pending = db.get_pending_tasks(rid)
    assert len(pending) == 1
    assert pending[0].task_id == "t_1"
    assert db.add_task(rid, _task()) is False

    db.update_task_status(rid, "t_1", "done")
    assert db.get_pending_tasks(rid) == []
    assert any(t.status == "done" for t in db.get_all_tasks(rid))

    db.finish_run(rid)
    assert db.get_run(rid)["status"] == "completed"
    db.close()


def test_finding_validation_and_dedupe(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = db.create_run("/some/repo", "test_run")
    db.add_task(rid, _task())
    db.add_finding(rid, "t_1", _finding())
    assert len(db.get_unvalidated_findings(rid)) == 1

    db.set_finding_validation(rid, "f_1", "confirmed", {
        "finding_id": "f_1", "verdict": "confirmed",
        "rationale": "ok", "validator_confidence": 0.9,
    })
    assert len(db.get_findings(rid, validation_status="confirmed")) == 1

    db.add_dedupe_group(rid, {
        "group_id": "g_1", "root_cause": "rc",
        "canonical_finding_id": "f_1", "member_finding_ids": ["f_1"],
    })
    db.assign_finding_group(rid, "f_1", "g_1", True)
    assert len(db.get_findings(rid, canonical_only=True)) == 1

    db.add_trace(rid, "f_1", {
        "finding_id": "f_1", "reachable": True, "confidence": 0.9,
        "rationale": "trivial", "entry_points": [], "call_chain": [],
    })
    reachable = db.get_reachable_canonical_findings(rid)
    assert len(reachable) == 1
    db.close()


def test_usage_aggregation(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = db.create_run("/r", "test_run")
    db.record_cost(rid, "hunt", "t_1", {"total_cost_usd": 0.01, "usage": {
        "input_tokens": 100, "output_tokens": 50,
    }, "num_turns": 3, "duration_ms": 1234})
    db.record_cost(rid, "hunt", "t_2", {"total_cost_usd": 0.02, "usage": {
        "input_tokens": 200, "output_tokens": 100,
    }, "num_turns": 5, "duration_ms": 4321})
    assert abs(db.total_cost(rid) - 0.03) < 1e-9
    assert db.total_input_tokens(rid) == 300
    assert db.total_output_tokens(rid) == 150
    assert db.total_tokens(rid) == 450
    db.close()


def test_task_and_finding_ids_are_run_scoped(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    run_a = db.create_run("/repo", "run_a")
    run_b = db.create_run("/repo", "run_b")

    assert db.add_task(run_a, _task("t_shared")) is True
    assert db.add_task(run_b, _task("t_shared")) is True
    assert db.add_task(run_b, _task("t_shared")) is False

    assert db.add_finding(run_a, "t_shared", _finding("f_shared")) is True
    assert db.add_finding(run_b, "t_shared", _finding("f_shared")) is True
    assert db.add_finding(run_b, "t_shared", _finding("f_shared")) is False

    db.set_finding_validation(run_a, "f_shared", "confirmed", {
        "finding_id": "f_shared",
        "verdict": "confirmed",
        "rationale": "ok",
        "validator_confidence": 1.0,
    })
    assert len(db.get_findings(run_a, validation_status="confirmed")) == 1
    assert len(db.get_findings(run_b, validation_status="confirmed")) == 0

    group = {
        "group_id": "g_shared",
        "root_cause": "same local root cause",
        "canonical_finding_id": "f_shared",
        "member_finding_ids": ["f_shared"],
    }
    db.add_dedupe_group(run_a, group)
    db.add_dedupe_group(run_b, group)
    db.assign_finding_group(run_a, "f_shared", "g_shared", True)
    db.assign_finding_group(run_b, "f_shared", "g_shared", True)

    db.add_trace(run_a, "f_shared", {
        "finding_id": "f_shared",
        "reachable": True,
        "confidence": 0.9,
        "rationale": "a",
    })
    db.add_trace(run_b, "f_shared", {
        "finding_id": "f_shared",
        "reachable": False,
        "confidence": 0.1,
        "rationale": "b",
    })
    assert db.get_trace(run_a, "f_shared")["reachable"] is True
    assert db.get_trace(run_b, "f_shared")["reachable"] is False
    assert len(db.get_reachable_canonical_findings(run_a)) == 1
    assert len(db.get_reachable_canonical_findings(run_b)) == 0
    db.close()


def test_legacy_database_requires_reset(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE runs (run_id TEXT PRIMARY KEY)")
    conn.commit()
    conn.close()

    with pytest.raises(LegacyDatabaseError, match="audit db reset --yes"):
        StateDB(db_path)


def test_v2_database_migrates_to_v3_without_losing_runs(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        """CREATE TABLE runs (
        run_id TEXT PRIMARY KEY,
        repo_path TEXT NOT NULL,
        started_at REAL NOT NULL,
        finished_at REAL,
        status TEXT NOT NULL DEFAULT 'running'
        )"""
    )
    conn.execute(
        "INSERT INTO runs (run_id, repo_path, started_at, status) VALUES (?, ?, ?, ?)",
        ("old_run", "/repo", 1.0, "completed"),
    )
    conn.execute("PRAGMA user_version = 2")
    conn.commit()
    conn.close()

    db = StateDB(db_path)
    try:
        assert db.get_run("old_run")["status"] == "completed"
        db.create_campaign(
            campaign_id="camp",
            repo_path="/repo",
            requested_runs=2,
            max_tokens=100,
            stop_after_empty=1,
            seed_run_ids=["old_run"],
        )
        db.start_campaign_run("camp", "camp-1", 1)
        db.finish_campaign_run(
            "camp",
            "camp-1",
            status="completed",
            tokens=12,
            new_reachable_issue_count=1,
        )
        assert db.campaign_total_tokens("camp") == 12
        assert db._conn.execute("PRAGMA user_version").fetchone()[0] == 3
    finally:
        db.close()
