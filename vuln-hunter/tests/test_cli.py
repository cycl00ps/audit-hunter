from click.testing import CliRunner

from audit import cli
from audit.state import StateDB


def test_run_marks_interrupted_run_aborted(tmp_path, monkeypatch):
    db_path = tmp_path / "state.db"
    repo = tmp_path / "repo"
    repo.mkdir()

    monkeypatch.setattr(cli, "DB_PATH", db_path)
    monkeypatch.setattr(cli, "RESULTS_ROOT", tmp_path / "results")
    monkeypatch.setattr(cli, "configure_auth", lambda **kwargs: object())

    async def fake_run_pipeline(*, repo_path, run_id, db, **kwargs):
        db.create_run(str(repo_path), run_id)
        raise KeyboardInterrupt()

    monkeypatch.setattr(cli, "run_pipeline", fake_run_pipeline)

    result = CliRunner().invoke(
        cli.main,
        ["run", "--repo", str(repo), "--run-id", "interrupted"],
    )

    assert result.exit_code == 130
    db = StateDB(db_path)
    try:
        assert db.get_run("interrupted")["status"] == "aborted"
    finally:
        db.close()


def test_status_list_shows_tokens_not_cost(tmp_path, monkeypatch):
    db_path = tmp_path / "state.db"
    db = StateDB(db_path)
    try:
        rid = db.create_run("/repo", "run_1")
        db.record_cost(rid, "recon", None, {
            "usage": {"input_tokens": 10, "output_tokens": 5},
        })
    finally:
        db.close()

    monkeypatch.setattr(cli, "DB_PATH", db_path)

    result = CliRunner().invoke(cli.main, ["status"])

    assert result.exit_code == 0
    assert "tokens" in result.output
    assert "cost ($)" not in result.output
    assert "15" in result.output


def test_status_detail_shows_token_split(tmp_path, monkeypatch):
    db_path = tmp_path / "state.db"
    db = StateDB(db_path)
    try:
        rid = db.create_run("/repo", "run_1")
        db.record_cost(rid, "recon", None, {
            "usage": {"input_tokens": 10, "output_tokens": 5},
        })
    finally:
        db.close()

    monkeypatch.setattr(cli, "DB_PATH", db_path)

    result = CliRunner().invoke(cli.main, ["status", "--run-id", "run_1"])

    assert result.exit_code == 0
    assert "tokens" in result.output
    assert "input tokens" in result.output
    assert "output tokens" in result.output
    assert "total cost ($)" not in result.output
    assert "15" in result.output
    assert "10" in result.output
    assert "5" in result.output


def test_run_warns_max_cost_is_legacy_and_passes_token_cap(tmp_path, monkeypatch):
    db_path = tmp_path / "state.db"
    repo = tmp_path / "repo"
    report = tmp_path / "report.json"
    repo.mkdir()

    monkeypatch.setattr(cli, "DB_PATH", db_path)
    monkeypatch.setattr(cli, "RESULTS_ROOT", tmp_path / "results")
    monkeypatch.setattr(cli, "configure_auth", lambda **kwargs: object())

    async def fake_run_pipeline(*, max_cost_usd, max_tokens, **kwargs):
        assert max_cost_usd == 12.5
        assert max_tokens == 100
        return report

    monkeypatch.setattr(cli, "run_pipeline", fake_run_pipeline)

    result = CliRunner().invoke(
        cli.main,
        [
            "run",
            "--repo",
            str(repo),
            "--run-id",
            "budgeted",
            "--max-cost-usd",
            "12.5",
            "--max-tokens",
            "100",
        ],
    )

    assert result.exit_code == 0
    assert "--max-cost-usd is deprecated" in result.output
    assert "--max-tokens" in result.output


def test_run_reasoning_effort_overrides_all_stages(tmp_path, monkeypatch):
    db_path = tmp_path / "state.db"
    repo = tmp_path / "repo"
    report = tmp_path / "report.json"
    repo.mkdir()

    monkeypatch.setattr(cli, "DB_PATH", db_path)
    monkeypatch.setattr(cli, "RESULTS_ROOT", tmp_path / "results")
    monkeypatch.setattr(cli, "configure_auth", lambda **kwargs: object())

    async def fake_run_pipeline(*, config, **kwargs):
        assert {sc.reasoning_effort for sc in config.stages.values()} == {"high"}
        return report

    monkeypatch.setattr(cli, "run_pipeline", fake_run_pipeline)

    result = CliRunner().invoke(
        cli.main,
        [
            "run",
            "--repo",
            str(repo),
            "--run-id",
            "effort",
            "--reasoning-effort",
            "high",
        ],
    )

    assert result.exit_code == 0
    assert "set reasoning effort to high" in result.output


def test_run_rejects_invalid_reasoning_effort(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    result = CliRunner().invoke(
        cli.main,
        [
            "run",
            "--repo",
            str(repo),
            "--reasoning-effort",
            "max",
        ],
    )

    assert result.exit_code != 0
    assert "Invalid value for '--reasoning-effort'" in result.output


def test_campaign_run_parses_and_forwards_options(tmp_path, monkeypatch):
    db_path = tmp_path / "state.db"
    repo = tmp_path / "repo"
    report = tmp_path / "results" / "camp" / "campaign" / "report.json"
    scope = tmp_path / "scope.txt"
    repo.mkdir()
    scope.write_text("stay in scope")
    captured = {}

    monkeypatch.setattr(cli, "DB_PATH", db_path)
    monkeypatch.setattr(cli, "RESULTS_ROOT", tmp_path / "results")
    monkeypatch.setattr(cli, "configure_auth", lambda **kwargs: object())

    async def fake_run_campaign(**kwargs):
        captured.update(kwargs)
        return report

    monkeypatch.setattr(cli, "run_campaign", fake_run_campaign)

    result = CliRunner().invoke(
        cli.main,
        [
            "campaign",
            "run",
            "--repo",
            str(repo),
            "--campaign-id",
            "camp",
            "--runs",
            "4",
            "--max-tokens",
            "1000",
            "--stop-after-empty",
            "2",
            "--seed-run-id",
            "seed-a",
            "--seed-run-id",
            "seed-b",
            "--max-concurrency",
            "1",
            "--max-recon-tasks",
            "3",
            "--reasoning-effort",
            "low",
            "--target-url",
            "http://target.local",
            "--target-creds",
            "email=a@example.com",
            "--scope-notes",
            str(scope),
        ],
    )

    assert result.exit_code == 0
    assert captured["repo_path"] == repo.resolve()
    assert captured["campaign_id"] == "camp"
    assert captured["runs"] == 4
    assert captured["max_tokens"] == 1000
    assert captured["stop_after_empty"] == 2
    assert captured["seed_run_ids"] == ["seed-a", "seed-b"]
    assert captured["max_recon_tasks"] == 3
    assert captured["live_target"] == {
        "url": "http://target.local",
        "credentials": {"email": "a@example.com"},
    }
    assert captured["scope_notes"] == "stay in scope"
    assert captured["results_root"] == tmp_path / "results"
    assert {sc.concurrency for sc in captured["config"].stages.values()} == {1}
    assert {sc.reasoning_effort for sc in captured["config"].stages.values()} == {"low"}


def test_campaign_run_allows_omitting_max_tokens(tmp_path, monkeypatch):
    db_path = tmp_path / "state.db"
    repo = tmp_path / "repo"
    report = tmp_path / "results" / "camp" / "campaign" / "report.json"
    repo.mkdir()
    captured = {}

    monkeypatch.setattr(cli, "DB_PATH", db_path)
    monkeypatch.setattr(cli, "RESULTS_ROOT", tmp_path / "results")
    monkeypatch.setattr(cli, "configure_auth", lambda **kwargs: object())

    async def fake_run_campaign(**kwargs):
        captured.update(kwargs)
        return report

    monkeypatch.setattr(cli, "run_campaign", fake_run_campaign)

    result = CliRunner().invoke(
        cli.main,
        [
            "campaign",
            "run",
            "--repo",
            str(repo),
            "--campaign-id",
            "camp",
            "--runs",
            "10",
            "--max-concurrency",
            "6",
            "--max-recon-tasks",
            "15",
            "--stop-after-empty",
            "3",
        ],
    )

    assert result.exit_code == 0
    assert captured["max_tokens"] is None
    assert captured["runs"] == 10
    assert captured["max_recon_tasks"] == 15


def test_campaign_status_shows_child_runs(tmp_path, monkeypatch):
    db_path = tmp_path / "state.db"
    db = StateDB(db_path)
    try:
        db.create_campaign(
            campaign_id="camp",
            repo_path="/repo",
            requested_runs=3,
            max_tokens=1000,
            stop_after_empty=2,
            seed_run_ids=[],
        )
        db.start_campaign_run("camp", "camp-1", 1)
        db.finish_campaign_run(
            "camp",
            "camp-1",
            status="completed",
            tokens=50,
            new_reachable_issue_count=2,
        )
        db.finish_campaign("camp", "completed", "requested_runs_completed")
    finally:
        db.close()

    monkeypatch.setattr(cli, "DB_PATH", db_path)

    result = CliRunner().invoke(cli.main, ["campaign", "status", "--campaign-id", "camp"])

    assert result.exit_code == 0
    assert "camp-1" in result.output
    assert "new reachable issues" in result.output
    assert "50" in result.output


def test_db_reset_dry_run_deletes_nothing(tmp_path, monkeypatch):
    db_path = tmp_path / "state.db"
    results = tmp_path / "results"
    work = tmp_path / "work"
    db_path.write_text("db")
    results.mkdir()
    (results / "artifact").write_text("x")
    work.mkdir()
    (work / "scratch").write_text("x")

    monkeypatch.setattr(cli, "DB_PATH", db_path)
    monkeypatch.setattr(cli, "RESULTS_ROOT", results)
    monkeypatch.setattr(cli, "REPO_ROOT", tmp_path)

    result = CliRunner().invoke(cli.main, ["db", "reset", "--all", "--dry-run"])

    assert result.exit_code == 0
    assert db_path.exists()
    assert results.exists()
    assert work.exists()


def test_db_reset_yes_removes_only_database_by_default(tmp_path, monkeypatch):
    db_path = tmp_path / "state.db"
    results = tmp_path / "results"
    work = tmp_path / "work"
    db_path.write_text("db")
    results.mkdir()
    work.mkdir()

    monkeypatch.setattr(cli, "DB_PATH", db_path)
    monkeypatch.setattr(cli, "RESULTS_ROOT", results)
    monkeypatch.setattr(cli, "REPO_ROOT", tmp_path)

    result = CliRunner().invoke(cli.main, ["db", "reset", "--yes"])

    assert result.exit_code == 0
    assert not db_path.exists()
    assert results.exists()
    assert work.exists()


def test_db_reset_yes_all_removes_outputs(tmp_path, monkeypatch):
    db_path = tmp_path / "state.db"
    results = tmp_path / "results"
    work = tmp_path / "work"
    db_path.write_text("db")
    results.mkdir()
    work.mkdir()

    monkeypatch.setattr(cli, "DB_PATH", db_path)
    monkeypatch.setattr(cli, "RESULTS_ROOT", results)
    monkeypatch.setattr(cli, "REPO_ROOT", tmp_path)

    result = CliRunner().invoke(cli.main, ["db", "reset", "--yes", "--all"])

    assert result.exit_code == 0
    assert not db_path.exists()
    assert not results.exists()
    assert not work.exists()


def test_db_reset_requires_confirmation_without_yes(tmp_path, monkeypatch):
    db_path = tmp_path / "state.db"
    db_path.write_text("db")

    monkeypatch.setattr(cli, "DB_PATH", db_path)
    monkeypatch.setattr(cli, "RESULTS_ROOT", tmp_path / "results")
    monkeypatch.setattr(cli, "REPO_ROOT", tmp_path)

    result = CliRunner().invoke(cli.main, ["db", "reset"], input="n\n")

    assert result.exit_code == 1
    assert db_path.exists()
