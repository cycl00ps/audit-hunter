"""SQLite-backed run state. JSONL artifacts in results/ are the source of
truth for raw agent output; this DB is the queryable index used for
orchestration, resume, and reporting."""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


SCHEMA_VERSION = 3


class LegacyDatabaseError(RuntimeError):
    """Raised when an existing state.db was created with an incompatible schema."""


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    repo_path TEXT NOT NULL,
    started_at REAL NOT NULL,
    finished_at REAL,
    status TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS recon_outputs (
    run_id TEXT PRIMARY KEY,
    raw_json TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS tasks (
    run_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    source TEXT NOT NULL,
    attack_class TEXT NOT NULL,
    scope_hint TEXT NOT NULL,
    target_files TEXT NOT NULL,
    rationale TEXT,
    priority INTEGER NOT NULL DEFAULT 3,
    status TEXT NOT NULL DEFAULT 'pending',
    raw_json TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (run_id, task_id),
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS findings (
    run_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    file TEXT NOT NULL,
    line_start INTEGER NOT NULL,
    line_end INTEGER NOT NULL,
    vuln_class TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT NOT NULL,
    poc_succeeded INTEGER DEFAULT 0,
    confidence REAL,
    raw_json TEXT NOT NULL,
    validation_status TEXT,
    validation_json TEXT,
    group_id TEXT,
    is_canonical INTEGER DEFAULT 0,
    PRIMARY KEY (run_id, finding_id),
    FOREIGN KEY (run_id, task_id) REFERENCES tasks(run_id, task_id)
);

CREATE TABLE IF NOT EXISTS traces (
    run_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    reachable INTEGER NOT NULL,
    confidence REAL,
    rationale TEXT,
    raw_json TEXT NOT NULL,
    PRIMARY KEY (run_id, finding_id),
    FOREIGN KEY (run_id, finding_id) REFERENCES findings(run_id, finding_id)
);

CREATE TABLE IF NOT EXISTS dedupe_groups (
    run_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    root_cause TEXT NOT NULL,
    canonical_finding_id TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    PRIMARY KEY (run_id, group_id),
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS costs (
    cost_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    ref_id TEXT,
    usd REAL,
    input_tokens INTEGER,
    output_tokens INTEGER,
    cache_read_tokens INTEGER,
    cache_creation_tokens INTEGER,
    num_turns INTEGER,
    duration_ms INTEGER,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    ref_id TEXT,
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id TEXT PRIMARY KEY,
    repo_path TEXT NOT NULL,
    requested_runs INTEGER NOT NULL,
    max_tokens INTEGER,
    stop_after_empty INTEGER NOT NULL,
    seed_run_ids TEXT NOT NULL,
    started_at REAL NOT NULL,
    finished_at REAL,
    status TEXT NOT NULL DEFAULT 'running',
    stop_reason TEXT
);

CREATE TABLE IF NOT EXISTS campaign_runs (
    campaign_id TEXT NOT NULL,
    child_run_id TEXT NOT NULL,
    run_index INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'running',
    tokens INTEGER NOT NULL DEFAULT 0,
    new_reachable_issue_count INTEGER NOT NULL DEFAULT 0,
    started_at REAL NOT NULL,
    finished_at REAL,
    PRIMARY KEY (campaign_id, child_run_id),
    UNIQUE (campaign_id, run_index),
    FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id)
);

CREATE INDEX IF NOT EXISTS idx_tasks_run_status ON tasks(run_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_validation ON findings(validation_status);
CREATE INDEX IF NOT EXISTS idx_findings_group ON findings(group_id);
CREATE INDEX IF NOT EXISTS idx_costs_run_stage ON costs(run_id, stage);
CREATE INDEX IF NOT EXISTS idx_campaign_runs_campaign ON campaign_runs(campaign_id, run_index);
"""


MIGRATION_V2_TO_V3 = """
CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id TEXT PRIMARY KEY,
    repo_path TEXT NOT NULL,
    requested_runs INTEGER NOT NULL,
    max_tokens INTEGER,
    stop_after_empty INTEGER NOT NULL,
    seed_run_ids TEXT NOT NULL,
    started_at REAL NOT NULL,
    finished_at REAL,
    status TEXT NOT NULL DEFAULT 'running',
    stop_reason TEXT
);

CREATE TABLE IF NOT EXISTS campaign_runs (
    campaign_id TEXT NOT NULL,
    child_run_id TEXT NOT NULL,
    run_index INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'running',
    tokens INTEGER NOT NULL DEFAULT 0,
    new_reachable_issue_count INTEGER NOT NULL DEFAULT 0,
    started_at REAL NOT NULL,
    finished_at REAL,
    PRIMARY KEY (campaign_id, child_run_id),
    UNIQUE (campaign_id, run_index),
    FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id)
);

CREATE INDEX IF NOT EXISTS idx_campaign_runs_campaign ON campaign_runs(campaign_id, run_index);
"""


@dataclass
class Task:
    task_id: str
    run_id: str
    source: str
    attack_class: str
    scope_hint: str
    target_files: list[str]
    rationale: str
    priority: int
    status: str
    raw_json: dict


@dataclass
class Finding:
    finding_id: str
    task_id: str
    run_id: str
    file: str
    line_start: int
    line_end: int
    vuln_class: str
    severity: str
    description: str
    evidence: str
    poc_succeeded: bool
    confidence: float | None
    raw_json: dict
    validation_status: str | None
    validation_json: dict | None
    group_id: str | None
    is_canonical: bool


class StateDB:
    def __init__(self, db_path: Path):
        self.path = db_path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        user_version = int(
            self._conn.execute("PRAGMA user_version").fetchone()[0]
        )
        has_tables = bool(
            self._conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' LIMIT 1"
            ).fetchone()
        )
        if has_tables and user_version not in {SCHEMA_VERSION, 2}:
            self._conn.close()
            raise LegacyDatabaseError(
                f"{self.path} uses legacy schema version {user_version}; "
                "run `audit db reset --yes` to create a fresh database."
            )
        if has_tables and user_version == 2:
            self._conn.executescript(MIGRATION_V2_TO_V3)
        self._conn.executescript(SCHEMA)
        self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        self._conn.commit()

    # ---------- runs ----------

    def create_run(self, repo_path: str, run_id: str | None = None) -> str:
        run_id = run_id or f"run_{uuid.uuid4().hex[:8]}"
        self._conn.execute(
            "INSERT INTO runs (run_id, repo_path, started_at, status) VALUES (?, ?, ?, ?)",
            (run_id, repo_path, time.time(), "running"),
        )
        self._conn.commit()
        return run_id

    def finish_run(self, run_id: str, status: str = "completed") -> None:
        self._conn.execute(
            "UPDATE runs SET status = ?, finished_at = ? WHERE run_id = ?",
            (status, time.time(), run_id),
        )
        self._conn.commit()

    def get_run(self, run_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()

    def list_runs(self) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                "SELECT * FROM runs ORDER BY started_at DESC"
            ).fetchall()
        )

    # ---------- campaigns ----------

    def create_campaign(
        self,
        *,
        campaign_id: str,
        repo_path: str,
        requested_runs: int,
        max_tokens: int | None,
        stop_after_empty: int,
        seed_run_ids: list[str],
    ) -> None:
        self._conn.execute(
            """INSERT INTO campaigns
            (campaign_id, repo_path, requested_runs, max_tokens, stop_after_empty,
             seed_run_ids, started_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'running')""",
            (
                campaign_id,
                repo_path,
                requested_runs,
                max_tokens,
                stop_after_empty,
                json.dumps(seed_run_ids),
                time.time(),
            ),
        )
        self._conn.commit()

    def finish_campaign(
        self, campaign_id: str, status: str = "completed", stop_reason: str | None = None
    ) -> None:
        self._conn.execute(
            """UPDATE campaigns
            SET status = ?, stop_reason = ?, finished_at = ?
            WHERE campaign_id = ?""",
            (status, stop_reason, time.time(), campaign_id),
        )
        self._conn.commit()

    def get_campaign(self, campaign_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM campaigns WHERE campaign_id = ?", (campaign_id,)
        ).fetchone()

    def list_campaigns(self) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                "SELECT * FROM campaigns ORDER BY started_at DESC"
            ).fetchall()
        )

    def start_campaign_run(
        self, campaign_id: str, child_run_id: str, run_index: int
    ) -> None:
        self._conn.execute(
            """INSERT INTO campaign_runs
            (campaign_id, child_run_id, run_index, status, started_at)
            VALUES (?, ?, ?, 'running', ?)""",
            (campaign_id, child_run_id, run_index, time.time()),
        )
        self._conn.commit()

    def finish_campaign_run(
        self,
        campaign_id: str,
        child_run_id: str,
        *,
        status: str,
        tokens: int,
        new_reachable_issue_count: int,
    ) -> None:
        self._conn.execute(
            """UPDATE campaign_runs
            SET status = ?, tokens = ?, new_reachable_issue_count = ?, finished_at = ?
            WHERE campaign_id = ? AND child_run_id = ?""",
            (
                status,
                tokens,
                new_reachable_issue_count,
                time.time(),
                campaign_id,
                child_run_id,
            ),
        )
        self._conn.commit()

    def list_campaign_runs(self, campaign_id: str) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                """SELECT * FROM campaign_runs
                WHERE campaign_id = ?
                ORDER BY run_index""",
                (campaign_id,),
            ).fetchall()
        )

    def campaign_total_tokens(self, campaign_id: str) -> int:
        total = 0
        for row in self.list_campaign_runs(campaign_id):
            total += max(int(row["tokens"]), self.total_tokens(row["child_run_id"]))
        return total

    # ---------- recon ----------

    def save_recon_output(self, run_id: str, payload: dict) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO recon_outputs (run_id, raw_json) VALUES (?, ?)",
            (run_id, json.dumps(payload)),
        )
        self._conn.commit()

    def get_recon_output(self, run_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT raw_json FROM recon_outputs WHERE run_id = ?", (run_id,)
        ).fetchone()
        return json.loads(row["raw_json"]) if row else None

    # ---------- tasks ----------

    def add_task(self, run_id: str, task: dict) -> bool:
        now = time.time()
        cur = self._conn.execute(
            """INSERT OR IGNORE INTO tasks
            (run_id, task_id, source, attack_class, scope_hint, target_files,
             rationale, priority, status, raw_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)""",
            (
                run_id,
                task["task_id"],
                task.get("source", "recon"),
                task["attack_class"],
                task["scope_hint"],
                json.dumps(task["target_files"]),
                task.get("rationale", ""),
                int(task.get("priority", 3)),
                json.dumps(task),
                now,
                now,
            ),
        )
        self._conn.commit()
        return cur.rowcount == 1

    def get_pending_tasks(self, run_id: str) -> list[Task]:
        rows = self._conn.execute(
            "SELECT * FROM tasks WHERE run_id = ? AND status = 'pending' ORDER BY priority, created_at",
            (run_id,),
        ).fetchall()
        return [self._row_to_task(r) for r in rows]

    def get_all_tasks(self, run_id: str) -> list[Task]:
        rows = self._conn.execute(
            "SELECT * FROM tasks WHERE run_id = ? ORDER BY created_at",
            (run_id,),
        ).fetchall()
        return [self._row_to_task(r) for r in rows]

    def update_task_status(self, run_id: str, task_id: str, status: str) -> None:
        self._conn.execute(
            "UPDATE tasks SET status = ?, updated_at = ? WHERE run_id = ? AND task_id = ?",
            (status, time.time(), run_id, task_id),
        )
        self._conn.commit()

    def record_task_result(self, run_id: str, task_id: str, payload: dict) -> None:
        row = self._conn.execute(
            "SELECT raw_json FROM tasks WHERE run_id = ? AND task_id = ?",
            (run_id, task_id),
        ).fetchone()
        if row is None:
            return
        raw = json.loads(row["raw_json"])
        raw["_hunt_result"] = payload
        self._conn.execute(
            "UPDATE tasks SET raw_json = ?, updated_at = ? WHERE run_id = ? AND task_id = ?",
            (json.dumps(raw), time.time(), run_id, task_id),
        )
        self._conn.commit()

    @staticmethod
    def _row_to_task(r: sqlite3.Row) -> Task:
        return Task(
            task_id=r["task_id"],
            run_id=r["run_id"],
            source=r["source"],
            attack_class=r["attack_class"],
            scope_hint=r["scope_hint"],
            target_files=json.loads(r["target_files"]),
            rationale=r["rationale"] or "",
            priority=r["priority"],
            status=r["status"],
            raw_json=json.loads(r["raw_json"]),
        )

    # ---------- findings ----------

    def add_finding(self, run_id: str, task_id: str, finding: dict) -> bool:
        poc = finding.get("poc") or {}
        cur = self._conn.execute(
            """INSERT OR IGNORE INTO findings
            (run_id, finding_id, task_id, file, line_start, line_end,
             vuln_class, severity, description, evidence, poc_succeeded,
             confidence, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                finding["finding_id"],
                task_id,
                finding["file"],
                finding["line_start"],
                finding["line_end"],
                finding["vuln_class"],
                finding["severity"],
                finding["description"],
                finding["evidence_snippet"],
                1 if poc.get("succeeded") else 0,
                finding.get("confidence"),
                json.dumps(finding),
            ),
        )
        self._conn.commit()
        return cur.rowcount == 1

    def get_findings(self, run_id: str, *, validation_status: str | None = None,
                     canonical_only: bool = False) -> list[Finding]:
        sql = "SELECT * FROM findings WHERE run_id = ?"
        args: list[Any] = [run_id]
        if validation_status is not None:
            sql += " AND validation_status = ?"
            args.append(validation_status)
        if canonical_only:
            sql += " AND is_canonical = 1"
        rows = self._conn.execute(sql, args).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def get_unvalidated_findings(self, run_id: str) -> list[Finding]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE run_id = ? AND validation_status IS NULL",
            (run_id,),
        ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def set_finding_validation(
        self, run_id: str, finding_id: str, status: str, payload: dict
    ) -> None:
        self._conn.execute(
            """UPDATE findings
            SET validation_status = ?, validation_json = ?
            WHERE run_id = ? AND finding_id = ?""",
            (status, json.dumps(payload), run_id, finding_id),
        )
        self._conn.commit()

    def assign_finding_group(
        self, run_id: str, finding_id: str, group_id: str, is_canonical: bool
    ) -> None:
        self._conn.execute(
            """UPDATE findings
            SET group_id = ?, is_canonical = ?
            WHERE run_id = ? AND finding_id = ?""",
            (group_id, 1 if is_canonical else 0, run_id, finding_id),
        )
        self._conn.commit()

    @staticmethod
    def _row_to_finding(r: sqlite3.Row) -> Finding:
        return Finding(
            finding_id=r["finding_id"],
            task_id=r["task_id"],
            run_id=r["run_id"],
            file=r["file"],
            line_start=r["line_start"],
            line_end=r["line_end"],
            vuln_class=r["vuln_class"],
            severity=r["severity"],
            description=r["description"],
            evidence=r["evidence"],
            poc_succeeded=bool(r["poc_succeeded"]),
            confidence=r["confidence"],
            raw_json=json.loads(r["raw_json"]),
            validation_status=r["validation_status"],
            validation_json=json.loads(r["validation_json"]) if r["validation_json"] else None,
            group_id=r["group_id"],
            is_canonical=bool(r["is_canonical"]),
        )

    # ---------- traces ----------

    def add_trace(self, run_id: str, finding_id: str, payload: dict) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO traces
            (run_id, finding_id, reachable, confidence, rationale, raw_json)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                finding_id,
                1 if payload.get("reachable") else 0,
                payload.get("confidence"),
                payload.get("rationale", ""),
                json.dumps(payload),
            ),
        )
        self._conn.commit()

    def get_trace(self, run_id: str, finding_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT raw_json FROM traces WHERE run_id = ? AND finding_id = ?",
            (run_id, finding_id),
        ).fetchone()
        return json.loads(row["raw_json"]) if row else None

    def get_reachable_canonical_findings(self, run_id: str) -> list[tuple[Finding, dict]]:
        out: list[tuple[Finding, dict]] = []
        for f in self.get_findings(run_id, validation_status="confirmed", canonical_only=True):
            tr = self.get_trace(run_id, f.finding_id)
            if tr and tr.get("reachable"):
                out.append((f, tr))
        return out

    # ---------- dedupe ----------

    def add_dedupe_group(self, run_id: str, group: dict) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO dedupe_groups
            (run_id, group_id, root_cause, canonical_finding_id, raw_json)
            VALUES (?, ?, ?, ?, ?)""",
            (
                run_id,
                group["group_id"],
                group["root_cause"],
                group["canonical_finding_id"],
                json.dumps(group),
            ),
        )
        self._conn.commit()

    def get_dedupe_group(self, run_id: str, group_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT raw_json FROM dedupe_groups WHERE run_id = ? AND group_id = ?",
            (run_id, group_id),
        ).fetchone()
        return json.loads(row["raw_json"]) if row else None

    # ---------- usage records ----------

    def record_cost(
        self,
        run_id: str,
        stage: str,
        ref_id: str | None,
        result_msg: dict,
    ) -> None:
        usage = result_msg.get("usage") or {}
        self._conn.execute(
            """INSERT INTO costs
            (run_id, stage, ref_id, usd, input_tokens, output_tokens,
             cache_read_tokens, cache_creation_tokens, num_turns, duration_ms, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                stage,
                ref_id,
                result_msg.get("total_cost_usd"),
                usage.get("input_tokens"),
                usage.get("output_tokens"),
                usage.get("cache_read_input_tokens"),
                usage.get("cache_creation_input_tokens"),
                result_msg.get("num_turns"),
                result_msg.get("duration_ms"),
                time.time(),
            ),
        )
        self._conn.commit()

    def total_cost(self, run_id: str) -> float:
        row = self._conn.execute(
            "SELECT COALESCE(SUM(usd), 0) AS total FROM costs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        return float(row["total"]) if row else 0.0

    def total_input_tokens(self, run_id: str) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(SUM(input_tokens), 0) AS total FROM costs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        return int(row["total"]) if row else 0

    def total_output_tokens(self, run_id: str) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(SUM(output_tokens), 0) AS total FROM costs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        return int(row["total"]) if row else 0

    def total_tokens(self, run_id: str) -> int:
        return self.total_input_tokens(run_id) + self.total_output_tokens(run_id)

    # ---------- artifacts ----------

    def add_artifact(
        self, run_id: str, stage: str, ref_id: str | None, kind: str, path: str
    ) -> None:
        self._conn.execute(
            """INSERT INTO artifacts
            (run_id, stage, ref_id, kind, path, created_at)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (run_id, stage, ref_id, kind, path, time.time()),
        )
        self._conn.commit()

    # ---------- context manager ----------

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "StateDB":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


@contextmanager
def open_db(path: Path) -> Iterator[StateDB]:
    db = StateDB(path)
    try:
        yield db
    finally:
        db.close()
