from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner
from jsonschema import Draft7Validator

from audit_hunter import cli


SCHEMA = Path(__file__).resolve().parent.parent / "audit_hunter" / "schemas" / "audit_report.schema.json"


def test_audit_hunter_combine_writes_envelope(tmp_path: Path) -> None:
    reports = tmp_path / "reports" / "run1"
    reports.mkdir(parents=True)
    (reports / "secret-hunter.report.json").write_text(json.dumps({
        "schema_version": "1.0",
        "tool": "secret-hunter",
        "run_id": "run1",
        "target": {"repo_path": "/repo"},
        "summary": {"total": 2},
        "scanner_runs": [],
        "findings": [],
    }))
    (reports / "vuln-hunter.report.json").write_text(json.dumps({
        "run_id": "run1",
        "target": {"repo_path": "/repo"},
        "summary": {"total": 1},
        "findings": [],
    }))

    result = CliRunner().invoke(
        cli.main,
        ["combine", "--run-id", "run1", "--reports-dir", str(tmp_path / "reports")],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads((reports / "audit-hunter.report.json").read_text())
    Draft7Validator(json.loads(SCHEMA.read_text())).validate(payload)
    assert payload["summary"] == {
        "total": 3,
        "by_tool": {"secret-hunter": 2, "vuln-hunter": 1},
    }
