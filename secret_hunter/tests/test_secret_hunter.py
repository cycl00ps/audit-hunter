from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner
from jsonschema import Draft7Validator

from audit_hunter_common.paths import project_paths
from secret_hunter import cli
from secret_hunter.parsers import dedupe_findings, parse_gitleaks


SCHEMA = Path(__file__).resolve().parent.parent / "schemas" / "secret_report.schema.json"


def test_gitleaks_parser_redacts_secret(tmp_path: Path) -> None:
    artifact = tmp_path / "gitleaks.json"
    artifact.write_text(json.dumps([
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API Key",
            "File": "app.py",
            "StartLine": 4,
            "EndLine": 4,
            "Match": "token = 'super-secret-value'",
            "Secret": "super-secret-value",
            "Fingerprint": "app.py:generic-api-key:4",
        }
    ]))

    findings = dedupe_findings(parse_gitleaks(artifact))

    assert len(findings) == 1
    text = json.dumps(findings)
    assert "super-secret-value" not in text
    assert "<redacted:" in findings[0]["redacted_evidence"]


def test_secret_hunter_cli_uses_bin_scanners_and_writes_schema_valid_report(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    bin_dir = tmp_path / "bin"
    scratch_dir = tmp_path / "scratch"
    reports_dir = tmp_path / "reports"
    repo.mkdir()
    bin_dir.mkdir()

    _write_executable(
        bin_dir / "trufflehog",
        """#!/bin/sh
printf '%s\n' '{"DetectorName":"AWS Access Key","Verified":true,"Redacted":"<redacted>","SourceMetadata":{"Data":{"Filesystem":{"file":"app.py","line":2}}}}'
""",
    )
    _write_executable(
        bin_dir / "gitleaks",
        """#!/bin/sh
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--report-path" ]; then
    shift
    out="$1"
  fi
  shift
done
printf '%s\n' '[{"RuleID":"generic-api-key","Description":"Generic API Key","File":"app.py","StartLine":3,"EndLine":3,"Match":"token=secret-value","Secret":"secret-value","Fingerprint":"app.py:generic:3"}]' > "$out"
exit 1
""",
    )

    result = CliRunner().invoke(
        cli.main,
        [
            "scan",
            "--repo",
            str(repo),
            "--run-id",
            "run1",
            "--bin-dir",
            str(bin_dir),
            "--scratch-dir",
            str(scratch_dir),
            "--reports-dir",
            str(reports_dir),
            "--no-ai-analysis",
        ],
    )

    assert result.exit_code == 0, result.output
    report_path = reports_dir / "run1" / "secret-hunter.report.json"
    payload = json.loads(report_path.read_text())
    Draft7Validator(json.loads(SCHEMA.read_text())).validate(payload)
    assert payload["summary"]["total"] == 2
    assert "secret-value" not in report_path.read_text()
    assert (scratch_dir / "artifacts" / "run1" / "secret-hunter" / "trufflehog.ndjson").exists()


def test_project_paths_env_overrides(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AUDIT_BIN_DIR", str(tmp_path / "tools"))
    monkeypatch.setenv("AUDIT_SCRATCH_DIR", str(tmp_path / "scratchy"))
    monkeypatch.setenv("AUDIT_REPORTS_DIR", str(tmp_path / "final"))

    paths = project_paths()

    assert paths.bin_dir == (tmp_path / "tools").resolve()
    assert paths.scratch_dir == (tmp_path / "scratchy").resolve()
    assert paths.reports_dir == (tmp_path / "final").resolve()


def _write_executable(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(path.stat().st_mode | 0o111)
