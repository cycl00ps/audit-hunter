from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from click.testing import CliRunner
from jsonschema import Draft7Validator
import pytest

from audit_hunter_common.paths import project_paths
from secret_hunter import cli
from secret_hunter.parsers import dedupe_findings, parse_gitleaks, parse_trufflehog


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
    assert "supe...alue" in findings[0]["redacted_evidence"]


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
    assert payload["scanner_runs"][0]["command"][1] == "filesystem"
    assert payload["scanner_runs"][1]["command"][1] == "dir"
    assert payload["scanner_runs"][1]["command"][2] == str(repo.resolve())
    assert "--source" not in payload["scanner_runs"][1]["command"]
    assert "--log-opts=--all" not in payload["scanner_runs"][1]["command"]
    assert "secret-value" not in report_path.read_text()
    assert (scratch_dir / "artifacts" / "run1" / "secret-hunter" / "trufflehog.ndjson").exists()


def test_secret_hunter_uses_git_history_modes_for_git_repo(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    bin_dir = tmp_path / "bin"
    scratch_dir = tmp_path / "scratch"
    reports_dir = tmp_path / "reports"
    repo.mkdir()
    bin_dir.mkdir()
    _init_git_repo(repo)

    _write_executable(
        bin_dir / "trufflehog",
        """#!/bin/sh
printf '%s\n' '{"DetectorName":"Generic Secret","Verified":true,"Raw":"super-secret-value","SourceMetadata":{"Data":{"Git":{"file":"app.py","line":4,"commit":"abc123"}}}}'
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
printf '%s\n' '[{"RuleID":"generic-api-key","Description":"Generic API Key","File":"app.py","StartLine":4,"EndLine":4,"Commit":"abc123","Match":"token=super-secret-value","Secret":"super-secret-value","Fingerprint":"app.py:generic:4"}]' > "$out"
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
    trufflehog_cmd = payload["scanner_runs"][0]["command"]
    gitleaks_cmd = payload["scanner_runs"][1]["command"]
    assert trufflehog_cmd[1] == "git"
    assert trufflehog_cmd[2].startswith("file://")
    assert gitleaks_cmd[1] == "git"
    assert gitleaks_cmd[2] == str(repo.resolve())
    assert "--source" not in gitleaks_cmd
    assert "--log-opts=--all" in gitleaks_cmd
    assert payload["summary"]["total"] == 1
    assert payload["findings"][0]["sources"] == ["trufflehog", "gitleaks"]
    assert len(payload["findings"][0]["raw_artifact_paths"]) == 2
    report_text = report_path.read_text()
    assert "super-secret-value" not in report_text
    assert "supe...alue" in report_text
    assert "token=" in payload["findings"][0]["redacted_evidence"]


def test_dedupe_merges_same_secret_from_trufflehog_and_gitleaks(tmp_path: Path) -> None:
    trufflehog_artifact = tmp_path / "trufflehog.ndjson"
    gitleaks_artifact = tmp_path / "gitleaks.json"
    trufflehog_artifact.write_text(
        '{"DetectorName":"Generic Secret","Verified":false,"Raw":"shared-secret-value",'
        '"SourceMetadata":{"Data":{"Git":{"file":"app.py","line":9,"commit":"abc123"}}}}\n'
    )
    gitleaks_artifact.write_text(json.dumps([
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API Key",
            "File": "app.py",
            "StartLine": 9,
            "EndLine": 9,
            "Commit": "abc123",
            "Match": "token=shared-secret-value",
            "Secret": "shared-secret-value",
            "Fingerprint": "app.py:generic:9",
        }
    ]))

    findings = dedupe_findings(parse_trufflehog(trufflehog_artifact) + parse_gitleaks(gitleaks_artifact))

    assert len(findings) == 1
    assert findings[0]["sources"] == ["trufflehog", "gitleaks"]
    assert len(findings[0]["raw_artifact_paths"]) == 2
    assert "shared-secret-value" not in json.dumps(findings)
    assert "shar...alue" in findings[0]["redacted_evidence"]


def test_dedupe_merges_multiline_secret_with_line_mismatch(tmp_path: Path) -> None:
    trufflehog_artifact = tmp_path / "trufflehog.ndjson"
    gitleaks_artifact = tmp_path / "gitleaks.json"
    secret = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc123\n-----END OPENSSH PRIVATE KEY-----\n"
    trufflehog_artifact.write_text(json.dumps({
        "DetectorName": "Private Key",
        "Verified": False,
        "Raw": secret,
        "Redacted": secret[:64],
        "SourceMetadata": {"Data": {"Git": {"file": "test_key", "commit": "abc123"}}},
    }) + "\n")
    gitleaks_artifact.write_text(json.dumps([
        {
            "RuleID": "private-key",
            "Description": "Private Key",
            "File": "test_key",
            "StartLine": 1,
            "EndLine": 3,
            "Commit": "abc123",
            "Match": secret,
            "Secret": secret.strip(),
            "Fingerprint": "test_key:private-key:1",
        }
    ]))

    findings = dedupe_findings(parse_trufflehog(trufflehog_artifact) + parse_gitleaks(gitleaks_artifact))

    assert len(findings) == 1
    assert findings[0]["sources"] == ["trufflehog", "gitleaks"]
    assert secret not in json.dumps(findings)
    assert "----...----" in findings[0]["redacted_evidence"]


def test_secret_hunter_cli_rejects_repo_url() -> None:
    result = CliRunner().invoke(cli.main, ["scan", "--repo-url", "https://example.com/repo.git"])

    assert result.exit_code != 0
    assert "--repo-url" in result.output


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


def _init_git_repo(path: Path) -> None:
    if shutil.which("git") is None:
        pytest.skip("git is required for git-mode scanner tests")
    subprocess.run(["git", "-C", str(path), "init"], text=True, capture_output=True, check=True)
