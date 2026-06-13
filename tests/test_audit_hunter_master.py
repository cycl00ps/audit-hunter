from __future__ import annotations

import json
import subprocess
from pathlib import Path

from click.testing import CliRunner
from jsonschema import Draft7Validator

from audit_hunter import assessment as assessment_mod
from audit_hunter import cli
from audit_hunter import threat_model as threat_model_mod


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


def test_audit_hunter_threat_model_writes_target_and_report_artifacts(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    reports = tmp_path / "reports"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        "[project]\ndependencies = ['fastapi>=0.1', 'click>=8']\n"
    )
    (repo / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")

    result = CliRunner().invoke(
        cli.main,
        [
            "threat-model",
            "--repo",
            str(repo),
            "--run-id",
            "run1",
            "--mode",
            "deterministic",
            "--reports-dir",
            str(reports),
        ],
    )

    assert result.exit_code == 0, result.output
    target_threat_model = repo / ".audit-hunter" / "threat-model.md"
    target_config = repo / ".audit-hunter" / "security-config.json"
    report_threat_model = reports / "run1" / "threat-model.md"
    report_config = reports / "run1" / "security-config.json"
    assert target_threat_model.exists()
    assert target_config.exists()
    assert report_threat_model.read_text() == target_threat_model.read_text()
    assert report_config.read_text() == target_config.read_text()

    payload = json.loads(target_config.read_text())
    assert payload["artifact_root"] == ".audit-hunter"
    assert "Python" in payload["tech_stack"]
    assert "FastAPI" in payload["tech_stack"]
    assert "# Threat Model for repo" in target_threat_model.read_text()


def test_audit_hunter_threat_model_defaults_to_ai_and_writes_same_artifacts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = tmp_path / "repo"
    reports = tmp_path / "reports"
    scratch = tmp_path / "scratch"
    repo.mkdir()
    (repo / "app.py").write_text("def login():\n    pass\n")
    calls: list[str] = []

    def fake_codex_stage(**kwargs):
        calls.append(kwargs["stage_name"])
        if kwargs["stage_name"] == "understanding":
            return json.dumps({
                "repo_purpose": "AI-understood test application",
                "components": [],
                "data_flows": [],
                "trust_boundaries": {},
                "auth_mechanism": "login function",
                "sensitive_assets": [],
                "stride_risks": [],
                "excluded_paths": ["tests/"],
                "tech_stack": ["Python"],
                "assumptions": [],
                "files_inspected": ["app.py"],
            })
        return json.dumps({
            "threat_model_markdown": _valid_threat_model_text("repo", "AI-authored"),
            "security_config": _valid_security_config(["Python"]),
        })

    monkeypatch.setattr(threat_model_mod, "_run_codex_stage", fake_codex_stage)

    result = CliRunner().invoke(
        cli.main,
        [
            "threat-model",
            "--repo",
            str(repo),
            "--run-id",
            "run1",
            "--scratch-dir",
            str(scratch),
            "--reports-dir",
            str(reports),
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls == ["understanding", "render"]
    assert "AI understanding pass starting" in result.output
    target_threat_model = repo / ".audit-hunter" / "threat-model.md"
    report_threat_model = reports / "run1" / "threat-model.md"
    assert "AI-authored" in target_threat_model.read_text()
    assert report_threat_model.read_text() == target_threat_model.read_text()
    assert (
        scratch / "artifacts" / "run1" / "audit-hunter" / "threat-model-profile-seed.json"
    ).exists()


def test_audit_hunter_threat_model_edit_updates_report_copy(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = tmp_path / "repo"
    reports = tmp_path / "reports"
    repo.mkdir()
    (repo / "app.py").write_text("print('hello')\n")

    def fake_editor(command, check):
        assert check is False
        Path(command[-1]).write_text(_valid_threat_model_text("repo", "Edited"))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(threat_model_mod.subprocess, "run", fake_editor)

    result = CliRunner().invoke(
        cli.main,
        [
            "threat-model",
            "--repo",
            str(repo),
            "--run-id",
            "run1",
            "--reports-dir",
            str(reports),
            "--mode",
            "deterministic",
            "--edit-threat-model",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Edited" in (repo / ".audit-hunter" / "threat-model.md").read_text()
    assert "Edited" in (reports / "run1" / "threat-model.md").read_text()


def test_audit_hunter_threat_model_ai_rejects_invalid_markdown(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hello')\n")

    def fake_codex_stage(**kwargs):
        if kwargs["stage_name"] == "understanding":
            return json.dumps({"repo_purpose": "test"})
        return json.dumps({
            "threat_model_markdown": "# Not the right format\n",
            "security_config": _valid_security_config(["Python"]),
        })

    monkeypatch.setattr(threat_model_mod, "_run_codex_stage", fake_codex_stage)

    result = CliRunner().invoke(
        cli.main,
        [
            "threat-model",
            "--repo",
            str(repo),
            "--run-id",
            "run1",
            "--reports-dir",
            str(tmp_path / "reports"),
        ],
    )

    assert result.exit_code == 1
    assert "missing required section" in result.output


def test_audit_hunter_assess_runs_tools_and_passes_generated_scope(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = tmp_path / "repo"
    reports = tmp_path / "reports"
    scratch = tmp_path / "scratch"
    bin_dir = tmp_path / "bin"
    user_scope = tmp_path / "scope.md"
    repo.mkdir()
    bin_dir.mkdir()
    (repo / "pyproject.toml").write_text("[project]\ndependencies = ['fastapi']\n")
    (repo / "app.py").write_text("def login():\n    pass\n")
    user_scope.write_text("Only consider high-impact auth bugs.")

    events: list[str] = []
    commands: list[list[str]] = []

    def fake_scan_repository(**kwargs):
        events.append("secret")
        assert kwargs["repo_path"] == repo.resolve()
        assert kwargs["run_id"] == "run1"
        assert kwargs["paths"].bin_dir == bin_dir.resolve()
        assert kwargs["ai_analysis"] is False
        assert kwargs["verify"] is False
        assert (repo / ".audit-hunter" / "threat-model.md").exists()
        report = reports / "run1" / "secret-hunter.report.json"
        _write_tool_report(report, "secret-hunter", 2, repo)
        return report

    def fake_vuln_run(command, check):
        events.append("vuln")
        commands.append(command)
        assert check is False
        assert events == ["secret", "vuln"]
        scope_path = Path(command[command.index("--scope-notes") + 1])
        scope_text = scope_path.read_text()
        assert "# audit-hunter Generated Vulnerability Scope" in scope_text
        assert "# Threat Model for repo" in scope_text
        assert "Only consider high-impact auth bugs." in scope_text
        assert str(scratch / "artifacts" / "run1" / "audit-hunter") in str(scope_path)
        _write_tool_report(reports / "run1" / "vuln-hunter.report.json", "vuln-hunter", 1, repo)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(assessment_mod, "scan_repository", fake_scan_repository)
    monkeypatch.setattr(assessment_mod.subprocess, "run", fake_vuln_run)

    result = CliRunner().invoke(
        cli.main,
        [
            "assess",
            "--repo",
            str(repo),
            "--run-id",
            "run1",
            "--bin-dir",
            str(bin_dir),
            "--scratch-dir",
            str(scratch),
            "--reports-dir",
            str(reports),
            "--threat-model-mode",
            "deterministic",
            "--no-ai-analysis",
            "--no-verify",
            "--max-tokens",
            "123",
            "--max-concurrency",
            "1",
            "--max-recon-tasks",
            "2",
            "--target-url",
            "http://localhost:8888",
            "--target-creds",
            "email=user@example.com",
            "--scope-notes",
            str(user_scope),
            "--provider",
            "codex",
            "--vuln-command",
            "vuln-hunter",
        ],
    )

    assert result.exit_code == 0, result.output
    assert events == ["secret", "vuln"]
    command = commands[0]
    assert command[:2] == ["vuln-hunter", "run"]
    assert _option_value(command, "--repo") == str(repo.resolve())
    assert _option_value(command, "--run-id") == "run1"
    assert _option_value(command, "--reports-dir") == str(reports.resolve())
    assert _option_value(command, "--scratch-dir") == str(scratch.resolve())
    assert _option_value(command, "--max-tokens") == "123"
    assert _option_value(command, "--max-concurrency") == "1"
    assert _option_value(command, "--max-recon-tasks") == "2"
    assert _option_value(command, "--target-url") == "http://localhost:8888"
    assert _option_value(command, "--target-creds") == "email=user@example.com"
    assert _option_value(command, "--provider") == "codex"

    combined = json.loads((reports / "run1" / "audit-hunter.report.json").read_text())
    assert combined["summary"]["total"] == 3
    assert combined["summary"]["by_tool"] == {
        "secret-hunter": 2,
        "vuln-hunter": 1,
    }


def test_audit_hunter_assess_skip_threat_model_reuses_existing_artifacts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = tmp_path / "repo"
    reports = tmp_path / "reports"
    scratch = tmp_path / "scratch"
    repo.mkdir()
    artifact_dir = repo / ".audit-hunter"
    artifact_dir.mkdir()
    (artifact_dir / "threat-model.md").write_text("# Existing threat model\n")
    (artifact_dir / "security-config.json").write_text(json.dumps({
        "version": "1.0.0",
        "generated": "2026-06-05T00:00:00+10:00",
        "severity_thresholds": {
            "block_merge": "CRITICAL",
            "require_review": "HIGH",
            "inform": "MEDIUM",
        },
        "confidence_threshold": 0.8,
        "excluded_paths": ["tests/"],
        "tech_stack": ["Python"],
        "artifact_root": ".audit-hunter",
    }) + "\n")

    def fake_scan_repository(**kwargs):
        report = reports / "run1" / "secret-hunter.report.json"
        _write_tool_report(report, "secret-hunter", 0, repo)
        return report

    def fake_vuln_run(command, check):
        scope_path = Path(command[command.index("--scope-notes") + 1])
        assert "# Existing threat model" in scope_path.read_text()
        _write_tool_report(reports / "run1" / "vuln-hunter.report.json", "vuln-hunter", 0, repo)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(assessment_mod, "scan_repository", fake_scan_repository)
    monkeypatch.setattr(assessment_mod.subprocess, "run", fake_vuln_run)

    result = CliRunner().invoke(
        cli.main,
        [
            "assess",
            "--repo",
            str(repo),
            "--run-id",
            "run1",
            "--reports-dir",
            str(reports),
            "--scratch-dir",
            str(scratch),
            "--skip-threat-model",
            "--vuln-command",
            "vuln-hunter",
        ],
    )

    assert result.exit_code == 0, result.output
    assert (reports / "run1" / "threat-model.md").read_text() == "# Existing threat model\n"
    assert (reports / "run1" / "audit-hunter.report.json").exists()


def test_audit_hunter_assess_threat_scope_runs_zero_keeps_user_scope_only(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = tmp_path / "repo"
    reports = tmp_path / "reports"
    scratch = tmp_path / "scratch"
    user_scope = tmp_path / "scope.md"
    repo.mkdir()
    (repo / "app.py").write_text("print('hello')\n")
    user_scope.write_text("User exclusions apply.")

    def fake_scan_repository(**kwargs):
        report = reports / "run1" / "secret-hunter.report.json"
        _write_tool_report(report, "secret-hunter", 0, repo)
        return report

    def fake_vuln_run(command, check):
        scope_path = Path(command[command.index("--scope-notes") + 1])
        scope_text = scope_path.read_text()
        assert "User exclusions apply." in scope_text
        assert "# audit-hunter Generated Vulnerability Scope" not in scope_text
        _write_tool_report(reports / "run1" / "vuln-hunter.report.json", "vuln-hunter", 0, repo)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(assessment_mod, "scan_repository", fake_scan_repository)
    monkeypatch.setattr(assessment_mod.subprocess, "run", fake_vuln_run)

    result = CliRunner().invoke(
        cli.main,
        [
            "assess",
            "--repo",
            str(repo),
            "--run-id",
            "run1",
            "--reports-dir",
            str(reports),
            "--scratch-dir",
            str(scratch),
            "--threat-model-mode",
            "deterministic",
            "--scope-notes",
            str(user_scope),
            "--threat-scope-runs",
            "0",
            "--vuln-command",
            "vuln-hunter",
        ],
    )

    assert result.exit_code == 0, result.output


def test_audit_hunter_assess_campaign_targets_first_run_by_default(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = tmp_path / "repo"
    reports = tmp_path / "reports"
    scratch = tmp_path / "scratch"
    user_scope = tmp_path / "scope.md"
    repo.mkdir()
    (repo / "app.py").write_text("def auth():\n    pass\n")
    user_scope.write_text("All campaign runs must stay in scope.")
    commands: list[list[str]] = []

    def fake_scan_repository(**kwargs):
        report = reports / "camp1" / "secret-hunter.report.json"
        _write_tool_report(report, "secret-hunter", 1, repo, run_id="camp1")
        return report

    def fake_vuln_run(command, check):
        commands.append(command)
        targeted_path = Path(command[command.index("--targeted-scope-notes") + 1])
        targeted_text = targeted_path.read_text()
        assert "# audit-hunter Generated Vulnerability Scope" in targeted_text
        assert "All campaign runs must stay in scope." not in targeted_text
        assert _option_value(command, "--scope-notes") == str(user_scope)
        _write_tool_report(reports / "camp1" / "campaign.report.json", "campaign", 2, repo, run_id="camp1")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(assessment_mod, "scan_repository", fake_scan_repository)
    monkeypatch.setattr(assessment_mod.subprocess, "run", fake_vuln_run)

    result = CliRunner().invoke(
        cli.main,
        [
            "assess",
            "--repo",
            str(repo),
            "--run-id",
            "camp1",
            "--reports-dir",
            str(reports),
            "--scratch-dir",
            str(scratch),
            "--threat-model-mode",
            "deterministic",
            "--vuln-mode",
            "campaign",
            "--runs",
            "3",
            "--stop-after-empty",
            "2",
            "--seed-run-id",
            "seed-a",
            "--scope-notes",
            str(user_scope),
            "--vuln-command",
            "vuln-hunter",
        ],
    )

    assert result.exit_code == 0, result.output
    command = commands[0]
    assert command[:3] == ["vuln-hunter", "campaign", "run"]
    assert _option_value(command, "--campaign-id") == "camp1"
    assert _option_value(command, "--runs") == "3"
    assert _option_value(command, "--stop-after-empty") == "2"
    assert _option_value(command, "--targeted-scope-runs") == "1"
    assert _option_value(command, "--seed-run-id") == "seed-a"
    combined = json.loads((reports / "camp1" / "audit-hunter.report.json").read_text())
    assert combined["summary"]["total"] == 3
    assert combined["summary"]["by_tool"] == {
        "campaign": 2,
        "secret-hunter": 1,
    }


def test_audit_hunter_assess_rejects_too_many_threat_scope_runs(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    result = CliRunner().invoke(
        cli.main,
        [
            "assess",
            "--repo",
            str(repo),
            "--run-id",
            "camp1",
            "--reports-dir",
            str(tmp_path / "reports"),
            "--vuln-mode",
            "campaign",
            "--runs",
            "2",
            "--threat-scope-runs",
            "3",
            "--vuln-command",
            "vuln-hunter",
        ],
    )

    assert result.exit_code == 1
    assert "--threat-scope-runs cannot exceed --runs" in result.output


def test_audit_hunter_assess_skip_threat_model_fails_when_artifacts_missing(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    result = CliRunner().invoke(
        cli.main,
        [
            "assess",
            "--repo",
            str(repo),
            "--run-id",
            "run1",
            "--reports-dir",
            str(tmp_path / "reports"),
            "--skip-threat-model",
            "--vuln-command",
            "vuln-hunter",
        ],
    )

    assert result.exit_code == 1
    assert "missing threat model artifacts" in result.output


def test_audit_hunter_assess_fails_on_vuln_nonzero_without_combining(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = tmp_path / "repo"
    reports = tmp_path / "reports"
    repo.mkdir()
    (repo / "app.py").write_text("print('hello')\n")

    def fake_scan_repository(**kwargs):
        report = reports / "run1" / "secret-hunter.report.json"
        _write_tool_report(report, "secret-hunter", 0, repo)
        return report

    def fake_vuln_run(command, check):
        return subprocess.CompletedProcess(command, 2)

    monkeypatch.setattr(assessment_mod, "scan_repository", fake_scan_repository)
    monkeypatch.setattr(assessment_mod.subprocess, "run", fake_vuln_run)

    result = CliRunner().invoke(
        cli.main,
        [
            "assess",
            "--repo",
            str(repo),
            "--run-id",
            "run1",
            "--reports-dir",
            str(reports),
            "--scratch-dir",
            str(tmp_path / "scratch"),
            "--threat-model-mode",
            "deterministic",
            "--vuln-command",
            "vuln-hunter",
        ],
    )

    assert result.exit_code == 1
    assert "vulnerability scan failed with exit code 2" in result.output
    assert not (reports / "run1" / "audit-hunter.report.json").exists()


def _valid_threat_model_text(repo_name: str, marker: str) -> str:
    return "\n".join([
        f"# Threat Model for {repo_name}",
        "",
        "**Generated:** 2026-06-13T00:00:00+10:00",
        "**Version:** 1.0.0",
        "**Methodology:** STRIDE",
        "",
        "## 1. System Overview",
        "",
        f"{marker} repository overview.",
        "",
        "### Key Components",
        "",
        "| Component | Purpose | Security Criticality | Entry Points |",
        "|-----------|---------|---------------------|--------------|",
        "| App | Handles requests | HIGH | `app.py` |",
        "",
        "### Data Flow",
        "",
        "Data enters through `app.py` and leaves through responses.",
        "",
        "## 2. Trust Boundaries",
        "",
        "**Zone 1 - Public:** CLI or HTTP input.",
        "**Zone 2 - Authenticated:** User context.",
        "**Zone 3 - Privileged:** Operator config.",
        "**Zone 4 - Internal:** Filesystem.",
        "",
        "**Auth mechanism:** login function.",
        "",
        "## 3. STRIDE Threat Analysis",
        "",
        "### S - Spoofing Identity",
        "",
        "No material spoofing threat identified from inspected code.",
        "",
        "### T - Tampering with Data",
        "",
        "No material tampering threat identified from inspected code.",
        "",
        "### R - Repudiation",
        "",
        "No material repudiation threat identified from inspected code.",
        "",
        "### I - Information Disclosure",
        "",
        "No material information disclosure threat identified from inspected code.",
        "",
        "### D - Denial of Service",
        "",
        "No material denial-of-service threat identified from inspected code.",
        "",
        "### E - Elevation of Privilege",
        "",
        "No material elevation-of-privilege threat identified from inspected code.",
        "",
        "## 4. Vulnerability Pattern Library",
        "",
        "### Python Patterns",
        "",
        "**Vulnerable:**",
        "```text",
        "subprocess.run(user_input, shell=True)",
        "```",
        "",
        "**Safe:**",
        "```text",
        "subprocess.run(['tool', validated_arg], shell=False)",
        "```",
        "",
        "## 5. Assumptions & Accepted Risks",
        "",
        "1. Test assumption.",
        "",
    ])


def _valid_security_config(tech_stack: list[str]) -> dict:
    return {
        "version": "1.0.0",
        "generated": "2026-06-13T00:00:00+10:00",
        "severity_thresholds": {
            "block_merge": "CRITICAL",
            "require_review": "HIGH",
            "inform": "MEDIUM",
        },
        "confidence_threshold": 0.8,
        "excluded_paths": ["tests/"],
        "tech_stack": tech_stack,
        "artifact_root": ".audit-hunter",
    }


def _write_tool_report(
    path: Path,
    tool: str,
    total: int,
    repo: Path,
    *,
    run_id: str = "run1",
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "schema_version": "1.0",
        "tool": tool,
        "run_id": run_id,
        "target": {"repo_path": str(repo.resolve())},
        "summary": {"total": total},
        "findings": [],
    }))


def _option_value(command: list[str], option: str) -> str:
    return command[command.index(option) + 1]
