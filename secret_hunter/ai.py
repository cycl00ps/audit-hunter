"""Optional AI false-positive triage for secret findings."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


def analyze_findings(
    findings: list[dict[str, Any]],
    *,
    repo_path: Path,
    artifact_dir: Path,
    enabled: bool,
    model: str = "gpt-5.4-mini",
    codex_path: str | None = None,
) -> None:
    """Mutate findings with AI analysis when Codex is available."""
    if not findings:
        return
    if not enabled:
        _mark_all(findings, "disabled", "AI false-positive analysis was disabled.")
        return

    codex = codex_path or shutil.which("codex")
    if not codex:
        _mark_all(findings, "not_run", "Codex CLI was not available.")
        return

    artifact_dir.mkdir(parents=True, exist_ok=True)
    last_message = artifact_dir / "secret-analysis.codex-last.txt"
    prompt = _build_prompt(findings)
    cmd = [
        codex,
        "exec",
        "--model",
        model,
        "--json",
        "--sandbox",
        "read-only",
        "--skip-git-repo-check",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--output-last-message",
        str(last_message),
        "-",
    ]
    result = subprocess.run(
        cmd,
        cwd=repo_path,
        input=prompt,
        text=True,
        capture_output=True,
        timeout=180,
        check=False,
    )
    (artifact_dir / "secret-analysis.stdout.jsonl").write_text(result.stdout)
    (artifact_dir / "secret-analysis.stderr.txt").write_text(result.stderr)
    if result.returncode != 0 or not last_message.exists():
        _mark_all(findings, "error", "Codex analysis failed or returned no final message.")
        return

    try:
        payload = _extract_json(last_message.read_text())
    except ValueError:
        _mark_all(findings, "error", "Codex analysis did not return parseable JSON.")
        return

    by_id = {
        item.get("finding_id"): item
        for item in payload.get("analyses", [])
        if isinstance(item, dict)
    }
    for finding in findings:
        item = by_id.get(finding["finding_id"])
        if not item:
            finding["ai_analysis"] = {
                "status": "not_run",
                "likely_secret_type": finding["secret_type"],
                "false_positive_likelihood": "unknown",
                "confidence": 0.0,
                "rationale": "AI returned no analysis for this finding.",
            }
            continue
        finding["ai_analysis"] = {
            "status": "completed",
            "likely_secret_type": str(item.get("likely_secret_type") or finding["secret_type"]),
            "false_positive_likelihood": _fp_value(item.get("false_positive_likelihood")),
            "confidence": _confidence(item.get("confidence")),
            "rationale": str(item.get("rationale") or "")[:1000],
        }


def _build_prompt(findings: list[dict[str, Any]]) -> str:
    compact = []
    for finding in findings[:100]:
        compact.append({
            "finding_id": finding["finding_id"],
            "sources": finding["sources"],
            "detector_name": finding["detector_name"],
            "secret_type": finding["secret_type"],
            "verification": finding["verification"],
            "file": finding["file"],
            "line_start": finding["line_start"],
            "redacted_evidence": finding["redacted_evidence"],
        })
    return (
        "Analyze these redacted secret-scanner findings for false positives. "
        "Do not request or infer raw secret values. Return only JSON with this "
        "shape: {\"analyses\":[{\"finding_id\":\"...\","
        "\"likely_secret_type\":\"...\",\"false_positive_likelihood\":"
        "\"low|medium|high|unknown\",\"confidence\":0.0,"
        "\"rationale\":\"short reason\"}]}.\n\n"
        f"{json.dumps({'findings': compact}, ensure_ascii=False)}"
    )


def _mark_all(findings: list[dict[str, Any]], status: str, rationale: str) -> None:
    for finding in findings:
        finding["ai_analysis"] = {
            "status": status,
            "likely_secret_type": finding["secret_type"],
            "false_positive_likelihood": "unknown",
            "confidence": 0.0,
            "rationale": rationale,
        }


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end < start:
            raise ValueError("no JSON object found") from None
        payload = json.loads(text[start : end + 1])
    if not isinstance(payload, dict):
        raise ValueError("expected JSON object")
    return payload


def _fp_value(value: object) -> str:
    raw = str(value or "unknown").lower()
    return raw if raw in {"low", "medium", "high", "unknown"} else "unknown"


def _confidence(value: object) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return 0.0
    return min(1.0, max(0.0, parsed))
