"""Normalize native TruffleHog and Gitleaks machine output."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from secret_hunter.redaction import redact_evidence, redact_secret


SEVERITIES = ("informational", "low", "medium", "high", "critical")
VERIFICATION_STRENGTH = {
    "not_supported": 0,
    "failed": 1,
    "unknown": 2,
    "unverified": 3,
    "verified": 4,
}


def parse_trufflehog(path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(errors="replace").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        findings.append(_trufflehog_finding(raw, line_no, path))
    return findings


def parse_gitleaks(path: Path) -> list[dict[str, Any]]:
    if not path.exists() or not path.read_text().strip():
        return []
    raw = json.loads(path.read_text())
    if isinstance(raw, dict):
        records = raw.get("findings") or raw.get("Findings") or []
    else:
        records = raw
    findings = []
    for index, item in enumerate(records or [], start=1):
        if isinstance(item, dict):
            findings.append(_gitleaks_finding(item, index, path))
    return findings


def dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for finding in findings:
        key = finding.pop("_dedupe_key")
        if key not in merged:
            merged[key] = finding
            continue

        current = merged[key]
        for source in finding["sources"]:
            if source not in current["sources"]:
                current["sources"].append(source)
        for artifact in finding["raw_artifact_paths"]:
            if artifact not in current["raw_artifact_paths"]:
                current["raw_artifact_paths"].append(artifact)
        current["severity"] = _max_severity(current["severity"], finding["severity"])
        current["confidence"] = max(current["confidence"], finding["confidence"])
        if len(finding["redacted_evidence"]) > len(current["redacted_evidence"]):
            current["redacted_evidence"] = finding["redacted_evidence"]
        if _verification_rank(finding) > _verification_rank(current):
            current["verification"] = finding["verification"]

    for index, finding in enumerate(merged.values(), start=1):
        finding["finding_id"] = f"secret_{index:04d}"
        finding["title"] = _title_for(finding)
    return list(merged.values())


def _trufflehog_finding(raw: dict[str, Any], index: int, artifact_path: Path) -> dict[str, Any]:
    detector = str(raw.get("DetectorName") or raw.get("DetectorType") or "unknown_secret")
    verified = raw.get("Verified")
    raw_secret = raw.get("Raw") or raw.get("RawV2") or raw.get("Secret")
    redacted_evidence = redact_secret(raw_secret) if raw_secret else redact_evidence(raw.get("Redacted") or detector)
    source_meta = raw.get("SourceMetadata") or {}
    file_path, line_start, commit = _trufflehog_location(source_meta)
    verification = "verified" if verified is True else "unverified" if verified is False else "unknown"
    fingerprint = str(raw.get("SourceID") or raw.get("DetectorType") or "")

    return _base_finding(
        source="trufflehog",
        detector_name=detector,
        secret_type=detector,
        verification_status=verification,
        file_path=file_path,
        line_start=line_start,
        line_end=line_start,
        fingerprint=fingerprint,
        redacted_evidence=redacted_evidence,
        raw_artifact_path=artifact_path,
        commit=commit,
        confidence=0.95 if verified is True else 0.65,
        severity="high" if verified is True else "medium",
        secret_identity=_secret_identity(raw_secret),
    )


def _gitleaks_finding(raw: dict[str, Any], index: int, artifact_path: Path) -> dict[str, Any]:
    detector = str(raw.get("RuleID") or raw.get("Description") or "unknown_secret")
    secret = raw.get("Secret")
    match = raw.get("Match") or raw.get("Secret") or detector
    file_path = str(raw.get("File") or raw.get("SymlinkFile") or "")
    line_start = _optional_int(raw.get("StartLine"))
    line_end = _optional_int(raw.get("EndLine")) or line_start
    fingerprint = str(raw.get("Fingerprint") or "")
    entropy = raw.get("Entropy")
    confidence = 0.7 if _float_or_none(entropy) and float(entropy) >= 3.5 else 0.55
    redacted_evidence = redact_evidence(match, secret)

    return _base_finding(
        source="gitleaks",
        detector_name=detector,
        secret_type=str(raw.get("Description") or detector),
        verification_status="not_supported",
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        fingerprint=fingerprint,
        redacted_evidence=redacted_evidence,
        raw_artifact_path=artifact_path,
        commit=raw.get("Commit"),
        confidence=confidence,
        severity="medium",
        secret_identity=_secret_identity(secret),
    )


def _base_finding(
    *,
    source: str,
    detector_name: str,
    secret_type: str,
    verification_status: str,
    file_path: str,
    line_start: int | None,
    line_end: int | None,
    fingerprint: str,
    redacted_evidence: str,
    raw_artifact_path: Path,
    commit: object | None,
    confidence: float,
    severity: str,
    secret_identity: str | None,
) -> dict[str, Any]:
    dedupe_key = _dedupe_key(
        commit=commit,
        file_path=file_path,
        line_start=line_start,
        secret_identity=secret_identity,
        redacted_evidence=redacted_evidence,
        fingerprint=fingerprint,
    )
    safe_fingerprint = fingerprint or dedupe_key
    return {
        "finding_id": "",
        "title": "",
        "severity": severity,
        "sources": [source],
        "detector_name": detector_name,
        "secret_type": secret_type,
        "verification": {"status": verification_status},
        "confidence": confidence,
        "file": file_path,
        "line_start": line_start,
        "line_end": line_end,
        "commit": str(commit) if commit else None,
        "fingerprint": safe_fingerprint,
        "redacted_evidence": redacted_evidence,
        "raw_artifact_paths": [str(raw_artifact_path)],
        "ai_analysis": {
            "status": "not_run",
            "likely_secret_type": secret_type,
            "false_positive_likelihood": "unknown",
            "confidence": 0.0,
            "rationale": "AI false-positive analysis was not run.",
        },
        "_dedupe_key": dedupe_key,
    }


def _trufflehog_location(source_meta: dict[str, Any]) -> tuple[str, int | None, str | None]:
    data = source_meta.get("Data") or {}
    for key in ("Filesystem", "Git", "Github", "GitLab", "S3"):
        node = data.get(key)
        if not isinstance(node, dict):
            continue
        file_path = node.get("file") or node.get("File") or node.get("path") or node.get("Path")
        line = node.get("line") or node.get("Line")
        commit = node.get("commit") or node.get("Commit")
        if file_path or line or commit:
            return str(file_path or ""), _optional_int(line), str(commit) if commit else None
    return "", None, None


def _title_for(finding: dict[str, Any]) -> str:
    source_text = "+".join(finding["sources"])
    location = finding["file"] or "unknown location"
    return f"{finding['secret_type']} detected by {source_text} in {location}"


def _max_severity(a: str, b: str) -> str:
    return max((a, b), key=lambda value: SEVERITIES.index(value))


def _verification_rank(finding: dict[str, Any]) -> int:
    return VERIFICATION_STRENGTH.get(finding["verification"]["status"], 0)


def _dedupe_key(
    *,
    commit: object | None,
    file_path: str,
    line_start: int | None,
    secret_identity: str | None,
    redacted_evidence: str,
    fingerprint: str,
) -> str:
    material = {
        "commit": str(commit) if commit else "",
        "file": file_path,
        "identity": secret_identity,
    }
    if secret_identity is None:
        material["line"] = line_start
        material["identity"] = _evidence_identity(redacted_evidence) or _hash(f"fingerprint:{fingerprint}")
    return _hash(json.dumps(material, sort_keys=True))


def _secret_identity(secret: object | None) -> str | None:
    if secret in (None, ""):
        return None
    value = str(secret).strip()
    if not value:
        return None
    if _looks_redacted(value):
        return None
    return _hash(f"secret:{value}")


def _evidence_identity(evidence: str) -> str | None:
    value = evidence.strip()
    if not value or _looks_redacted(value):
        return None
    return _hash(f"evidence:{value}")


def _looks_redacted(value: str) -> bool:
    lowered = value.lower()
    if "redacted" in lowered:
        return True
    stripped = value.strip("*xX._- ")
    return stripped == ""


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:24]


def _optional_int(value: object) -> int | None:
    if value in (None, ""):
        return None
    try:
        out = int(value)
    except (TypeError, ValueError):
        return None
    return out if out > 0 else None


def _float_or_none(value: object) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
