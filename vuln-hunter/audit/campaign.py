"""Sequential multi-run campaign orchestration."""

from __future__ import annotations

import copy
import json
import logging
import re
from pathlib import Path
from typing import Iterable

from audit.config import HarnessConfig
from audit.json_utils import validate_schema
from audit.orchestrator import CostExceeded, run_pipeline
from audit.state import Finding, StateDB
from audit.stages._common import RESULTS as DEFAULT_RESULTS_ROOT
from audit.stages._common import SCHEMAS
from audit.stages.report import _normalize_report_summary

log = logging.getLogger(__name__)

_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")
_SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


async def run_campaign(
    *,
    repo_path: Path,
    campaign_id: str,
    runs: int,
    max_tokens: int | None,
    stop_after_empty: int,
    seed_run_ids: list[str],
    db: StateDB,
    config: HarnessConfig,
    max_recon_tasks: int | None = None,
    live_target: dict | None = None,
    scope_notes: str | None = None,
    targeted_scope_notes: str | None = None,
    targeted_scope_runs: int = 0,
    results_root: Path = DEFAULT_RESULTS_ROOT,
    scratch_root: Path | None = None,
) -> Path:
    """Run the existing pipeline repeatedly with shared campaign memory."""
    repo_path = repo_path.resolve()
    if targeted_scope_runs < 0:
        raise ValueError("targeted_scope_runs must be >= 0")
    if targeted_scope_runs > runs:
        raise ValueError("targeted_scope_runs cannot exceed requested runs")

    seeds = list(dict.fromkeys(seed_run_ids))
    db.create_campaign(
        campaign_id=campaign_id,
        repo_path=str(repo_path),
        requested_runs=runs,
        max_tokens=max_tokens,
        stop_after_empty=stop_after_empty,
        seed_run_ids=seeds,
    )

    seen_issue_keys = issue_keys_for_reachable_findings(db, seeds)
    prior_run_ids = list(seeds)
    child_run_ids: list[str] = []
    empty_streak = 0
    stop_reason: str | None = None

    try:
        for run_index in range(1, runs + 1):
            used_tokens = db.campaign_total_tokens(campaign_id)
            remaining_tokens: int | None = None
            if max_tokens is not None:
                remaining_tokens = max_tokens - used_tokens
                if remaining_tokens <= 0:
                    stop_reason = "token_budget_exhausted"
                    break

            child_run_id = f"{campaign_id}-{run_index}"
            if db.get_run(child_run_id) is not None:
                raise RuntimeError(
                    f"child run_id {child_run_id!r} already exists; "
                    "choose a new campaign-id or remove the existing run."
                )

            db.start_campaign_run(campaign_id, child_run_id, run_index)
            child_run_ids.append(child_run_id)
            child_base_scope = combine_scope_notes(
                targeted_scope_notes if run_index <= targeted_scope_runs else None,
                scope_notes,
            )
            child_scope_notes = append_campaign_ledger(
                child_base_scope, build_memory_ledger(db, prior_run_ids)
            )

            log.info(
                "[%s] campaign child %s starting with %s remaining tokens",
                campaign_id,
                child_run_id,
                remaining_tokens if remaining_tokens is not None else "unlimited",
            )

            try:
                await run_pipeline(
                    repo_path=repo_path,
                    run_id=child_run_id,
                    db=db,
                    config=config,
                    max_tokens=remaining_tokens,
                    resume=False,
                    max_recon_tasks=max_recon_tasks,
                    live_target=live_target,
                    scope_notes=child_scope_notes,
                    reports_root=results_root,
                    scratch_root=scratch_root,
                )
            except CostExceeded:
                new_count = count_new_reachable_issues(db, child_run_id, seen_issue_keys)
                db.finish_campaign_run(
                    campaign_id,
                    child_run_id,
                    status="aborted",
                    tokens=db.total_tokens(child_run_id),
                    new_reachable_issue_count=new_count,
                )
                prior_run_ids.append(child_run_id)
                stop_reason = "token_budget_exhausted"
                break
            except Exception:
                db.finish_campaign_run(
                    campaign_id,
                    child_run_id,
                    status="failed",
                    tokens=db.total_tokens(child_run_id),
                    new_reachable_issue_count=0,
                )
                db.finish_campaign(
                    campaign_id,
                    status="failed",
                    stop_reason=f"child_run_failed:{child_run_id}",
                )
                raise

            new_count = count_new_reachable_issues(db, child_run_id, seen_issue_keys)
            db.finish_campaign_run(
                campaign_id,
                child_run_id,
                status="completed",
                tokens=db.total_tokens(child_run_id),
                new_reachable_issue_count=new_count,
            )
            prior_run_ids.append(child_run_id)
            empty_streak = empty_streak + 1 if new_count == 0 else 0

            if empty_streak >= stop_after_empty:
                stop_reason = f"no_new_reachable_issues_after_{empty_streak}_runs"
                break

        if stop_reason is None:
            stop_reason = "requested_runs_completed"

        report_path = write_campaign_report(
            campaign_id=campaign_id,
            repo_path=repo_path,
            child_run_ids=child_run_ids,
            results_root=results_root,
        )
        db.finish_campaign(campaign_id, status="completed", stop_reason=stop_reason)
        log.info("[%s] campaign complete: %s", campaign_id, stop_reason)
        return report_path
    except Exception:
        row = db.get_campaign(campaign_id)
        if row is not None and row["status"] == "running":
            db.finish_campaign(campaign_id, status="failed", stop_reason="campaign_failed")
        raise


def append_campaign_ledger(scope_notes: str | None, ledger: str) -> str | None:
    if not ledger:
        return scope_notes
    if not scope_notes:
        return ledger
    return f"{scope_notes.rstrip()}\n\n---\n\n{ledger}"


def combine_scope_notes(*parts: str | None) -> str | None:
    cleaned = [part.strip() for part in parts if part and part.strip()]
    if not cleaned:
        return None
    return "\n\n---\n\n".join(cleaned)


def build_memory_ledger(
    db: StateDB, run_ids: Iterable[str], *, max_chars: int = 12_000
) -> str:
    """Build compact cross-run memory for prompt injection."""
    ordered_run_ids = list(dict.fromkeys(run_ids))
    if not ordered_run_ids:
        return ""

    header = (
        "## Prior Campaign Findings Ledger\n\n"
        "Confirmed reachable items are hard avoid: do not repeat the exact "
        "root cause unless you have a new sink, new entry point, or higher "
        "impact. Rejected and needs_more_info items are soft avoid: revisit "
        "only when new evidence addresses the prior rejection.\n"
    )
    lines: list[str] = [header, "\n### Confirmed Reachable (Hard Avoid)\n"]

    for run_id in ordered_run_ids:
        for finding, trace in db.get_reachable_canonical_findings(run_id):
            root = _root_cause_text(db, finding)
            entry_points = _entry_point_summary(trace)
            line = (
                f"- `{run_id}/{finding.finding_id}` {finding.severity} "
                f"{finding.vuln_class} at `{finding.file}:{finding.line_start}`; "
                f"root cause: {_compact(root, 220)}"
            )
            if entry_points:
                line += f"; entry points: {entry_points}"
            if not _append_line(lines, line, max_chars):
                return _finalize_ledger(lines)

    if not _append_line(lines, "\n### Rejected / Needs More Info (Soft Avoid)\n", max_chars):
        return _finalize_ledger(lines)

    for run_id in reversed(ordered_run_ids):
        rejected = [
            f for f in db.get_findings(run_id)
            if f.validation_status in {"rejected", "needs_more_info"}
        ]
        for finding in rejected:
            rationale = ""
            if finding.validation_json:
                rationale = finding.validation_json.get("rationale", "")
            line = (
                f"- `{run_id}/{finding.finding_id}` {finding.validation_status} "
                f"{finding.vuln_class} at `{finding.file}:{finding.line_start}`; "
                f"claim: {_compact(finding.description, 160)}"
            )
            if rationale:
                line += f"; prior rationale: {_compact(rationale, 180)}"
            if not _append_line(lines, line, max_chars):
                return _finalize_ledger(lines)

    ledger = _finalize_ledger(lines)
    return ledger if "-" in ledger else ""


def issue_keys_for_reachable_findings(db: StateDB, run_ids: Iterable[str]) -> set[str]:
    keys: set[str] = set()
    for run_id in run_ids:
        for finding, _trace in db.get_reachable_canonical_findings(run_id):
            keys.add(issue_key_for_finding(db, finding))
    return keys


def count_new_reachable_issues(
    db: StateDB, run_id: str, seen_issue_keys: set[str]
) -> int:
    current_keys = issue_keys_for_reachable_findings(db, [run_id])
    new_keys = current_keys - seen_issue_keys
    seen_issue_keys.update(current_keys)
    return len(new_keys)


def issue_key_for_finding(db: StateDB, finding: Finding) -> str:
    text = _root_cause_text(db, finding)
    return _issue_key(
        file=finding.file,
        line_start=finding.line_start,
        vuln_class=finding.vuln_class,
        text=text,
    )


def issue_key_for_report_finding(finding: dict) -> str:
    return _issue_key(
        file=str(finding.get("file", "")),
        line_start=int(finding.get("line_start") or 0),
        vuln_class=str(finding.get("vuln_class", "")),
        text=str(finding.get("title") or finding.get("description") or ""),
    )


def write_campaign_report(
    *,
    campaign_id: str,
    repo_path: Path,
    child_run_ids: list[str],
    results_root: Path = DEFAULT_RESULTS_ROOT,
) -> Path:
    payload = merge_campaign_reports(
        campaign_id=campaign_id,
        repo_path=repo_path,
        child_run_ids=child_run_ids,
        results_root=results_root,
    )
    errors = validate_schema(payload, SCHEMAS / "report.schema.json")
    if errors:
        raise ValueError(f"invalid campaign report: {errors}")

    out_dir = results_root / campaign_id
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "campaign.report.json"
    out_path.write_text(json.dumps(payload, indent=2))
    return out_path


def merge_campaign_reports(
    *,
    campaign_id: str,
    repo_path: Path,
    child_run_ids: list[str],
    results_root: Path = DEFAULT_RESULTS_ROOT,
) -> dict:
    entries: dict[str, dict] = {}
    order = 0

    for child_run_id in child_run_ids:
        report_path = results_root / child_run_id / "vuln-hunter.report.json"
        if not report_path.exists():
            report_path = results_root / child_run_id / "report" / "report.json"
        if not report_path.exists():
            continue
        report = json.loads(report_path.read_text())
        for finding in report.get("findings", []) or []:
            key = issue_key_for_report_finding(finding)
            candidate = copy.deepcopy(finding)
            if key not in entries:
                entries[key] = {
                    "finding": candidate,
                    "source_runs": {child_run_id},
                    "order": order,
                }
                order += 1
                continue

            entry = entries[key]
            entry["source_runs"].add(child_run_id)
            current_rank = _severity_rank(entry["finding"].get("severity"))
            candidate_rank = _severity_rank(candidate.get("severity"))
            if candidate_rank > current_rank:
                entry["finding"] = candidate

    findings: list[dict] = []
    for entry in sorted(
        entries.values(),
        key=lambda item: (
            -_severity_rank(item["finding"].get("severity")),
            str(item["finding"].get("file", "")),
            int(item["finding"].get("line_start") or 0),
            item["order"],
        ),
    ):
        finding = entry["finding"]
        source_runs = sorted(entry["source_runs"])
        if len(source_runs) > 1:
            finding["variants"] = source_runs
        findings.append(finding)

    payload = {
        "run_id": campaign_id,
        "target": {"repo_path": str(repo_path.resolve())},
        "summary": {"total": 0, "by_severity": {}},
        "findings": findings,
    }
    return _normalize_report_summary(payload)


def _issue_key(*, file: str, line_start: int, vuln_class: str, text: str) -> str:
    return "|".join(
        [
            _normalize_file(file),
            str(line_start),
            _normalize_text(vuln_class),
            _normalize_text(text)[:160],
        ]
    )


def _root_cause_text(db: StateDB, finding: Finding) -> str:
    if finding.group_id:
        group = db.get_dedupe_group(finding.run_id, finding.group_id)
        if group and group.get("root_cause"):
            return str(group["root_cause"])
    return str(
        finding.raw_json.get("root_cause")
        or finding.raw_json.get("title")
        or finding.description
    )


def _entry_point_summary(trace: dict) -> str:
    entries = []
    for entry in (trace.get("entry_points") or [])[:3]:
        location = entry.get("location")
        if location:
            entries.append(str(location))
    return ", ".join(entries)


def _append_line(lines: list[str], line: str, max_chars: int) -> bool:
    candidate = "\n".join(lines + [line])
    if len(candidate) > max_chars:
        return False
    lines.append(line)
    return True


def _finalize_ledger(lines: list[str]) -> str:
    return "\n".join(lines).strip()


def _compact(value: str, limit: int) -> str:
    compacted = " ".join(str(value).split())
    if len(compacted) <= limit:
        return compacted
    return compacted[: limit - 3].rstrip() + "..."


def _normalize_file(path: str) -> str:
    value = path.replace("\\", "/").strip().lower()
    while value.startswith("./"):
        value = value[2:]
    return value


def _normalize_text(value: str) -> str:
    return _NON_ALNUM_RE.sub(" ", value.strip().lower()).strip()


def _severity_rank(severity: object) -> int:
    return _SEVERITY_RANK.get(str(severity or "").lower(), -1)
