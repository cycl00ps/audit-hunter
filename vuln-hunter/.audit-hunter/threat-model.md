# Threat Model for audit

**Generated:** 2026-05-29T21:21:25+10:00
**Version:** 1.0.0
**Methodology:** STRIDE

## 1. System Overview

`audit` is a Python 3.11 Click CLI that runs an 8-stage vulnerability-discovery pipeline against a target source repository. It launches Codex CLI or Claude Agent SDK agents, validates JSON outputs with schemas, stores run state in SQLite, and writes raw artifacts plus reports under `results/` and `work/`.

### Key Components

| Component | Purpose | Security Criticality | Entry Points |
|-----------|---------|---------------------|-------------|
| CLI (`audit/cli.py`) | Operator command parsing and local state controls. | HIGH | `audit auth-check`, `audit run`, `audit campaign run`, `audit report`, `audit status`, `audit db reset` |
| Auth (`audit/auth.py`) | Chooses Codex or Claude credential mode from environment/login files. | HIGH | `configure_auth()`, `OPENAI_API_KEY`, `ANTHROPIC_*`, `CLAUDE_CODE_OAUTH_TOKEN` |
| Pipeline (`audit/orchestrator.py`, `audit/stages/*.py`) | Runs Recon, Hunt, Validate, Gapfill, Dedupe, Trace, Feedback, Report. | HIGH | `run_pipeline()`, `run_campaign()` |
| Agent runner (`audit/runner.py`) | Builds prompts, runs `codex exec` or `ClaudeSDKClient`, records JSONL. | HIGH | `run_agent()`, `_run_codex_exec()`, `_run_claude_agent_once()` |
| State/artifacts (`audit/state.py`, `results/`, `work/`) | Stores tasks, findings, traces, costs, reports, and Hunt scratch data. | HIGH | `state.db`, `StageContext.results_dir()`, `StageContext.work_dir()` |
| Config/prompts/schemas (`config/`, `prompts/`, `schemas/`) | Defines models, tools, stage behavior, and output contracts. | MEDIUM | `config/stages.yaml`, `prompts/*.md`, `schemas/*.schema.json` |

### Data Flow

CLI input, provider credentials, target repo paths, optional scope notes, and optional live-target credentials flow into stage user input. Agent JSON is schema-validated, indexed in `state.db`, and persisted as JSONL/report artifacts.

## 2. Trust Boundaries

**Zone 1 - Public:** Target repository contents, CLI `--repo`, `--scope-notes`, `--target-url`, `--target-creds`, live target responses, and model output.
**Zone 2 - Authenticated:** Local operator shell, provider API/login credentials, and permission to run the CLI.
**Zone 3 - Privileged:** `audit db reset --all`, writes to `state.db`, `results/`, `work/`, provider selection, and stage model/tool config.
**Zone 4 - Internal:** SQLite, JSONL artifacts, temporary Codex homes, Hunt scratch dirs, subprocesses, local filesystem, and OpenAI/Claude APIs.

**Auth mechanism:** Local CLI only; no application-user auth. Provider auth uses `OPENAI_API_KEY` or Codex login for Codex mode, and Claude OAuth, gateway token, or opt-in Anthropic API key for Claude mode. Enforced at: `audit/cli.py` run/campaign calls to `configure_auth()` and provider-mode checks in `audit/auth.py`.

## 3. STRIDE Threat Analysis

### S - Spoofing Identity

**Threat:** Provider or live-target identity spoofing
**Components:** `audit/auth.py`, `audit/cli.py`, `audit/runner.py`
**Attack vector:** An attacker-controlled shell or wrapper sets `AUDIT_PROVIDER`, `ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN`, or `--target-url`; the operator runs `audit run`; credentials or reproduction traffic go to an unexpected provider, gateway, or target.
**Severity:** HIGH
**Existing mitigations:** Provider values are limited to `codex` and `claude`; `auth-check` displays selected mode; Claude mode scrubs conflicting API-key variables; live-target use is opt-in.
**Gaps:** No provider endpoint pinning or target-host allowlist is enforced in code; live-target network restrictions are prompt instructions, not a policy layer.

### T - Tampering with Data

**Threat:** Prompt-injection or model-output tampering of audit state
**Components:** `prompts/*.md`, `audit/runner.py`, `audit/state.py`, `results/`
**Attack vector:** A malicious target repo influences an agent; the agent emits misleading but schema-valid JSON; downstream stages store and trust that data for validation, trace, and report generation.
**Severity:** MEDIUM
**Existing mitigations:** Codex prompts tell agents to ignore ambient rules; outputs are JSON-schema validated with repair attempts; Validate and Trace provide separate review gates.
**Gaps:** Schema validation does not prove semantic truth; `state.db` and JSONL artifacts are mutable local files without signatures, hashes, or append-only storage.

### R - Repudiation

**Threat:** Weak attribution for local destructive or report-changing actions
**Components:** `audit/cli.py`, `audit/state.py`, `results/`, `work/`
**Attack vector:** A local user resets DB/output state, resumes a run, or edits artifacts; later review sees run rows and JSONL files but no operator identity or immutable event chain.
**Severity:** MEDIUM
**Existing mitigations:** SQLite records runs, costs, artifacts, statuses, and campaign metadata; `db reset` prompts unless `--yes` is passed.
**Gaps:** No per-command audit log, artifact hash chain, OS user capture, or file permission hardening.

### I - Information Disclosure

**Threat:** Secret and target-data leakage through artifacts
**Components:** `audit/cli.py`, `audit/runner.py`, `results/`, `state.db`
**Attack vector:** The target repo contains `.env`, `secrets/`, proprietary source, or `--target-creds` are supplied; stage user input is serialized; `_write_artifact()` records prompt/user blocks and model output in JSONL.
**Severity:** HIGH
**Existing mitigations:** `.gitignore` excludes `results/`, `work/`, and `state.db`; README warns outputs are not scrubbed; Codex API keys are not intentionally printed.
**Gaps:** No redaction for `live_target.credentials`, scope notes, source secrets, or model output; artifacts are not encrypted and have no retention policy.

### D - Denial of Service

**Threat:** Token, subprocess, and disk exhaustion
**Components:** `config/stages.yaml`, `audit/orchestrator.py`, `audit/stages/hunt.py`, `audit/runner.py`
**Attack vector:** A large or adversarial repo creates many Recon/Gapfill/Feedback tasks; Hunt defaults to high concurrency; child agents and PoC builds consume tokens, processes, disk, and SQLite space.
**Severity:** MEDIUM
**Existing mitigations:** `--max-tokens`, `--max-concurrency`, `--max-recon-tasks`, bounded feedback/gapfill loops, and transient retry limits.
**Gaps:** No default wall-clock timeout, memory quota, disk quota, or process-count quota per child task.

### E - Elevation of Privilege

**Threat:** Hunt-stage Bash execution of malicious target code
**Components:** `audit/stages/hunt.py`, `audit/runner.py`, `work/`, target repo via `--add-dir`
**Attack vector:** A target repo includes malicious build/test code; a Hunt agent runs it while compiling a PoC; if sandboxing is weaker than expected, code may access host files, network, or inherited credentials.
**Severity:** HIGH
**Existing mitigations:** Non-Hunt Codex stages use read-only sandboxing; Hunt gets a scratch dir; Codex uses isolated `CODEX_HOME`; README recommends disposable VMs/containers.
**Gaps:** Containerization, egress filtering, and sandbox verification are operational guidance rather than enforced repository code.

## 4. Vulnerability Pattern Library

### Python Click / asyncio subprocess / SQLite Patterns

**Vulnerable:**
```python
live_target = {"url": target_url, "credentials": creds}
initial_prompt = json.dumps(user_input, ensure_ascii=False)
_write_artifact(art, {"kind": "user", "text": initial_prompt[:50000]})
```

**Safe:**
```python
SENSITIVE_KEYS = {"password", "passwd", "token", "api_key", "secret", "credentials"}

def redact(value):
    if isinstance(value, dict):
        return {
            k: "[redacted]" if k.lower() in SENSITIVE_KEYS else redact(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value

safe_prompt = json.dumps(redact(user_input), ensure_ascii=False)
_write_artifact(art, {"kind": "user", "text": safe_prompt[:50000]})
```

## 5. Assumptions & Accepted Risks

1. The local operator and shell account are trusted; target repo contents, live target responses, and model output may be adversarial.
2. This is a local CLI, not a network service; HTTP risks apply only to optional live-target reproduction traffic.
3. Accepted risk: Hunt PoCs may execute untrusted target code unless the operator runs the tool in a disposable VM/container with restricted filesystem and network access.
