---
name: audit-hunter
description: Generate or refresh standalone STRIDE threat models for code repositories. Use when Codex, Cursor Agent, Claude Code, or another coding agent is asked to create a threat model, map trust boundaries, review security architecture, identify STRIDE risks, or produce security configuration for an audit workflow.
---

# Audit Hunter

Generate a concise, repository-specific STRIDE threat model and matching security configuration for the current codebase. This skill is standalone: do not depend on external package prompts, scripts, or installed skill paths.

## Outputs

Write both files under the repository being analyzed:

- `.audit-hunter/threat-model.md`
- `.audit-hunter/security-config.json`

Create `.audit-hunter/` if it does not exist. If legacy `.bug-hunter/triage.json` exists, read it for file structure and domain hints, but keep all new outputs under `.audit-hunter/`.

## Workflow

1. Inspect the repository before writing outputs:
   - detect languages, frameworks, package managers, and runtime entry points
   - identify public, authenticated, internal, and administrative interfaces
   - identify auth/session mechanisms, authorization checks, data stores, queues, file/storage boundaries, third-party services, and secrets/config sources
   - identify sensitive assets such as credentials, tokens, PII, payment data, audit logs, tenant data, source code, and deployment controls
2. Map trust boundaries:
   - public/untrusted input
   - authenticated user context
   - privileged/admin context
   - internal service-to-service context
   - persistence, filesystem, cache, queue, and external SaaS boundaries
3. Generate a short STRIDE model focused on realistic threats for this codebase.
4. Generate `security-config.json` with severity thresholds and detected tech stack metadata.

Prefer actual file paths, route names, function names, command names, config files, and framework concepts over generic labels. If evidence is uncertain, state the assumption briefly instead of inventing details.

## Threat Model Format

Use this Markdown structure:

```markdown
# Threat Model for [Repository Name]

**Generated:** [ISO 8601 date]
**Version:** 1.0.0
**Methodology:** STRIDE

## 1. System Overview

[2-3 sentence description of what the system does, the detected tech stack, and the main components.]

### Key Components

| Component | Purpose | Security Criticality | Entry Points |
|-----------|---------|---------------------|-------------|
| [name] | [purpose] | HIGH/MEDIUM/LOW | [routes, commands, events, jobs] |

### Data Flow

[1-2 sentences describing how data moves from input through processing to storage/output.]

## 2. Trust Boundaries

**Zone 1 - Public:** [untrusted inputs and public entry points]
**Zone 2 - Authenticated:** [session/user-scoped entry points]
**Zone 3 - Privileged:** [admin/operator/deployment controls]
**Zone 4 - Internal:** [service, database, queue, filesystem, cache, and SaaS integrations]

**Auth mechanism:** [JWT/session/OAuth/API key/none detected]. Enforced at: [middleware/route-level/command checks/unknown].

## 3. STRIDE Threat Analysis

### S - Spoofing Identity
[1-2 specific threats, or "No material spoofing threat identified from inspected code."]

### T - Tampering with Data
[1-2 specific threats, or "No material tampering threat identified from inspected code."]

### R - Repudiation
[1-2 specific threats, or "No material repudiation threat identified from inspected code."]

### I - Information Disclosure
[1-2 specific threats, or "No material information disclosure threat identified from inspected code."]

### D - Denial of Service
[1-2 specific threats, or "No material denial-of-service threat identified from inspected code."]

### E - Elevation of Privilege
[1-2 specific threats, or "No material elevation-of-privilege threat identified from inspected code."]

## 4. Vulnerability Pattern Library

### [Detected Tech Stack] Patterns

**Vulnerable:**
```[lang]
[short vulnerable pattern relevant to this repo]
```

**Safe:**
```[lang]
[short safer alternative relevant to this repo]
```

## 5. Assumptions & Accepted Risks

1. [assumption about trusted input, deployment, or missing context]
2. [accepted risk or "None identified"]
```

For each listed STRIDE threat, include:

- **Threat:** short name
- **Components:** affected paths/modules
- **Attack vector:** 2-4 concrete steps
- **Severity:** CRITICAL/HIGH/MEDIUM/LOW
- **Existing mitigations:** what the code/config already does
- **Gaps:** what remains missing or uncertain

Keep the threat model compact enough for downstream agents to consume. Aim for about 3KB; exceed that only when necessary to avoid losing important repo-specific boundaries.

## Security Config Format

Write `.audit-hunter/security-config.json` as valid JSON:

```json
{
  "version": "1.0.0",
  "generated": "<ISO 8601 date>",
  "severity_thresholds": {
    "block_merge": "CRITICAL",
    "require_review": "HIGH",
    "inform": "MEDIUM"
  },
  "confidence_threshold": 0.8,
  "excluded_paths": ["test/", "tests/", "docs/", "scripts/"],
  "tech_stack": ["<detected language/framework/tool>"],
  "artifact_root": ".audit-hunter"
}
```

Adjust `excluded_paths` only when the repository clearly uses different generated, vendor, fixture, or documentation directories. Keep JSON strict: no comments, no trailing commas.

## Agent Compatibility

Use whatever file search, read, and shell tools the active agent runtime provides. For Codex prefer `rg`/`rg --files`; for Claude Code use its Glob/Grep/Read tools when available; for Cursor Agent use workspace search and terminal tools. The required behavior is the same across runtimes: inspect first, then write the two `.audit-hunter/` artifacts.

Do not write `.bug-hunter/` outputs, and do not require Node.js or package-specific helper scripts.
