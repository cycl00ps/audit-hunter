# audit-hunter

<img src="assets/audit-hunter.jpg" alt="audit-hunter logo" align="right" width="180">

`audit-hunter` is a security-audit toolkit with focused, independently
runnable tools:

- `threat-model/` maps a repository before testing. It explains what the
  repo is, where its trust boundaries are, and which STRIDE risks matter.
- `vuln-hunter/` performs vulnerability hunting against a repository as
  either a one-off audit run or a repeated campaign.
- `secret-hunter` scans repositories with user-managed TruffleHog and Gitleaks
  binaries, then writes a normalized secret report.
- `audit-hunter` is the master entrypoint scaffold for combining per-tool
  reports.

Run `threat-model` first when you are starting on an unfamiliar codebase.
Use `vuln-hunter` and `secret-hunter` as separate discovery tools after that.
`audit-hunter` can combine their JSON reports without owning tool-specific
logic.

## Tools

### threat-model

`threat-model/` is an agent skill for generating repository-specific STRIDE
threat models. It is intentionally lightweight: the active coding agent reads
the target repo directly, identifies the application shape, and writes the
audit context back into the target repository.

It inspects:

- languages, frameworks, package managers, and runtime entry points
- public, authenticated, internal, and administrative interfaces
- auth/session mechanisms, authorization checks, data stores, queues, caches,
  filesystem boundaries, third-party services, and secrets/config sources
- sensitive assets such as credentials, tokens, PII, tenant data, source code,
  audit logs, and deployment controls
- STRIDE risks: spoofing, tampering, repudiation, information disclosure,
  denial of service, and elevation of privilege

It writes:

```text
.audit-hunter/threat-model.md
.audit-hunter/security-config.json
```

Use it from an agent runtime that supports `SKILL.md` style skills. The skill
metadata exposes it as `audit-hunter`, so a typical prompt is:

```text
Use $audit-hunter to generate a STRIDE threat model and security config for this codebase.
```

The generated threat model gives the tester a concise explanation of the repo,
the key trust boundaries, realistic threat scenarios, and the vulnerability
patterns worth prioritizing. Treat it as the first artifact in an audit.

### vuln-hunter

`vuln-hunter/` is a runnable Python CLI that drives an 8-stage vulnerability
discovery pipeline through Codex CLI by default, with a Claude provider path
available for legacy use.

The pipeline is:

| # | Stage | Purpose |
|---|-------|---------|
| 1 | Recon | Map the repo and emit narrow hunt tasks |
| 2 | Hunt | Run one attack class per agent task and attempt PoCs |
| 3 | Validate | Adversarially re-read findings and try to disprove them |
| 4 | Gapfill | Re-queue under-covered areas |
| 5 | Dedupe | Cluster findings by root cause |
| 6 | Trace | Prove attacker-controlled input reaches the vulnerable sink |
| 7 | Feedback | Turn reachable traces into follow-up hunt tasks |
| 8 | Report | Produce a schema-validated final report |

Use a one-off run when you want a bounded audit pass. Use a campaign when you
want repeated runs with shared memory, dedupe across prior results, and a stop
condition based on whether new reachable issues are still being found.

See [`vuln-hunter/README.md`](vuln-hunter/README.md) for the full CLI,
provider, model, and safety documentation.

### secret-hunter

`secret-hunter` is a standalone scanner wrapper. Put third-party binaries in
top-level `bin/` or make them available on `PATH`:

```bash
uv sync --extra dev
uv run secret-hunter scan --repo /path/to/target --run-id my-run
```

Raw scanner outputs are written under `scratch/artifacts/<run-id>/secret-hunter/`.
The final normalized report is written to
`reports/<run-id>/secret-hunter.report.json`.

### audit-hunter

The master entrypoint currently provides report combination:

```bash
uv sync --extra dev
uv run audit-hunter combine --run-id my-run
```

This writes `reports/<run-id>/audit-hunter.report.json` from the per-tool
reports already present in that run directory.

## Recommended Workflow

1. Generate the threat model against the target repo:

   ```text
   Use $audit-hunter to generate a STRIDE threat model and security config for this codebase.
   ```

2. Review the generated files in the target repo:

   ```text
   .audit-hunter/threat-model.md
   .audit-hunter/security-config.json
   ```

3. Create optional scope notes for the vulnerability hunt. Include accepted
   risks, exclusions, test-only services, severity thresholds, live-target
   credentials guidance, or areas the tester should prioritize.

4. Run `vuln-hunter` as either a one-off run or a campaign.

## vuln-hunter Quickstart

Install the CLI from the `vuln-hunter/` directory:

```bash
cd vuln-hunter
uv sync --extra dev
```

Configure authentication for Codex/OpenAI:

```bash
export OPENAI_API_KEY="sk-..."
uv run vuln-hunter auth-check
```

Run a one-off audit:

```bash
uv run vuln-hunter run --repo /path/to/target --run-id my-run \
  --max-concurrency 1 \
  --max-recon-tasks 15 \
  --max-tokens 200000

uv run vuln-hunter status --run-id my-run
uv run vuln-hunter report --run-id my-run --format md > report.md
```

Run a campaign:

```bash
uv run vuln-hunter campaign run --repo /path/to/target \
  --campaign-id my-campaign \
  --runs 5 \
  --stop-after-empty 2 \
  --max-tokens 500000

uv run vuln-hunter campaign status --campaign-id my-campaign
uv run vuln-hunter campaign report --campaign-id my-campaign --format md > campaign-report.md
```

Pass scope notes when the threat-model review identifies exclusions or
priorities:

```bash
uv run vuln-hunter run --repo /path/to/target \
  --run-id scoped-run \
  --scope-notes /path/to/scope-notes.md
```

If a live deployment is available, `vuln-hunter` can ask agents to reproduce
findings against it:

```bash
uv run vuln-hunter run --repo /path/to/target --run-id live \
  --target-url http://server.local:8888 \
  --target-creds email=admin@example.com \
  --target-creds password=change-me \
  --max-concurrency 1 \
  --max-tokens 200000
```

## Project Layout

```text
threat-model/          Agent skill for STRIDE threat models
  SKILL.md             Skill instructions and output formats
  agents/openai.yaml   Agent metadata

vuln-hunter/           Python vulnerability hunting CLI
  audit/               CLI, orchestrator, runner, state, and stage modules
  prompts/             Stage prompts
  schemas/             JSON schemas for stage outputs
  config/              Per-stage model/provider/tool configuration
  tests/               Unit tests
  README.md            Detailed vuln-hunter documentation

assets/                Shared README assets
bin/                   User-managed third-party binaries; contents ignored
scratch/               Cloned repos, raw artifacts, and work dirs; contents ignored
reports/               Final JSON reports; contents ignored
LICENSE                MIT license
```

## Safety

Both tools inspect target source code, and `vuln-hunter` may run agent-created
PoCs in per-task scratch directories. Run audits inside a disposable VM or
container when the target source is untrusted.

`vuln-hunter` and `secret-hunter` read everything made available to them,
including `.env` or `secrets/` directories in the target. Raw artifacts are
written under `scratch/`, final reports are written under `reports/`, and
local vulnerability run state is kept in `vuln-hunter/state.db`.

## License

[MIT](LICENSE). Reuse freely. No warranty.

## Thanks

This project builds on ideas and patterns from:

- [codexstar69/bug-hunter](https://github.com/codexstar69/bug-hunter), an
  adversarial multi-agent bug finding and security scanning project.
- [evilsocket/audit](https://github.com/evilsocket/audit), an 8-stage
  vulnerability-discovery agent.

Thanks to those projects and their maintainers for the inspiration.
