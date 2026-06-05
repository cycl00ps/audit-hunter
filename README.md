# audit-hunter

<img src="assets/audit-hunter.jpg" alt="audit-hunter logo" align="right" width="180">

`audit-hunter` is a security-audit toolkit with focused, independently
runnable tools plus a one-shot local assessment flow:

- `audit-hunter threat-model` maps a repository before testing. It explains
  what the repo is, where its trust boundaries are, and which STRIDE risks
  matter. `threat-model/` keeps the optional agent skill version of that flow.
- `vuln-hunter/` performs vulnerability hunting against a repository as
  either a one-off audit run or a repeated campaign.
- `secret-hunter` scans repositories with user-managed TruffleHog and Gitleaks
  binaries, then writes a normalized secret report.
- `audit-hunter assess` runs the local one-shot flow: threat model, secret
  scan, vulnerability scan, then consolidated report.

Run `threat-model` first when you are starting on an unfamiliar codebase.
Use `vuln-hunter` and `secret-hunter` as separate discovery tools after that.
`audit-hunter assess` automates that sequence without owning tool-specific
secret or vulnerability scanning logic.

## Tools

### threat-model

`audit-hunter threat-model` generates repository-specific STRIDE threat models
and matching security configuration for already-cloned local repositories:

```bash
uv run --locked audit-hunter threat-model --repo /path/to/target --run-id my-run
```

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
reports/<run-id>/threat-model.md
reports/<run-id>/security-config.json
```

The generated threat model gives the tester and downstream tools a concise
explanation of the repo, the key trust boundaries, realistic threat scenarios,
and the vulnerability patterns worth prioritizing. Treat it as the first
artifact in an audit.

For a higher-fidelity agent-authored model, `threat-model/` remains available
as a `SKILL.md` style skill. The skill metadata exposes it as `audit-hunter`,
so a typical prompt is:

```text
Use $audit-hunter to generate a STRIDE threat model and security config for this codebase.
```

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
uv sync --locked --extra dev
uv run --locked secret-hunter scan --repo /path/to/target --run-id my-run
```

Raw scanner outputs are written under `scratch/artifacts/<run-id>/secret-hunter/`.
The final normalized report is written to
`reports/<run-id>/secret-hunter.report.json`.

### audit-hunter

The master entrypoint provides one-shot orchestration and report combination:

```bash
uv run --locked audit-hunter assess --repo /path/to/target --run-id my-run \
  --max-concurrency 1 \
  --max-recon-tasks 15 \
  --max-tokens 200000
```

`assess` runs these steps in order:

1. Generate `.audit-hunter/threat-model.md` and
   `.audit-hunter/security-config.json`, unless `--skip-threat-model` is set.
2. Build generated vuln-hunter scope notes from the threat model and security
   config.
3. Run `secret-hunter` against the target repo.
4. Run existing `vuln-hunter run` with the generated scope notes.
5. Combine per-tool JSON reports.

By default the vulnerability step is a single `vuln-hunter run`. To run a
campaign through the one-shot flow:

```bash
uv run --locked audit-hunter assess --repo /path/to/target --run-id my-campaign \
  --vuln-mode campaign \
  --runs 5 \
  --stop-after-empty 2 \
  --max-tokens 500000
```

In campaign mode, generated threat-model targeting is applied only to the
first vuln child run by default. Control that with `--threat-scope-runs`:

```bash
--threat-scope-runs 0   # no generated threat targeting
--threat-scope-runs 1   # first run only, default
--threat-scope-runs 3   # first three child runs
```

User-provided `--scope-notes` are still passed as general scope/exclusion
notes for the whole vuln run or campaign.

If threat artifacts already exist in the target repo, reuse them:

```bash
uv run --locked audit-hunter assess --repo /path/to/target --run-id my-run \
  --skip-threat-model
```

The generated vulnerability scope file is written under
`scratch/artifacts/<run-id>/audit-hunter/`. In single-run mode, user
`--scope-notes` are appended to the generated threat context. In campaign mode,
generated threat context is passed as targeted scope for the first
`--threat-scope-runs` child runs, while user `--scope-notes` apply to every
child run.

You can still combine existing reports manually:

```bash
uv sync --locked --extra dev
uv run --locked audit-hunter combine --run-id my-run
```

This writes `reports/<run-id>/audit-hunter.report.json` from the per-tool
reports already present in that run directory.

## One-shot Quickstart

Install the top-level tools:

```bash
uv sync --locked --extra dev
```

Install the nested vulnerability hunter environment:

```bash
uv sync --project vuln-hunter --locked --extra dev
```

Configure Codex/OpenAI auth for vulnerability hunting:

```bash
export OPENAI_API_KEY="sk-..."
uv run --project vuln-hunter --locked vuln-hunter auth-check
```

Put `trufflehog` and/or `gitleaks` in top-level `bin/` or make them available
on `PATH`, then run a bounded one-shot assessment:

```bash
uv run --locked audit-hunter assess --repo /path/to/target --run-id my-run \
  --max-concurrency 1 \
  --max-recon-tasks 15 \
  --max-tokens 200000
```

For repeated vuln hunting with the same one-shot setup:

```bash
uv run --locked audit-hunter assess --repo /path/to/target --run-id my-campaign \
  --vuln-mode campaign \
  --runs 5 \
  --threat-scope-runs 1 \
  --stop-after-empty 2 \
  --max-tokens 500000
```

Primary outputs:

```text
/path/to/target/.audit-hunter/threat-model.md
/path/to/target/.audit-hunter/security-config.json
reports/<run-id>/threat-model.md
reports/<run-id>/security-config.json
reports/<run-id>/secret-hunter.report.json
reports/<run-id>/vuln-hunter.report.json       # single-run mode
reports/<run-id>/campaign.report.json          # campaign mode
reports/<run-id>/audit-hunter.report.json
scratch/artifacts/<run-id>/audit-hunter/*.md
```

Use `--skip-threat-model` when `.audit-hunter/threat-model.md` and
`.audit-hunter/security-config.json` already exist in the target repo.

## Manual Workflow

1. Generate the threat model against the target repo:

   ```bash
   uv run --locked audit-hunter threat-model --repo /path/to/target --run-id my-run
   ```

2. Review the generated files in the target repo:

   ```text
   .audit-hunter/threat-model.md
   .audit-hunter/security-config.json
   ```

3. Create optional scope notes for the vulnerability hunt. Include accepted
   risks, exclusions, test-only services, severity thresholds, live-target
   credentials guidance, or areas the tester should prioritize.

4. Run `secret-hunter` and `vuln-hunter` manually, or use
   `audit-hunter assess` to run them in order.

## vuln-hunter Quickstart

Install the CLI from the `vuln-hunter/` directory:

```bash
cd vuln-hunter
uv sync --locked --extra dev
```

Configure authentication for Codex/OpenAI:

```bash
export OPENAI_API_KEY="sk-..."
uv run --locked vuln-hunter auth-check
```

Run a one-off audit:

```bash
uv run --locked vuln-hunter run --repo /path/to/target --run-id my-run \
  --max-concurrency 1 \
  --max-recon-tasks 15 \
  --max-tokens 200000

uv run --locked vuln-hunter status --run-id my-run
uv run --locked vuln-hunter report --run-id my-run --format md > report.md
```

Run a campaign:

```bash
uv run --locked vuln-hunter campaign run --repo /path/to/target \
  --campaign-id my-campaign \
  --runs 5 \
  --stop-after-empty 2 \
  --max-tokens 500000

uv run --locked vuln-hunter campaign status --campaign-id my-campaign
uv run --locked vuln-hunter campaign report --campaign-id my-campaign --format md > campaign-report.md
```

Pass scope notes when the threat-model review identifies exclusions or
priorities:

```bash
uv run --locked vuln-hunter run --repo /path/to/target \
  --run-id scoped-run \
  --scope-notes /path/to/scope-notes.md
```

If a live deployment is available, `vuln-hunter` can ask agents to reproduce
findings against it:

```bash
uv run --locked vuln-hunter run --repo /path/to/target --run-id live \
  --target-url http://server.local:8888 \
  --target-creds email=admin@example.com \
  --target-creds password=change-me \
  --max-concurrency 1 \
  --max-tokens 200000
```

## Project Layout

```text
threat-model/          Agent skill for STRIDE threat models
  SKILL.md             Optional agent-skill instructions and output formats
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
