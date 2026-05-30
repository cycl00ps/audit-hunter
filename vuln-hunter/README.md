# audit

An 8-stage vulnerability-discovery agent, driven by **Codex CLI** and your
OpenAI API key by default. Many narrow agents, deliberate disagreement, and
an explicit reachability gate.

MIT-licensed. Uses `OPENAI_API_KEY` or an existing `codex login` by default;
the legacy Claude Code Agent SDK path remains available with `--provider claude`.

## Origin

This project is a from-scratch reimplementation of the pipeline described in
Cloudflare's [Project Glasswing](https://blog.cloudflare.com/cyber-frontier-models/)
post, which tested Anthropic's Mythos preview LLM against Cloudflare's own
codebase. The blog argues that real-world vulnerability discovery does **not**
come from asking one big model "find bugs here" — it comes from:

1. **Many narrow agents** working in parallel on tightly-scoped questions
   ("Look for command injection in this specific function, with this trust
   boundary above it") rather than one exhaustive agent.
2. **Deliberate disagreement** — a second agent, on a different model, that
   tries to *disprove* the first agent's findings.
3. **A reachability trace** as the gating step — most "is this code buggy?"
   findings are noise unless an attacker-controlled input can actually reach
   the sink from outside the system.
4. **A feedback loop** so reachable bugs in one place automatically seed
   hunts for the same pattern elsewhere.

This repo packages that pipeline into a runnable agent. The Cloudflare post
showed the architecture; this codebase ships the prompts, schemas, state
store, and orchestrator.

## The 8 stages

![Vulnerability discovery harness — 8 stages](https://raw.githubusercontent.com/evilsocket/audit/main/docs/pipeline.png)

<sub>Diagram from Cloudflare's [Project Glasswing](https://blog.cloudflare.com/cyber-frontier-models/) post, reproduced here for reference.</sub>

| # | Stage    | Default model | Purpose |
|---|----------|---------------|---------|
| 1 | Recon    | gpt-5.5 | Map the repo, emit narrowly-scoped Hunt tasks |
| 2 | Hunt     | gpt-5.4-mini | One attack class per agent; compile/run PoCs |
| 3 | Validate | gpt-5.5 | Adversarial re-read; tries to **disprove** (different model from Hunt) |
| 4 | Gapfill  | gpt-5.4-mini | Re-queue under-covered areas |
| 5 | Dedupe   | gpt-5.4-mini | Cluster findings by root cause |
| 6 | Trace    | gpt-5.5 | Prove attacker-controlled input reaches the sink |
| 7 | Feedback | gpt-5.4-mini | Turn reachable traces into new Hunt tasks |
| 8 | Report   | gpt-5.4-mini | Schema-validated structured report |

Each stage is one markdown prompt in `prompts/` + one JSON Schema in
`schemas/`. The orchestrator passes the schema into the system prompt so
every output is shape-stable on the first try.

## Quickstart

```bash
# 1. Install
uv sync --extra dev

# 2. Auth (pick one)
#    (a) Use the OpenAI API key already in your shell:
export OPENAI_API_KEY="sk-..."
#    (b) Or store it for Codex:
printenv OPENAI_API_KEY | codex login --with-api-key

# 3. Verify
uv run audit auth-check

# 4. Run
uv run audit run --repo /path/to/target --run-id my-run
uv run audit status --run-id my-run
uv run audit report --run-id my-run --format md > report.md
```

By default the agent runs `codex exec` subprocesses and authenticates with
`OPENAI_API_KEY` or a stored Codex login/access token. The key is never
printed or persisted by this project.

To start from a clean run database, use:

```bash
uv run audit db reset --yes              # remove state.db only
uv run audit db reset --yes --all        # also remove results/ and work/
uv run audit db reset --all --dry-run    # preview cleanup targets
```

## Using a different model / provider

### Codex / OpenAI

```bash
export OPENAI_API_KEY="sk-..."
uv run audit auth-check
uv run audit run --repo /path/to/target --run-id codex-run --max-tokens 200000
```

Edit `config/stages.yaml` to change the per-stage Codex/OpenAI models and
reasoning effort, or use `--reasoning-effort` to override all stages for one
run. See `docs/models.md` for available models and recommended stage
placement. The runner includes the schema in the prompt and performs local
schema validation plus repair attempts.

### Claude fallback

The previous Claude Code SDK path is preserved for users who want it:

```bash
claude login
uv run audit auth-check --provider claude
uv run audit run --provider claude --repo /path/to/target --run-id crun
```

Claude gateway, OAuth-token, and metered `ANTHROPIC_API_KEY` modes still
work through `--provider claude`; `ANTHROPIC_API_KEY` remains opt-in via
`--allow-api-key` or `AUDIT_ALLOW_API_KEY=1`. With no custom `--config`,
the CLI uses `config/stages.claude.yaml` for the legacy Claude model names.

## Token containment

A real production codebase can produce 15-50 Hunt tasks and 25+ findings to
validate. At default concurrency this can burn through a lot of tokens. Flags
to keep it bounded:

```bash
uv run audit run --repo /path/to/target \
  --max-concurrency 1 \           # one agent subprocess at a time
  --max-recon-tasks 15 \          # cap initial Hunt fanout
  --max-tokens 200000             # abort cleanly if exceeded
```

The budget guard fires between *and* within stages — a per-task check in
Hunt cooperatively aborts rather than running 30 more tasks past the cap.
`--max-cost-usd` remains available as a legacy flag for providers that return
`total_cost_usd`, but `--max-tokens` is the preferred provider-independent cap.

## Live-target reproduction (optional)

If the target has a running deployment, point the agents at it. Hunt now
**reproduces** each finding against the live service instead of compiling
a local PoC, Validate **rejects** findings that don't reproduce, and Trace
**confirms** reachability with real HTTP round-trips. The static path
remains available — these flags are opt-in.

```bash
uv run audit run --repo /path/to/target --run-id live \
  --max-concurrency 1 --max-tokens 200000 \
  --target-url http://server.local:8888 \
  --target-creds email=admin@system.com \
  --target-creds password=changechangeme
```

Rules the agents follow when `--target-url` is set:
- Network egress is restricted to that host + `127.0.0.1`. No other external
  hosts.
- A finding that doesn't reproduce against the live target is dropped or
  rejected (depending on stage) — "no fabrication".
- Credentials flow into every relevant stage's user_input as a dict.

## Scope notes (optional)

Targets often have intentionally-loose-by-design surfaces that aren't bugs
(e.g. plaintext API keys when that's a feature, test-only Mailpit endpoints,
anonymous-analytics ingest). Drop them in a text file and pass it in — the
notes are appended verbatim to every stage's user_input, and Recon / Hunt /
Validate honor exclusions you list.

```bash
uv run audit run --repo /path/to/target --scope-notes target_scope.md
```

Example `target_scope.md`:

```markdown
- Mailpit (port 1025) is test-only; ignore.
- Plaintext API keys in the database are a required feature.
- Don't flag rate-limit absence on anonymous /ping endpoints.
- Only consider critical/high severity.
```

## Recon mines git history

Recon greps the git history for past security patches
(`CVE`, `sec:`, `fix.*auth`, `sanitize`, …) — patched files are hardened,
but **sibling files with the same idiom often aren't**. Findings get seeded
against the unpatched copies. Adds zero token usage on repos without that pattern;
catches real cross-component bugs on repos that have it.

## Logic chains

The pipeline's default is one-attack-class-per-task (the Cloudflare paper's
narrow-scope rule). Recon can also emit `logic_chain` tasks for high-impact
multi-component paths (auth-bypass + IDOR + path-traversal that compose into
RCE, etc.) — one chain per task, with the `scope_hint` naming the specific
chain. This is the one allowed exception to single-attack-class scoping.

## Layout

```
prompts/        8 stage prompts (markdown, loaded as system prompts)
schemas/        9 JSON schemas — every agent output is validated
config/         stages.yaml — model + concurrency + tool allowlist per stage
docs/           model selection and architecture notes
audit/          Python package
  auth.py       Codex / Claude auth checks
  state.py      SQLite DAO (runs, tasks, findings, traces, dedupe, usage records)
  runner.py     Codex CLI / Claude SDK runner with schema validation + repair turn
  orchestrator.py pipeline driver
  stages/       one module per stage
work/           per-Hunt-task scratch dirs (sandbox for PoC compile/run)
results/        JSONL artifacts per stage + final report.json
state.db        SQLite (gitignored)
```

## Safety

Hunt agents have Bash and run inside per-task scratch dirs. Codex runs use
Codex sandbox modes, but you should still run the audit inside a disposable
VM or container when you don't trust the target source — a target with
malicious build scripts could otherwise execute on your host during PoC
compilation.

The agent reads everything you `--add-dir`, including any `.env` or
`secrets/` directories in the target. Outputs land in `results/<run-id>/`
which is `.gitignore`d but **not** scrubbed of those reads.

## License

[MIT](LICENSE). Reuse freely. No warranty.

## Acknowledgements

- The pipeline design is from Cloudflare's [Project Glasswing](https://blog.cloudflare.com/cyber-frontier-models/)
  blog post. The credit for the architecture goes there.
- Runs through Codex CLI by default, with the official Claude Code Agent SDK
  preserved as an optional provider.
