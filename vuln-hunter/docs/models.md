# Models and Reasoning Effort

The audit pipeline selects models per stage in `config/stages.yaml`. The
default provider is `codex`, which runs `codex exec` with explicit model and
reasoning-effort settings.

## Configure Models

Set the model and reasoning effort on each stage:

```yaml
stages:
  validate:
    model: gpt-5.5
    reasoning_effort: xhigh
    concurrency: 10
    tools: [Read, Grep, Glob]
```

`reasoning_effort` is optional for custom configs. If it is omitted, the
backend default applies. The supported values are:

```text
none, low, medium, high, xhigh
```

Reasoning effort is not part of the model ID. Use:

```yaml
model: gpt-5.5
reasoning_effort: xhigh
```

Do not use:

```yaml
model: gpt-5.5 xhigh
```

For one-off experiments, override every stage from the CLI:

```bash
audit run --repo /path/to/target --reasoning-effort high
```

The runner uses `--ignore-user-config`, so `~/.codex/config.toml` is not a
source of truth for audit runs.

## Available OpenAI Models

These model IDs were visible to the current API key on 2026-05-28:

| Model | Best use in this pipeline |
|---|---|
| `gpt-5.5` | High-value reasoning stages: Recon, Validate, Trace |
| `gpt-5.5-pro` | Rare adjudication or highest-stakes Validate/Trace runs |
| `gpt-5.4` | Strong general fallback when `gpt-5.5` is unnecessary |
| `gpt-5.4-pro` | Higher-compute general model; use sparingly |
| `gpt-5.4-mini` | High-fanout stages: Hunt, Gapfill, Dedupe, Feedback, Report |
| `gpt-5.4-nano` | Cheapest smoke/testing runs; not recommended for security judgment |
| `gpt-5.3-codex` | Code-heavy Hunt or Trace experiments |
| `gpt-5` | Older frontier fallback |
| `gpt-5-mini` | Older low-cost fallback |
| `gpt-5-nano` | Older cheapest fallback |

Known reasoning-effort support from direct API validation:

| Model | Supported reasoning efforts |
|---|---|
| `gpt-5.5` | `none`, `low`, `medium`, `high`, `xhigh` |
| `gpt-5.5-pro` | `medium`, `high`, `xhigh` |

Other GPT-5 family models may reject some effort values. If a model rejects an
effort, lower the effort or remove `reasoning_effort` for that stage.

## Recommended Stage Mix

The default config uses balanced quality and token spend:

| Stage | Default model | Default effort | Rationale |
|---|---|---:|---|
| Recon | `gpt-5.5` | `xhigh` | Shapes all downstream work |
| Hunt | `gpt-5.4-mini` | `medium` | High fanout; keep spend controlled |
| Validate | `gpt-5.5` | `xhigh` | Deliberate disagreement and false-positive control |
| Gapfill | `gpt-5.4-mini` | `medium` | Generates follow-up coverage |
| Dedupe | `gpt-5.4-mini` | `medium` | Clustering task, usually bounded |
| Trace | `gpt-5.5` | `xhigh` | Highest-value reachability proof |
| Feedback | `gpt-5.4-mini` | `medium` | Seeds additional tasks |
| Report | `gpt-5.4-mini` | `medium` | Formats confirmed findings |

Use `gpt-5.5-pro` only when the extra cost and slower runtime are justified.
It is a poor fit for high-concurrency Hunt runs.

## Claude Provider

The legacy Claude provider uses `config/stages.claude.yaml` and Claude model
IDs. OpenAI reasoning-effort levels are ignored for Claude runs.
