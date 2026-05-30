"""Auth setup for Codex CLI and the Claude Code Agent SDK.

Codex mode uses the local `codex` CLI and either OPENAI_API_KEY from the
environment or a stored Codex login/access token. It does not inspect,
print, scrub, or persist the OpenAI key.

Claude mode uses Claude Code's authentication-precedence list
(https://code.claude.com/docs/en/authentication#authentication-precedence):

  1. Cloud provider credentials (Bedrock / Vertex / Foundry, when their
     respective `CLAUDE_CODE_USE_*` flag is set)
  2. ANTHROPIC_AUTH_TOKEN  (Bearer-token mode — used by LLM gateways
     like OpenRouter, custom proxies, etc.)
  3. ANTHROPIC_API_KEY      (the canonical metered Anthropic API)
  4. apiKeyHelper
  5. CLAUDE_CODE_OAUTH_TOKEN (long-lived subscription token)
  6. Subscription OAuth credentials from `claude login`

Claude mode supports four modes, picked in this order:

  - **gateway**: `ANTHROPIC_BASE_URL` points away from anthropic.com AND
    `ANTHROPIC_AUTH_TOKEN` is set. Used for OpenRouter and similar.
    We leave those two env vars intact but still scrub `ANTHROPIC_API_KEY`
    (it'd outrank the gateway token).

  - **api_key**: `ANTHROPIC_API_KEY` is set with no gateway configured,
    AND the caller passed `allow_api_key=True`. Metered Anthropic API
    billing. We leave the key in place; the SDK uses it natively.
    ANTHROPIC_AUTH_TOKEN is scrubbed so a stale value can't outrank
    the key.

    This mode is opt-in to protect users who set ANTHROPIC_API_KEY in
    their shell for other tools (e.g. anthropic-sdk-python) but expect
    subscription billing here. By default, the API key is scrubbed and
    one of the subscription modes wins instead — matching the behavior
    before this mode was added.

  - **oauth_token**: `CLAUDE_CODE_OAUTH_TOKEN` is set (Pro/Max/Team/Enterprise
    subscription, ideal for CI). We scrub `ANTHROPIC_API_KEY` (unless
    api_key mode was selected above) and `ANTHROPIC_AUTH_TOKEN` so they
    can't outrank the OAuth token.

  - **keychain_login**: `~/.claude/.credentials.json` exists from
    `claude login`. Same scrubbing as oauth_token.

Anything else raises AuthError.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass
class AuthStatus:
    provider: str
    auth_mode: str
    api_key_scrubbed: bool = False
    auth_token_scrubbed: bool = False
    claude_cli_path: str | None = None
    claude_cli_version: str | None = None
    codex_cli_path: str | None = None
    codex_cli_version: str | None = None
    credentials_file: Path | None = None
    gateway_base_url: str | None = None
    gateway_model: str | None = None  # value of ANTHROPIC_MODEL if set, for display
    openai_api_key_present: bool = False


class AuthError(RuntimeError):
    pass


CREDENTIALS_PATH = Path.home() / ".claude" / ".credentials.json"


def _is_gateway_base(url: str) -> bool:
    """A non-empty BASE_URL that doesn't point at canonical Anthropic
    counts as 'gateway mode'."""
    u = url.strip().lower()
    if not u:
        return False
    # Treat anything except api.anthropic.com / console.anthropic.com as gateway.
    return "anthropic.com" not in u


def configure_auth(
    env_file: Path | None = None,
    *,
    provider: str = "codex",
    allow_api_key: bool = False,
) -> AuthStatus:
    """Load .env, decide auth mode, scrub conflicting env vars accordingly.

    Args:
        env_file: Optional .env file to load before reading env vars.
        provider: "codex" for OpenAI/Codex CLI auth, or "claude" for the
            existing Claude Code Agent SDK auth path.
        allow_api_key: When True, ANTHROPIC_API_KEY is honored as a valid
            Claude auth path (api_key mode, metered billing). When False,
            the key is scrubbed in favor of subscription auth.

    Returns an AuthStatus describing what was picked. Raises AuthError if
    no usable auth path is available.
    """
    if env_file is not None and env_file.exists():
        load_dotenv(env_file)
    else:
        load_dotenv()

    provider = _normalize_provider(provider)
    if provider == "codex":
        return _configure_codex_auth()
    return _configure_claude_auth(allow_api_key=allow_api_key)


def _normalize_provider(provider: str) -> str:
    p = provider.strip().lower()
    if p not in {"codex", "claude"}:
        raise AuthError(f"Unknown provider {provider!r}; expected 'codex' or 'claude'.")
    return p


def _cli_version(cli_path: str) -> str | None:
    try:
        out = subprocess.run(
            [cli_path, "--version"], capture_output=True, text=True, timeout=10
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except (subprocess.SubprocessError, OSError):
        pass
    return None


def _configure_codex_auth() -> AuthStatus:
    cli_path = shutil.which("codex")
    if cli_path is None:
        raise AuthError(
            "`codex` CLI not found on PATH. Install Codex CLI or add it to PATH."
        )

    openai_key_present = bool(os.environ.get("OPENAI_API_KEY", "").strip())
    if openai_key_present:
        mode = "codex_api_key"
    else:
        try:
            out = subprocess.run(
                [cli_path, "login", "status"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (subprocess.SubprocessError, OSError) as e:
            raise AuthError(
                "No Codex auth available. Set OPENAI_API_KEY or run "
                "`codex login --with-api-key` / `codex login --with-access-token`."
            ) from e
        if out.returncode == 0 and "logged in" in (out.stdout + out.stderr).lower():
            mode = "codex_login"
        else:
            raise AuthError(
                "No Codex auth available. Set OPENAI_API_KEY or run "
                "`codex login --with-api-key` / `codex login --with-access-token`."
            )

    return AuthStatus(
        provider="codex",
        auth_mode=mode,
        codex_cli_path=cli_path,
        codex_cli_version=_cli_version(cli_path),
        openai_api_key_present=openai_key_present,
    )


def _configure_claude_auth(*, allow_api_key: bool = False) -> AuthStatus:
    cli_path = shutil.which("claude")
    if cli_path is None:
        raise AuthError(
            "`claude` CLI not found on PATH. Install Claude Code first: "
            "https://code.claude.com/docs/en/setup"
        )

    api_key_was_set = "ANTHROPIC_API_KEY" in os.environ
    base_url = os.environ.get("ANTHROPIC_BASE_URL", "")
    auth_token = os.environ.get("ANTHROPIC_AUTH_TOKEN", "").strip()
    gateway = _is_gateway_base(base_url) and bool(auth_token)

    api_key_scrubbed = False
    auth_token_was_scrubbed = False
    creds_file: Path | None = None

    if gateway:
        # Gateway path (OpenRouter / custom proxy / etc.): keep
        # ANTHROPIC_BASE_URL + ANTHROPIC_AUTH_TOKEN, but still drop
        # ANTHROPIC_API_KEY (rung 3 would outrank the gateway token).
        if api_key_was_set:
            del os.environ["ANTHROPIC_API_KEY"]
            api_key_scrubbed = True
        mode = "gateway"
    elif allow_api_key and api_key_was_set:
        # Explicit API key path (metered Anthropic billing). Leave the
        # key in place; the SDK uses it natively at precedence rung 3.
        # Scrub ANTHROPIC_AUTH_TOKEN so a stale value can't outrank the
        # key (rung 2 > rung 3). No claude login credentials are needed.
        if "ANTHROPIC_AUTH_TOKEN" in os.environ:
            del os.environ["ANTHROPIC_AUTH_TOKEN"]
            auth_token_was_scrubbed = True
        mode = "api_key"
    else:
        # Subscription paths: scrub both API-key vars so subscription
        # OAuth wins precedence. (When allow_api_key=False, this is the
        # only place ANTHROPIC_API_KEY can land — and we always scrub it,
        # matching the pre-opt-in behavior.)
        if api_key_was_set:
            del os.environ["ANTHROPIC_API_KEY"]
            api_key_scrubbed = True
        if "ANTHROPIC_AUTH_TOKEN" in os.environ:
            del os.environ["ANTHROPIC_AUTH_TOKEN"]
            auth_token_was_scrubbed = True

        token = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "").strip()
        creds_file = CREDENTIALS_PATH if CREDENTIALS_PATH.exists() else None
        if token:
            mode = "oauth_token"
        elif creds_file is not None:
            mode = "keychain_login"
        else:
            hint = ""
            if api_key_was_set:
                hint = (
                    "\n\nNote: ANTHROPIC_API_KEY was set but ignored. To use\n"
                    "metered API billing, re-run with --allow-api-key (or set\n"
                    "AUDIT_ALLOW_API_KEY=1 in the env)."
                )
            raise AuthError(
                "No auth available. Pick one of:\n"
                "  (a) Subscription OAuth (interactive): run `claude login`.\n"
                "  (b) Subscription OAuth (headless): run `claude setup-token` "
                "and paste into .env as CLAUDE_CODE_OAUTH_TOKEN.\n"
                "  (c) LLM gateway (OpenRouter / proxy): set "
                "ANTHROPIC_BASE_URL + ANTHROPIC_AUTH_TOKEN.\n"
                "  (d) Direct Anthropic API key (metered): set "
                "ANTHROPIC_API_KEY and pass --allow-api-key."
                + hint
            )

    return AuthStatus(
        provider="claude",
        auth_mode=mode,
        api_key_scrubbed=api_key_scrubbed,
        auth_token_scrubbed=auth_token_was_scrubbed,
        claude_cli_path=cli_path,
        claude_cli_version=_cli_version(cli_path),
        credentials_file=creds_file,
        gateway_base_url=base_url if mode == "gateway" else None,
        gateway_model=os.environ.get("ANTHROPIC_MODEL") if mode == "gateway" else None,
    )
