"""Tests for the API-error classification in runner.py."""

from __future__ import annotations

import pytest

from audit.runner import (
    QuotaExhaustedError,
    TransientAgentError,
    _build_repair_prompt,
    _schema_prompt_text,
    _classify_api_error,
)


@pytest.mark.parametrize("text", [
    "You're out of extra usage · resets 2am (Europe/Rome)",
    "Usage limit reached for the day.",
    "Your plan has no remaining quota.",
    "YOU'RE OUT OF EXTRA USAGE.",
])
def test_quota_classified(text: str) -> None:
    label, exc = _classify_api_error(text)
    assert label == "quota_exhausted"
    assert exc is QuotaExhaustedError


@pytest.mark.parametrize("text", [
    "API Error: 529 Overloaded. This is a server-side issue, usually temporary",
    "API Error: 429 Too Many Requests",
    "Server overloaded — please try again",
    "API Error: 503",
    "API Error: 502 Bad Gateway",
    "API Error: 500 Internal Server Error",
    "rate_limit hit",
    "Service temporarily unavailable",
])
def test_transient_classified(text: str) -> None:
    label, exc = _classify_api_error(text)
    assert label == "transient"
    assert exc is TransientAgentError


def test_unknown_defaults_to_transient() -> None:
    label, exc = _classify_api_error("some weird new error string")
    assert label == "unknown_api_error"
    assert exc is TransientAgentError


def test_empty_defaults_to_transient() -> None:
    label, exc = _classify_api_error("")
    assert label == "unknown_api_error"
    assert exc is TransientAgentError


def test_repair_prompt_includes_full_schema(tmp_path) -> None:
    schema = tmp_path / "out.schema.json"
    schema.write_text(
        '{"type":"object","required":["ok"],'
        '"properties":{"ok":{"type":"boolean"}}}'
    )

    prompt = _build_repair_prompt("{}", ["<root>: 'ok' is required"], schema)

    assert "Validate against this exact JSON Schema" in prompt
    assert '"required":["ok"]' in prompt


def test_schema_prompt_includes_local_refs(tmp_path) -> None:
    root = tmp_path / "root.schema.json"
    child = tmp_path / "child.schema.json"
    root.write_text(
        '{"type":"object","properties":{"items":{"type":"array",'
        '"items":{"$ref":"child.schema.json"}}}}'
    )
    child.write_text(
        '{"type":"object","required":["task_id","scope_hint"],'
        '"properties":{"task_id":{"type":"string"},"scope_hint":{"type":"string"}}}'
    )

    prompt = _schema_prompt_text(root)

    assert "## root.schema.json" in prompt
    assert "## child.schema.json" in prompt
    assert '"required":["task_id","scope_hint"]' in prompt
