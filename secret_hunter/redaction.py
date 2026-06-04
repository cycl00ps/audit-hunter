"""Secret redaction helpers."""

from __future__ import annotations


REDACTION = "<redacted>"


def redact_secret(secret: object) -> str:
    value = "" if secret is None else str(secret)
    if not value:
        return REDACTION
    return f"<redacted:{len(value)} chars>"


def redact_evidence(evidence: object, secret: object | None = None) -> str:
    text = "" if evidence is None else str(evidence)
    if not text:
        return REDACTION

    if secret:
        raw = str(secret)
        if raw and raw in text:
            text = text.replace(raw, redact_secret(raw))

    if len(text) > 500:
        text = text[:497] + "..."
    return text
