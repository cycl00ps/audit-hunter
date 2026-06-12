"""Secret redaction helpers."""

from __future__ import annotations


REDACTION = "<redacted>"


def redact_secret(secret: object) -> str:
    value = "" if secret is None else str(secret).strip()
    if not value:
        return REDACTION
    length = len(value)
    if length <= 4:
        return f"<redacted:{length} chars>"
    if length <= 8:
        return f"{value[:1]}...{value[-1:]} <redacted:{length} chars>"
    if length <= 16:
        return f"{value[:3]}...{value[-2:]} <redacted:{length} chars>"
    return f"{value[:4]}...{value[-4:]} <redacted:{length} chars>"


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
