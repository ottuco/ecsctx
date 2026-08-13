"""Tokenization + label formatting shared by every masking rule.

safe_tokenize wraps ecsctx.pii.tokenize with a fail-closed fallback: if PII is
not configured, or tokenization fails for any reason, it returns
[PII_REDACTED] rather than letting raw PII through or raising.
"""

from __future__ import annotations

from ecsctx.pii import tokenize as _pii_tokenize

from ecsctx.masking.fields_rules import get_field_rule


_TOKEN_PREFIXE = "ptok:"
_REDACTED = "[PII_REDACTED]"


def already_tokenized(text: str) -> bool:
    return text.startswith(_TOKEN_PREFIXE)


def safe_tokenize(value: str, field_type: str = "generic") -> str:
    if not value:
        return value

    # Idempotency: already tokenized.
    if already_tokenized(value):
        return value

    # Quote-stripping (single or double) happens inside tokenize(), via
    # normalize_value() — a general case for every field type, not just this
    # call site. See ecsctx.pii.normalize.strip_wrapping_quotes.
    try:
        token = _pii_tokenize(value, field_type)
    except Exception:
        return _REDACTED
    return token


def make_label(field_type: str) -> str:
    return F"{field_type.upper().replace('_', '-')}-MASKED"


def already_masked(text: str) -> bool:
    return "-MASKED:" in text or "-MASKED]" in text


def mask_by_field_type(value: str, field_type: str) -> str:
    field_rule = get_field_rule(field_type)
    label = make_label(field_rule.field_type)
    if not value or not field_rule.tokenizable:
        return f"[{label}]"
    if already_masked(value):
        return value
    token = safe_tokenize(value, field_rule.field_type)
    if token == _REDACTED:
        return f"[{label}]"
    return f"[{label}:{token}]"
