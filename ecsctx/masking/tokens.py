"""Tokenization + label formatting shared by every masking rule.

safe_tokenize wraps ecsctx.pii.tokenize with a fail-closed fallback: if PII is
not configured, or tokenization fails for any reason, it returns
[PII_REDACTED] rather than letting raw PII through or raising.
"""

from __future__ import annotations

from ecsctx.pii import tokenize as _pii_tokenize

_TOKEN_PREFIXE = "ptok:"
_REDACTED = "[PII_REDACTED]"


def already_tokenized(text: str) -> bool:
    return text.startswith(_TOKEN_PREFIXE)


def safe_tokenize(value: str, field_type: str = "generic") -> str:
    """Tokenize a value using HMAC-SHA-256 via the PII module.

    If PII is not configured, returns [PII_REDACTED] to prevent raw PII from
    appearing in logs.
    """
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


def mask_by_label(value: str, field_type: str, tokenizable: bool=True) -> str:
    label = make_label(field_type)
    if not value or not tokenizable:
        return f"[{label}]"
    if already_masked(value):
        return value
    token = safe_tokenize(value, field_type)
    if token == _REDACTED:
        return f"[{label}]"
    return f"[{label}:{token}]"
