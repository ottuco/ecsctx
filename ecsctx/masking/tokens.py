"""Tokenization + label formatting shared by every masking rule.

safe_tokenize wraps ecsctx.pii.tokenize with a fail-closed fallback: if PII is
not configured, or tokenization fails for any reason, it returns
[PII_REDACTED] rather than letting raw PII through or raising.
"""

from __future__ import annotations

import re

from ecsctx.masking.fields_rules import get_field_rule
from ecsctx.pii import tokenize as _pii_tokenize

_TOKEN_PREFIX = "ptok:"
_REDACTED = "[PII_REDACTED]"

# What _truncate_pan produces: the BIN, stars, and the last four (15 digits and
# up), or stars and the last four below that. With the [CARD-MASKED:…] wrapper
# gone, THIS SHAPE IS THE MARKER -- it is the only thing saying "a PAN already
# passed through here", so it has to be recognisable on its own. Five stars is
# the fewest _truncate_pan ever emits (a 15-digit PAN); {4,} leaves a margin.
_TRUNCATED_PAN = r"(?:\d{6})?\*{4,}\d{4}"

# A whole value that masking itself produced: a bare label, a bare token, a
# truncated PAN, or the pre-0.11 bracketed card form, which still arrives from
# documents masked by an older release.
_MASKED_VALUE = re.compile(
    rf"\[[A-Z0-9-]+-MASKED(?::ptok:[\w:.-]+)?\]|ptok:[\w:.-]+"
    rf"|{_TRUNCATED_PAN}|\[CARD-MASKED:{_TRUNCATED_PAN}\]"
)


def already_tokenized(text: str) -> bool:
    return text.startswith(_TOKEN_PREFIX)


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
    """Whether ``text`` is, in its entirety, something masking already produced.

    Anchored on purpose. It used to be a substring test for "-MASKED:" /
    "-MASKED]", which was safe only while every masked value wore brackets: a
    bare truncated PAN has no punctuation to search for, and a substring test
    would let a marker-shaped fragment vouch for the rest of a longer value.
    """
    return _MASKED_VALUE.fullmatch(text) is not None


def mask_by_field_type(value: str, field_type: str) -> str:
    """The token for ``value``, bare (``ptok:v1:…``), as a reader searches for
    it; ``[LABEL]`` where no token can stand: a type that is never tokenized,
    or PII tokenization not configured or failing.

    Brackets mean nothing survived. Where something real is carried -- a token,
    or a PAN's BIN and last four -- it is carried bare.
    """
    field_rule = get_field_rule(field_type)
    label = make_label(field_rule.field_type)
    if not value:
        # Nothing was there. A label would read as a value that had been
        # hidden -- the same reason a null stays null.
        return value
    if not field_rule.tokenizable:
        return f"[{label}]"
    if already_masked(value):
        return value
    token = safe_tokenize(value, field_rule.field_type)
    if token == _REDACTED:
        return f"[{label}]"
    return token
