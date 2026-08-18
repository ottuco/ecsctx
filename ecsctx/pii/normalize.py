"""Input normalization for deterministic tokenization.

Ensures the same business value always produces the same token,
regardless of formatting differences in the input.
"""

import re

# Strip everything except digits and leading +
_PHONE_STRIP = re.compile(r"[^\d+]")


def strip_wrapping_quotes(value: str) -> str:
    """Strip one layer of matching quote characters, single or double.

    A regex capture from raw text sometimes includes the surrounding quote
    punctuation as part of the match (e.g. a JSON-string value grabbed as
    '"user@example.com"') — that punctuation is a syntax artifact, not part
    of the value. Only strips a matching pair (same character at both ends),
    so "O'Brien" or a value with mismatched quote chars is left alone.
    """
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def normalize_email(value: str) -> str:
    """Trim whitespace and lowercase."""
    return value.lower()


def normalize_phone(value: str) -> str:
    """Normalize to E.164-ish: strip spaces/dashes/parens, keep leading +."""
    digits = _PHONE_STRIP.sub("", value)
    # Ensure leading + if original had it
    if value.startswith("+") and not digits.startswith("+"):
        digits = "+" + digits
    return digits


_NORMALIZERS = {
    "email": normalize_email,
    "phone": normalize_phone,
}


def normalize_value(value: str, field_type: str) -> str:
    """Normalize a value based on its field type.

    Quote-stripping runs first, for every field type, before the type-
    specific normalizer — a general case, not an email/phone-only concern.

    Unknown field types are stripped of surrounding whitespace only.
    """
    value = value.strip()
    value = strip_wrapping_quotes(value)
    normalizer = _NORMALIZERS.get(field_type)
    if normalizer:
        value = normalizer(value)
    return value.strip()
