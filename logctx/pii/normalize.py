"""Input normalization for deterministic tokenization.

Ensures the same business value always produces the same token,
regardless of formatting differences in the input.
"""

import re

# Strip everything except digits and leading +
_PHONE_STRIP = re.compile(r"[^\d+]")


def normalize_email(value: str) -> str:
    """Trim whitespace and lowercase."""
    return value.strip().lower()


def normalize_phone(value: str) -> str:
    """Normalize to E.164-ish: strip spaces/dashes/parens, keep leading +."""
    digits = _PHONE_STRIP.sub("", value)
    # Ensure leading + if original had it
    if value.lstrip().startswith("+") and not digits.startswith("+"):
        digits = "+" + digits
    return digits


_NORMALIZERS = {
    "email": normalize_email,
    "phone": normalize_phone,
}


def normalize_value(value: str, field_type: str) -> str:
    """Normalize a value based on its field type.

    Unknown field types are stripped of surrounding whitespace only.
    """
    normalizer = _NORMALIZERS.get(field_type)
    if normalizer:
        return normalizer(value)
    return value.strip()
