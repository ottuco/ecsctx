"""Path-based exemptions for key-based PII masking.

Lets a consuming service mark specific JSON paths as non-PII so their string
values are not key-tokenized. Content-based regex scrubbing (email/phone/card/
etc.) still runs on every string leaf regardless — defense in depth. Only the
ecsctx-derived PII categories (email/phone/address/name/generic) can be
exempted; secrets (cvv/credential/payment-id) never are — see
ecsctx.masking.patterns.key_label.

Path syntax: dict step "key", array step "[*]", single dict-key wildcard "*".
Matching is a PREFIX match, so a pattern also exempts the whole subtree below
it ("payment_methods" exempts everything under it; "payment_methods[*].name"
only that leaf).
"""

from __future__ import annotations

import os
import re

_exempt_patterns: tuple | None = None
_mask_auto_configure_attempted: bool = False


def _compile_path(pattern: str) -> tuple:
    """Parse an exemption pattern into a tuple of segments.

    "payment_methods[*].name" -> ("payment_methods", "[*]", "name")
    "customer.name"           -> ("customer", "name")
    "a.*.b"                   -> ("a", "*", "b")
    """
    return tuple(re.findall(r"\[\*\]|[^.\[\]]+", pattern))


def configure_masking(*, exempt_paths: list[str] | None = None) -> None:
    """Configure path exemptions for PII masking (highest precedence)."""
    global _exempt_patterns, _mask_auto_configure_attempted
    paths = exempt_paths or []
    _exempt_patterns = tuple(_compile_path(p) for p in paths if p)
    _mask_auto_configure_attempted = True


def configure_masking_from_env() -> None:
    """Load exemptions from the PII_MASK_EXEMPT_PATHS env var (CSV). Idempotent."""
    global _exempt_patterns, _mask_auto_configure_attempted
    if _mask_auto_configure_attempted or _exempt_patterns is not None:
        return
    _mask_auto_configure_attempted = True
    raw = os.environ.get("PII_MASK_EXEMPT_PATHS", "")
    paths = [p.strip() for p in raw.split(",") if p.strip()]
    _exempt_patterns = tuple(_compile_path(p) for p in paths)


def masking_is_configured() -> bool:
    """True if mask exemptions have been explicitly set or env-loaded."""
    return _exempt_patterns is not None


def _get_exempt_patterns() -> tuple:
    if _exempt_patterns is None:
        configure_masking_from_env()
    return _exempt_patterns or ()


def _reset_masking() -> None:
    """Reset masking config. For testing only."""
    global _exempt_patterns, _mask_auto_configure_attempted
    _exempt_patterns = None
    _mask_auto_configure_attempted = False


def _path_matches(path: tuple, pattern: tuple) -> bool:
    """Prefix match: True if `pattern` matches the leading segments of `path`.

    "[*]" matches an array step only; "*" matches exactly one dict-key step
    (never an array step); a literal matches an equal dict key.
    """
    if len(pattern) > len(path):
        return False
    for pat_seg, path_seg in zip(pattern, path):
        if pat_seg == "[*]":
            if path_seg != "[*]":
                return False
        elif pat_seg == "*":
            if path_seg == "[*]":
                return False
        elif pat_seg != path_seg:
            return False
    return True


def _path_is_exempt(path: tuple, patterns: tuple) -> bool:
    return any(_path_matches(path, p) for p in patterns)
