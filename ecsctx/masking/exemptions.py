"""Path-based exemptions for key-based PII masking.

Lets a consuming service mark specific JSON paths as non-PII so their string
values are not key-tokenized. Content-based regex scrubbing (email/phone/card/
etc.) still runs on every string leaf regardless — defense in depth. Only the
ecsctx-derived PII categories (email/phone/address/name/generic) can be
exempted; secrets (cvv/credential/payment-id) never are — see
ecsctx.masking.patterns.key_label.

Path syntax: dict step "key", array step "[*]", single dict-key wildcard "*".
A pattern is anchored at the root of the record or at a payload container
(payload, args, kwargs, extra, http request/response body), and matching is a
PREFIX match from there, so it also exempts the whole subtree below it
("payment_methods" exempts everything under it; "payment_methods[*].name"
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


def _from_django_settings() -> tuple[bool, list[str] | None]:
    """(settings_ready, ECSCTX_MASK_EXEMPT_PATHS). Django is an optional extra."""
    try:
        from django.conf import settings
    except ImportError:
        return True, None
    if not settings.configured:
        return False, None
    return True, getattr(settings, "ECSCTX_MASK_EXEMPT_PATHS", None)


def _get_exempt_patterns() -> tuple:
    """Explicit configure_masking() → the Django setting → the env var.

    Resolved here, by whatever masks first — a structlog line, the handler
    filter on a stdlib record, a body masker — so no call order can leave the
    setting unapplied. Not cached until settings are configured, so an early
    log line cannot pin the env-only answer.
    """
    global _exempt_patterns, _mask_auto_configure_attempted
    if _exempt_patterns is not None:
        return _exempt_patterns
    settings_ready, from_settings = _from_django_settings()
    if from_settings is not None:
        paths = list(from_settings)
    else:
        raw = os.environ.get("PII_MASK_EXEMPT_PATHS", "")
        paths = [p.strip() for p in raw.split(",") if p.strip()]
    patterns = tuple(_compile_path(p) for p in paths if p)
    if settings_ready:
        _exempt_patterns = patterns
        _mask_auto_configure_attempted = True
    return patterns


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


# Where 0.6.x's container-relative patterns ("payment_methods[*].name") were
# anchored: the payload containers the processor used to scan, before and
# after namespace_ecs_fields moves non-root keys under `extra`.
_CONTAINERS = (
    ("payload",),
    ("args",),
    ("args", "[*]"),
    ("kwargs",),
    ("extra",),
    ("extra", "payload"),
    ("http", "request", "body"),
    ("http", "response", "body"),
)


def _path_is_exempt(path: tuple, patterns: tuple) -> bool:
    """True if a pattern matches from the root of the record or from one of the
    payload containers.

    Patterns were written relative to the payload container in 0.6.x
    ("payment_methods[*].name") and relative to the whole record since 0.7.0
    ("payload.payment_methods[*].name"); both anchors are honoured. Nothing
    deeper: a short pattern such as "audit" must not exempt an "audit" key
    nested anywhere in a payload.
    """
    if not patterns:
        return False
    starts = [0] + [len(c) for c in _CONTAINERS if path[: len(c)] == c]
    return any(_path_matches(path[start:], p) for p in patterns for start in starts)
