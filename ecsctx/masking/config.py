"""Which masking packs are on.

Resolution order, first match wins:

1. an explicit ``configure_masking_packs()`` call — what
   ``get_logging_config(masking_packs=...)`` makes;
2. the Django setting ``ECSCTX_MASKING_PACKS``;
3. the environment variable ``ECSCTX_MASKING_PACKS`` (comma-separated);
4. ``default`` alone.

``default`` is always part of the result: turning off credential and email
masking is not something a service can ask for by listing other packs.

The Django setting is read lazily, at log time, because logging is configured
while settings are still being imported. Until settings are configured the
answer is not cached, so an early log line cannot pin the fallback for the
life of the process.
"""

from __future__ import annotations

import os
from collections.abc import Iterable

from ecsctx.masking.patterns import ALL_PACKS

_ENV_VAR = "ECSCTX_MASKING_PACKS"
_ALWAYS = frozenset({"default"})

_explicit: frozenset[str] | None = None
_resolved: frozenset[str] | None = None


def _normalise(packs: Iterable[str]) -> frozenset[str]:
    names = frozenset(name.strip() for name in packs if name and name.strip())
    unknown = names - ALL_PACKS
    if unknown:
        raise ValueError(
            f"unknown masking pack(s) {sorted(unknown)}; choose from {sorted(ALL_PACKS)}"
        )
    return names | _ALWAYS


def configure_masking_packs(packs: Iterable[str] | None) -> None:
    """Choose the packs explicitly. ``None`` goes back to settings/env/default."""
    global _explicit, _resolved
    _explicit = None if packs is None else _normalise(packs)
    _resolved = None


def _from_django_settings() -> tuple[bool, Iterable[str] | None]:
    """(settings_ready, value). Django is an optional extra."""
    try:
        from django.conf import settings
    except ImportError:
        return True, None
    if not settings.configured:
        return False, None
    return True, getattr(settings, "ECSCTX_MASKING_PACKS", None)


def get_masking_packs() -> frozenset[str]:
    global _resolved
    if _explicit is not None:
        return _explicit
    if _resolved is not None:
        return _resolved
    settings_ready, from_settings = _from_django_settings()
    if from_settings is not None:
        packs = _normalise(from_settings)
    else:
        packs = _normalise(os.environ.get(_ENV_VAR, "").split(","))
    if settings_ready:
        _resolved = packs
    return packs


def _reset_masking_config() -> None:
    """Forget every choice. For tests."""
    global _explicit, _resolved
    _explicit = None
    _resolved = None
