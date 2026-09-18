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
import warnings
from collections.abc import Iterable

from ecsctx.masking.patterns import ALL_PACKS

_ENV_VAR = "ECSCTX_MASKING_PACKS"
_ALWAYS = frozenset({"default"})

_explicit: frozenset[str] | None = None
_resolved: frozenset[str] | None = None
_warned: set[str] = set()


def _names(packs: Iterable[str] | str) -> frozenset[str]:
    """A setting or env var may be a list or one comma-separated string."""
    if isinstance(packs, str):
        packs = packs.split(",")
    return frozenset(name.strip() for name in packs if name and name.strip())


def _normalise(packs: Iterable[str] | str) -> frozenset[str]:
    names = _names(packs)
    unknown = names - ALL_PACKS
    if unknown:
        raise ValueError(
            f"unknown masking pack(s) {sorted(unknown)}; choose from {sorted(ALL_PACKS)}"
        )
    return names | _ALWAYS


def configure_masking_packs(packs: Iterable[str] | str | None) -> None:
    """Choose the packs explicitly. ``None`` goes back to settings/env/default.

    Raises on an unknown pack: this runs while logging is being configured,
    where failing loudly is right.
    """
    global _explicit, _resolved
    _explicit = None if packs is None else _normalise(packs)
    _resolved = None


def _from_django_settings() -> tuple[bool, Iterable[str] | str | None]:
    """(settings_ready, value). Django is an optional extra."""
    try:
        from django.conf import settings
    except ImportError:
        return True, None
    if not settings.configured:
        return False, None
    return True, getattr(settings, "ECSCTX_MASKING_PACKS", None)


def _configured_value() -> tuple[bool, str, Iterable[str] | str]:
    settings_ready, from_settings = _from_django_settings()
    if from_settings is not None:
        return settings_ready, "the ECSCTX_MASKING_PACKS setting", from_settings
    return settings_ready, "the ECSCTX_MASKING_PACKS environment variable", os.environ.get(_ENV_VAR, "")


def masking_pack_errors() -> list[str]:
    """Problems with the configured packs, for the Django boot check."""
    if _explicit is not None:
        return []
    _ready, source, value = _configured_value()
    unknown = _names(value) - ALL_PACKS
    if not unknown:
        return []
    message = (
        f"{source} names unknown masking pack(s) {sorted(unknown)}; choose from "
        f"{sorted(ALL_PACKS)}. Until it is fixed every pack is on."
    )
    return [message]


def get_masking_packs() -> frozenset[str]:
    """The packs in force. Never raises: this runs on every log line.

    An unknown pack name in the setting or env var fails closed — every pack
    is on, with a warning once — rather than turning masking off or making
    each log call raise. The boot check reports it.
    """
    global _resolved
    if _explicit is not None:
        return _explicit
    if _resolved is not None:
        return _resolved
    settings_ready, source, value = _configured_value()
    try:
        packs = _normalise(value)
    except ValueError as error:
        if source not in _warned:
            _warned.add(source)
            warnings.warn(f"{source}: {error}. Masking with every pack.", RuntimeWarning, stacklevel=2)
        packs = ALL_PACKS
    if settings_ready:
        _resolved = packs
    return packs


def _reset_masking_config() -> None:
    """Forget every choice. For tests."""
    global _explicit, _resolved
    _explicit = None
    _resolved = None
    _warned.clear()
