"""Which masking packs are on, and which key names a service marks safe.

Resolution order, first match wins:

1. an explicit ``configure_masking_packs()`` call — what
   ``get_logging_config(masking_packs=...)`` makes;
2. the Django setting ``ECSCTX_MASKING_PACKS``;
3. the environment variable ``ECSCTX_MASKING_PACKS`` (comma-separated);
4. ``default`` alone.

``default`` is always part of the result: turning off credential and email
masking is not something a service can ask for by listing other packs.

A service's own safe key names (``ECSCTX_MASK_SAFE_KEYS``) resolve the same
way: ``configure_masking_safe_keys()``, else the Django setting, else the
environment variable, else none. They extend ``patterns.SAFE_KEYS``, which holds
only names that mean the same in every service.

The Django setting is read lazily, at log time, because logging is configured
while settings are still being imported. Until settings are configured the
answer is not cached, so an early log line cannot pin the fallback for the
life of the process.
"""

from __future__ import annotations

import os
import warnings
from collections.abc import Iterable
from functools import lru_cache

from ecsctx.masking.patterns import ALL_PACKS, classify_key, never_safe

_ENV_VAR = "ECSCTX_MASKING_PACKS"
_SAFE_KEYS_VAR = "ECSCTX_MASK_SAFE_KEYS"
_ALWAYS = frozenset({"default"})

_explicit: frozenset[str] | None = None
_resolved: frozenset[str] | None = None
_explicit_safe: frozenset[str] | None = None
_resolved_safe: frozenset[str] | None = None
_warned: set[str] = set()


def _names(packs: Iterable[str] | str) -> frozenset[str]:
    """A setting or env var may be a list or one comma-separated string.

    Anything else — True, 1, a list holding a number — comes back as its repr,
    which is never a pack name, so it is reported and fails closed rather than
    raising on a log call.
    """
    if isinstance(packs, str):
        packs = packs.split(",")
    elif not isinstance(packs, (list, tuple, set, frozenset)):
        return frozenset({repr(packs)})
    return frozenset(
        (name.strip() if isinstance(name, str) else repr(name))
        for name in packs
        if not isinstance(name, str) or name.strip()
    )


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


def _from_django_settings(name: str = _ENV_VAR) -> tuple[bool, Iterable[str] | str | None]:
    """(settings_ready, value). Django is an optional extra."""
    try:
        from django.conf import settings
    except ImportError:
        return True, None
    if not settings.configured:
        return False, None
    return True, getattr(settings, name, None)


def _configured_value(name: str = _ENV_VAR) -> tuple[bool, str, Iterable[str] | str]:
    """(settings_ready, where the value came from, value): the Django setting,
    else the environment variable of the same name."""
    settings_ready, from_settings = _from_django_settings(name)
    if from_settings is not None:
        return settings_ready, f"the {name} setting", from_settings
    return settings_ready, f"the {name} environment variable", os.environ.get(name, "")


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


def _safe_names(keys: Iterable[str] | str) -> frozenset[str]:
    return frozenset(name.lower() for name in _names(keys))


def _accepted_safe_names(value: Iterable[str] | str) -> tuple[frozenset[str], tuple[str, ...]]:
    """(accepted names, refused names) of a setting or env value."""
    names = _safe_names(value)
    refused = tuple(sorted(name for name in names if never_safe(name)))
    return names - frozenset(refused), refused


# Until Django settings are configured nothing is cached, and every log line
# resolves the env var again: remember what each env value parses to.
_accepted_env_names = lru_cache(maxsize=8)(_accepted_safe_names)


def configure_masking_safe_keys(keys: Iterable[str] | str | None) -> None:
    """List key names this service's payloads use for things that are not PII,
    so the key rules leave their values alone. ``None`` goes back to
    settings/env.

    ecsctx's own SAFE_KEYS hold only names that mean the same in every
    service; the rest is the service's to list (``ecsctx.contrib.ottu.masking``
    has Ottu's). A listed key's value is still content-scanned, except that a
    digits-only reference number of up to 14 digits is left as it is -- an
    RRN, an acquirer id -- when the key is not PII on its own; a 15-19 digit
    value is always truncated. Raises on a name that is a card, CVV or
    credential outright: listing one would switch off a mask PCI requires.
    """
    global _explicit_safe, _resolved_safe
    if keys is None:
        _explicit_safe = None
    else:
        names = _safe_names(keys)
        refused = sorted(name for name in names if never_safe(name))
        if refused:
            raise ValueError(f"{refused} cannot be a safe key: it names a card, CVV or credential")
        _explicit_safe = names
    _resolved_safe = None


def masking_safe_key_errors() -> list[str]:
    """Names in the setting or env var that cannot be safe keys, for the Django boot check."""
    if _explicit_safe is not None:
        return []
    _ready, source, value = _configured_value(_SAFE_KEYS_VAR)
    refused = sorted(name for name in _safe_names(value) if never_safe(name))
    if not refused:
        return []
    message = (
        f"{source} lists {refused}, which name a card, CVV or credential and "
        "cannot be safe keys. They stay masked."
    )
    return [message]


def get_masking_safe_keys() -> frozenset[str]:
    """The service's own safe keys, lowercased. Never raises: this runs on every log line.

    A refused name in the setting or env var is dropped with a warning once,
    and stays masked; the boot check reports it.
    """
    global _resolved_safe
    if _explicit_safe is not None:
        return _explicit_safe
    if _resolved_safe is not None:
        return _resolved_safe
    settings_ready, source, value = _configured_value(_SAFE_KEYS_VAR)
    accept = _accepted_env_names if isinstance(value, str) else _accepted_safe_names
    names, refused = accept(value)
    if refused and source not in _warned:
        _warned.add(source)
        warnings.warn(
            f"{source}: {list(refused)} cannot be safe keys (a card, CVV or credential); they stay masked.",
            RuntimeWarning,
            stacklevel=2,
        )
    if settings_ready:
        _resolved_safe = names
    return names


def key_field_type(key: str) -> str | None:
    """The field type the engine gives a key name, under this service's packs
    and safe keys -- or None for a name it leaves to the content rules.

    For a value that reaches a log outside a mapping, where no key sits next
    to it: a URL path segment such as the card token in
    `DELETE /v1/pbl/card/token/<token>/`. Mask it with
    ``mask_by_field_type(value, key_field_type("token"))`` and it reads as the
    same field would.
    """
    return classify_key(key, get_masking_packs(), get_masking_safe_keys())


def _reset_masking_config() -> None:
    """Forget every choice. For tests."""
    global _explicit, _resolved, _explicit_safe, _resolved_safe
    _explicit = None
    _resolved = None
    _explicit_safe = None
    _resolved_safe = None
    _warned.clear()
