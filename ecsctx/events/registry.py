"""Who owns which event prefix.

One registry per process. A domain claims a prefix and the events under it;
claiming a prefix twice, or registering an event that does not live under the
prefix it was registered with, is rejected at startup rather than discovered as
two incompatible meanings of `payment.*` in the same index.
"""

import threading
import warnings

from ecsctx.events.spec import EventSpec

# The ECS field-set names. A domain called `log` emitting `log.written` reads in
# a query exactly like the `log.*` field set, and that ambiguity cannot be fixed
# after the documents are written.
RESERVED_PREFIXES = frozenset(
    {
        "ecs",
        "error",
        "event",
        "http",
        "labels",
        "log",
        "service",
        "span",
        "trace",
        "url",
        "user",
    }
)

_lock = threading.Lock()
_domains: dict[str, tuple[EventSpec, ...]] = {}
_by_action: dict[str, EventSpec] = {}
_aliases: dict[str, str] = {}
_frozen = False


class RegistryFrozenError(RuntimeError):
    """Registration attempted after `freeze()`."""


def register_domain(prefix: str, specs) -> None:
    """Claim `prefix` for `specs`. Idempotent only for an identical re-register.

    Re-registering the same prefix with the same specs is allowed because Django
    can import an AppConfig module twice under some autoreload paths; changing
    what a prefix means is not.
    """
    specs = tuple(specs)
    if not prefix.isidentifier() or prefix != prefix.lower():
        raise ValueError(f"{prefix!r} must be a bare lowercase identifier")
    if prefix in RESERVED_PREFIXES:
        raise ValueError(
            f"{prefix!r} is an ECS field-set name; an event under it would be "
            f"indistinguishable from the {prefix}.* fields in a query"
        )
    for spec in specs:
        if spec.domain != prefix:
            raise ValueError(f"{spec.action!r} does not belong to domain {prefix!r}")
    with _lock:
        if _frozen:
            raise RegistryFrozenError(
                f"cannot register {prefix!r}: the registry was frozen after app "
                f"loading, so anything registered now is invisible to consumers "
                f"that already read it"
            )
        existing = _domains.get(prefix)
        if existing is not None:
            if existing == specs:
                return
            raise ValueError(f"domain {prefix!r} is already registered")
        _domains[prefix] = specs
        for spec in specs:
            _by_action[spec.action] = spec


def register_aliases(mapping: dict[str, str]) -> None:
    """Map retired names to current ones.

    44 `ecs_event` sites in Connect and ~163 live names in Ottu PG predate this
    registry. They migrate by alias rather than by breaking.
    """
    with _lock:
        if _frozen:
            raise RegistryFrozenError("cannot add aliases after freeze()")
        for old, new in mapping.items():
            if old in _by_action:
                raise ValueError(f"{old!r} is a registered event, not a retired name")
            _aliases[old] = new


def resolve(name) -> EventSpec | None:
    """Look up an event by action, following the alias map. None if unknown."""
    if isinstance(name, EventSpec):
        return name
    spec = _by_action.get(name)
    if spec is not None:
        return spec
    target = _aliases.get(name)
    if target is None:
        return None
    resolved = _by_action.get(target)
    if resolved is not None:
        warnings.warn(
            f"{name!r} is a retired event name; use {target!r}",
            DeprecationWarning,
            stacklevel=3,
        )
    return resolved


def freeze() -> None:
    """Close registration. Called once app loading is done."""
    global _frozen
    with _lock:
        _frozen = True


def is_frozen() -> bool:
    return _frozen


def all_events() -> tuple[EventSpec, ...]:
    return tuple(_by_action.values())


def domains() -> tuple[str, ...]:
    return tuple(_domains)


def reset() -> None:
    """Forget every registration. For tests, and only for tests."""
    global _frozen
    with _lock:
        _domains.clear()
        _by_action.clear()
        _aliases.clear()
        _frozen = False
