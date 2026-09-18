"""Shared Ottu event vocabulary (ticket #159487 catalogue).

One module per domain exporting UPPER_SNAKE ``EventSpec`` constants, so a
typo is an ``AttributeError`` at import instead of a new value in the index.
A service registers the catalogue together with its own events through
``register_ottu()``, once, from an ``AppConfig.ready()``. Its own events live
in one module of that service, declared ahead of use, and are held to the same
naming rules (``rules``) as these; ``docs/events.md`` lists the catalogue and
``docs/rules/log-events.md`` is the rule every service follows.

``category``, ``type``, ``reasons`` and levels follow Connect's definitions,
the first service to emit this vocabulary end to end. ``required`` lists the
fields each event carries (minus ``event.action``, which is the spec itself);
it is declaration-only — the runtime contract validator does not enforce it
yet (#159491). A terminal event declared at ``warning`` is logged at warning
on failure (``failure_level``); an unexpected failure logs at ``error`` at the
call site, which always picks the level.
"""

from collections.abc import Iterable

from ecsctx.events import registry
from ecsctx.events.spec import EventSpec

from . import (
    api,
    auth,
    cache,
    card,
    crypto,
    net,
    payment,
    pg,
    rules,
    task,
    threeds,
    webhook,
    yaml_render,
)

ALL_DOMAINS: dict[str, tuple] = {
    "pg": pg.SPECS,
    "crypto": crypto.SPECS,
    "payment": payment.SPECS,
    "card": card.SPECS,
    "threeds": threeds.SPECS,
    "net": net.SPECS,
    "task": task.SPECS,
    "cache": cache.SPECS,
    "api": api.SPECS,
    "webhook": webhook.SPECS,
    "auth": auth.SPECS,
}


def register_ottu(
    *,
    local: dict[str, Iterable[EventSpec]] | None = None,
    aliases: dict[str, str] | None = None,
    freeze: bool = True,
) -> None:
    """Register the shared catalogue plus a service's own events, then freeze.

    A prefix can be registered only once, so a service's events under a
    shared prefix (``pg.payload_built`` next to ``pg.request_sent``) are
    merged into that domain here; prefixes the catalogue does not have
    (``wallet``, ``bus``) become domains of their own. Redefining a shared
    action raises. Call once, from an ``AppConfig.ready()``.

    Every local event is checked against ``rules`` first, and all of them are
    reported together: a badly named event fails the service at startup and in
    its tests, before anything is registered.
    """
    extra = {prefix: tuple(specs) for prefix, specs in (local or {}).items()}
    rules.check_all(spec for specs in extra.values() for spec in specs)
    for prefix, specs in ALL_DOMAINS.items():
        registry.register_domain(prefix, specs + extra.pop(prefix, ()))
    for prefix, specs in extra.items():
        registry.register_domain(prefix, specs)
    if aliases:
        registry.register_aliases(aliases)
    if freeze:
        registry.freeze()


__all__ = [
    "ALL_DOMAINS",
    "api",
    "auth",
    "cache",
    "card",
    "crypto",
    "net",
    "payment",
    "pg",
    "register_ottu",
    "rules",
    "task",
    "threeds",
    "webhook",
    "yaml_render",
]
