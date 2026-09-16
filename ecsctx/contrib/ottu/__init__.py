"""Shared Ottu event vocabulary (ticket #159487 catalogue).

One module per domain exporting UPPER_SNAKE ``EventSpec`` constants, so a
typo is an ``AttributeError`` at import instead of a new value in the index.
Extension is a new domain module plus ``register_domain`` — a plain ``Enum``
cannot gain members locally, which is why this is constants, not enums.

``required`` keeps the ticket's field names verbatim (minus ``event.action``,
which is the spec itself); it is declaration-only — the runtime contract
validator does not enforce it yet (#159491). ``category``/``type`` are set
only where the ticket or the ecsctx precedent pins them; taxonomy enrichment
is a follow-up once o11y confirms the ECS mappings.
"""

from . import api, auth, cache, card, crypto, net, payment, pg, task, threeds, webhook, yaml_render

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
    "task",
    "threeds",
    "webhook",
    "yaml_render",
]
