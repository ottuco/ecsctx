"""Render the registered catalogue as the ticket's ``logging-events.yaml``.

Deliberately stdlib-only: the shape is fixed (scalars, bools, flat string
lists), so a hand renderer stays deterministic without a new dependency.
The parser lives in the tests, next to the only consumer that reads back.
"""

from collections.abc import Mapping, Sequence
from typing import Any


def _scalar(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    return str(value)


def _list(values: Sequence[str]) -> str:
    return "[" + ", ".join(values) + "]"


def render(domains: Mapping[str, Sequence]) -> str:
    """Render ``{domain: [EventSpec, ...]}`` sorted by action."""
    specs = sorted(
        (spec for specs in domains.values() for spec in specs),
        key=lambda spec: spec.action,
    )
    lines = ["# Generated from ecsctx.contrib.ottu - do not edit by hand."]
    for spec in specs:
        lines.append(f"{spec.action}:")
        lines.append(f"  level: {_scalar(spec.level)}")
        lines.append(f"  terminal: {_scalar(spec.terminal)}")
        lines.append(f"  failure_level: {_scalar(spec.failure_level)}")
        lines.append(f"  kind: {_scalar(spec.kind)}")
        lines.append(f"  category: {_list(spec.category)}")
        lines.append(f"  type: {_list(spec.type)}")
        lines.append(f"  reasons: {_list(spec.reasons)}")
        lines.append(f"  required: {_list(spec.required)}")
        lines.append(f"  optional: {_list(spec.optional)}")
    return "\n".join(lines) + "\n"
