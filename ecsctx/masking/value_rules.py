"""Value rules: shapes of value a service masks as their label, wherever they
are logged (``ECSCTX_MASK_VALUE_RULES``).

The key rules read a value by the name it sits under. Some values are known by
their shape instead, under whatever key and in whatever text, and which shapes
those are is a service's to say: ecsctx names none. A service lists its rules
in ``ECSCTX_MASK_VALUE_RULES`` (``ecsctx.masking.config``;
``ecsctx.contrib.ottu.masking`` has Ottu's), and the engine asks them about
every mapping the key walk meets, every string that is JSON text, and every
JSON object written in free text or in a body ``redact_body`` masks. With none
configured, none of this runs.

A rule is anything with:

- ``field_type``: the type whose label a matching value becomes, as
  ``make_label`` spells it (``"sad"`` is ``[SAD-MASKED]``). A matching value is
  never hashed, and the label is masking's own output, left as it is.
- ``matches(value)``: whether a mapping is one -- a dict the key walk meets, or
  JSON text the engine parsed once to ask.
- ``hints``, optionally: literal strings a matching value's text holds at least
  one of. Text holding none is never parsed to ask; without hints every JSON
  object in text is.

``ValueRule`` is one, ready made.
"""

from __future__ import annotations

import importlib
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from ecsctx.masking.tokens import make_label


@dataclass(frozen=True)
class ValueRule:
    """A shape of value that is its label wherever it is logged."""

    field_type: str
    matches: Callable[[Mapping[str, Any]], bool]
    hints: tuple[str, ...] = ()


def is_value_rule(rule: Any) -> bool:
    field_type = getattr(rule, "field_type", None)
    return isinstance(field_type, str) and bool(field_type) and callable(getattr(rule, "matches", None))


def load_value_rules(value: Iterable[Any] | str) -> tuple[tuple[Any, ...], tuple[str, ...]]:
    """(rules, problems): the rules a setting names -- rule objects, or dotted
    import paths to a rule or to a collection of them, comma-separated in one
    string as an environment variable gives them -- and what is wrong with
    each item that is not one. An item that fails leaves the others."""
    if isinstance(value, str):
        items: list[Any] = [part.strip() for part in value.split(",") if part.strip()]
    elif isinstance(value, Iterable) and not isinstance(value, (bytes, Mapping)):
        items = list(value)
    else:
        return (), (f"{value!r} is not a list of value rules or of their import paths",)
    rules: list[Any] = []
    problems: list[str] = []
    for item in items:
        try:
            rules.extend(_rules_in(item))
        except ValueError as error:
            problems.append(str(error))
    return tuple(rules), tuple(problems)


def _rules_in(item: Any) -> tuple[Any, ...]:
    found = _imported(item) if isinstance(item, str) else item
    if is_value_rule(found):
        return (found,)
    if isinstance(found, Iterable) and not isinstance(found, (str, bytes, Mapping)):
        members = tuple(found)
        if all(is_value_rule(member) for member in members):
            return members
    raise ValueError(f"{item!r} is not a value rule or a collection of them: a rule has a `field_type` and `matches(value)`")


def _imported(path: str) -> Any:
    module, _, name = path.rpartition(".")
    if not module:
        raise ValueError(f"{path!r} is not a dotted import path")
    try:
        return getattr(importlib.import_module(module), name)
    except (ImportError, AttributeError) as error:
        raise ValueError(f"{path!r} does not import: {error}") from error


def label_of(value: Any, rules: tuple) -> str | None:
    """The label of the first rule a mapping matches; None for anything else."""
    if isinstance(value, dict):
        for rule in rules:
            if rule.matches(value):
                return f"[{make_label(rule.field_type)}]"
    return None


def hinted(text: str, rules: tuple) -> bool:
    """Whether a rule could match something in ``text``: one without hints,
    or one of whose hints ``text`` holds."""
    for rule in rules:
        hints = getattr(rule, "hints", ())
        if not hints or any(hint in text for hint in hints):
            return True
    return False


def parsed_json(text: str, rules: tuple) -> Any:
    """``text`` parsed, when it is JSON text a rule could match; None
    otherwise. Cheap for every other string: most do not start with a
    bracket."""
    first = text[:1]
    if first.isspace():
        first = text.lstrip()[:1]
    if first not in ("{", "[") or not hinted(text, rules):
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def text_label(text: str, rules: tuple) -> str | None:
    """The label of a string that is JSON text of a value a rule matches."""
    return label_of(parsed_json(text, rules), rules)


_MAX_DEPTH = 64


def label_within(value: Any, rules: tuple, depth: int = 0) -> str | None:
    """The label of a value a rule matches anywhere in ``value`` -- a
    mapping, a list, or JSON text, however deep -- or None."""
    if depth > _MAX_DEPTH:
        return None
    if isinstance(value, dict):
        if (label := label_of(value, rules)) is not None:
            return label
        items = value.values()
    elif isinstance(value, (list, tuple)):
        items = value
    elif isinstance(value, str):
        found = parsed_json(value, rules)
        return None if found is None else label_within(found, rules, depth + 1)
    else:
        return None
    for item in items:
        if (label := label_within(item, rules, depth + 1)) is not None:
            return label
    return None
