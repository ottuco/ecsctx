"""Value rules: shapes of value a service masks as their label, or ships as
sent, wherever they are logged (``ECSCTX_MASK_VALUE_RULES``).

The key rules read a value by the name it sits under. Some values are known by
their shape instead, under whatever key and in whatever text, and which shapes
those are is a service's to say: ecsctx names none. A service lists its rules
in ``ECSCTX_MASK_VALUE_RULES`` (``ecsctx.masking.config``;
``ecsctx.contrib.ottu.masking`` has Ottu's), and the engine asks them about
every mapping the key walk meets, every string that is JSON text, and every
JSON object written in free text or in a body ``redact_body`` masks. With none
configured, none of this runs.

A rule is one of two kinds, both asked in list order, the first match winning:

- A **label rule** has a ``field_type``: the type whose label a matching value
  becomes, as ``make_label`` spells it (``"sad"`` is ``[SAD-MASKED]``). A
  matching value is never hashed, and the label is masking's own output, left
  as it is. ``ValueRule`` is one, ready made.
- A **keep rule** has ``keep = True`` (the object itself, not a truthy value):
  a matching value ships exactly as sent, and the walk does not descend into
  it. ``KeepRule`` is one, ready made. Two things it cannot override: nothing
  is kept under a CVV or SAD key or inside a CVV or SAD container (the floor,
  applied where a key is known: ``filters``, ``patterns.kept_spans``), and a
  match holding a card, CVV or SAD key, or a card number, at any depth, is
  walked as if nothing matched (the guard, ``holds_card_data``).

Both have:

- ``matches(value)``: whether a mapping is one -- a dict the key walk meets, or
  JSON text the engine parsed once to ask. A label rule that raises leaves the
  ``[MASKING-FAILED: …]`` marker; a keep rule that raises counts as no match,
  since keep rules are asked on paths that must never raise (``redact_url``,
  ``redact_body``, ``mask_card_value``).
- ``hints``, optionally: literal strings a matching value's text holds at least
  one of. A rule is never asked about text holding none of its hints; without
  hints it is asked about every JSON object in text.
"""

from __future__ import annotations

import importlib
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, ClassVar, NamedTuple

from ecsctx.masking.tokens import make_label


@dataclass(frozen=True)
class ValueRule:
    """A shape of value that is its label wherever it is logged."""

    field_type: str
    matches: Callable[[Mapping[str, Any]], bool]
    hints: tuple[str, ...] = ()


@dataclass(frozen=True)
class KeepRule:
    """A shape of value that ships as sent wherever it is logged."""

    matches: Callable[[Any], bool]
    hints: tuple[str, ...] = ()
    keep: ClassVar[bool] = True


class _Keep:
    """What a value a keep rule matches is ruled: shipped as sent."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "KEEP"


KEEP = _Keep()


def is_keep_rule(rule: Any) -> bool:
    return getattr(rule, "keep", None) is True and callable(getattr(rule, "matches", None))


def is_label_rule(rule: Any) -> bool:
    field_type = getattr(rule, "field_type", None)
    return isinstance(field_type, str) and bool(field_type) and callable(getattr(rule, "matches", None))


def _hints_are_text(rule: Any) -> bool:
    """Whether a rule's ``hints``, if it has any, are a collection of strings:
    each is looked for in text as it is masked, and anything else would raise
    there -- in redact_url and redact_body too."""
    hints = getattr(rule, "hints", ())
    return isinstance(hints, (tuple, list, set, frozenset)) and all(isinstance(hint, str) for hint in hints)


def is_value_rule(rule: Any) -> bool:
    return (is_keep_rule(rule) or is_label_rule(rule)) and _hints_are_text(rule)


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
    raise ValueError(
        f"{item!r} is not a value rule or a collection of them: a rule has `matches(value)`, "
        "either a `field_type` (its label) or `keep = True` (it ships as sent), and optionally "
        "`hints`, a collection of strings"
    )


def _imported(path: str) -> Any:
    module, _, name = path.rpartition(".")
    if not module:
        raise ValueError(f"{path!r} is not a dotted import path")
    try:
        return getattr(importlib.import_module(module), name)
    except (ImportError, AttributeError) as error:
        raise ValueError(f"{path!r} does not import: {error}") from error


class _Split(NamedTuple):
    """What masking reads of a rule set, again and again: each rule with
    whether it keeps, and its keep and label rules, in their order."""

    rules: tuple
    flagged: tuple[tuple[Any, bool], ...]
    keep: tuple
    label: tuple


# Cached on the rule tuple's identity (as patterns._by_identity caches, never
# on its hash): asked about every mapping and every string masking reads.
# Bounded, and emptied, not evicted.
_SPLITS_LIMIT = 64
_splits: dict[int, _Split] = {}


def _split_of(rules: tuple) -> _Split:
    flagged = tuple((rule, is_keep_rule(rule)) for rule in rules)
    return _Split(
        rules,
        flagged,
        tuple(rule for rule, keep in flagged if keep),
        tuple(rule for rule, keep in flagged if not keep),
    )


def _split(rules: Iterable[Any]) -> _Split:
    if not isinstance(rules, tuple):
        return _split_of(tuple(rules))
    entry = _splits.get(id(rules))
    if entry is None or entry.rules is not rules:
        if len(_splits) >= _SPLITS_LIMIT:
            _splits.clear()
        # Keeping `rules` in the entry keeps its id from being reused.
        entry = _splits[id(rules)] = _split_of(rules)
    return entry


def keep_rules(rules: Iterable[Any]) -> tuple:
    """The keep rules of ``rules``, in their order."""
    return _split(rules).keep


def label_rules(rules: Iterable[Any]) -> tuple:
    """The label rules of ``rules``, in their order."""
    return _split(rules).label


def _first_match(value: Any, rules: Iterable[Any]) -> tuple[Any, bool] | None:
    """The first of ``rules`` a dict matches, with whether it keeps; None for
    no match or anything but a dict. A keep rule that raises counts as no
    match; a label rule's error reaches the caller."""
    if not isinstance(value, dict):
        return None
    for rule, keep in _split(rules).flagged:
        if keep:
            try:
                matched = bool(rule.matches(value))
            except Exception:  # noqa: BLE001 -- a service's matcher; a keep rule never raises
                matched = False
            if matched:
                return rule, True
        elif rule.matches(value):
            return rule, False
    return None


def rule_of(value: Any, rules: Iterable[Any]) -> Any:
    """The first of ``rules`` a mapping matches, or None -- None for anything
    but a dict. A keep rule that raises counts as no match; a label rule's
    error reaches the caller."""
    found = _first_match(value, rules)
    return None if found is None else found[0]


def applicable(text: str, rules: Iterable[Any]) -> tuple:
    """The rules a value written in ``text`` could match, in their order: one
    without hints, or one of whose hints ``text`` holds. ``rules`` itself when
    every one could, so what is cached on its identity is found again."""
    asked = tuple(
        rule for rule in rules if not (hints := getattr(rule, "hints", ())) or any(hint in text for hint in hints)
    )
    return rules if isinstance(rules, tuple) and len(asked) == len(rules) else asked


def hinted(text: str, rules: tuple) -> bool:
    """Whether a rule could match something in ``text``: one without hints,
    or one of whose hints ``text`` holds."""
    for rule in rules:
        hints = getattr(rule, "hints", ())
        if not hints or any(hint in text for hint in hints):
            return True
    return False


class DuplicateKey(ValueError):
    """JSON text naming a key twice in one object: json.loads keeps the last,
    and the text as written keeps both."""


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict:
    found = dict(pairs)
    if len(found) != len(pairs):
        raise DuplicateKey("a key written twice in one object")
    return found


def json_as_written(text: str) -> Any:
    """``text`` parsed as JSON, refusing a key written twice anywhere in it
    (``DuplicateKey``, a ValueError). A keep decision rests on the parse, and
    the text as written is what ships: a duplicate json.loads drops would
    carry what the guard never saw."""
    return json.loads(text, object_pairs_hook=_unique_keys)


def parses_as_written(text: str) -> bool:
    """Whether JSON text names no key twice: its parse is all it ships."""
    try:
        json_as_written(text)
    except (ValueError, RecursionError):
        return False
    return True


# Deeper than any payload a rule matches, shallow enough that a cycle or a
# crafted body stops long before Python's recursion limit.
_MAX_DEPTH = 64
# What the guard refuses to keep: a key the key rules read as one of these.
_CARD_DATA_TYPES = frozenset({"card", "cvv", "sad"})
# Epoch milliseconds, as written until 2065: thirteen digits from a 1, or from
# a 2 after 18 May 2033. Google Pay's `signedKey` carries one
# (`keyExpiration`), which `pan_shaped` reads as a card number; the one card
# number's shape the guard lets through. No card number is thirteen digits
# from a 1 or a 2.
_EPOCH_MILLISECONDS = re.compile(r"[12][0-9]{12}")


def holds_card_data(value: Any) -> bool:
    """Whether ``value`` holds, at any depth -- JSON text inside it included --
    a key the key rules read as a card, a CVV or other SAD (every pack on), a
    ``{name, value}`` pair whose identifier reads as one (as the key walk reads
    a pair, ``filters._pair``), or a leaf that is a card number as a whole:
    what no keep rule may ship, not even one that matches everything. Keys,
    pairs and whole leaves only: a CVV or a card number written inside a
    longer string (``"note": "cvv=123"``) is not read here, and keeping it out
    is a matcher's job.

    A leaf is a card number when it is an int ``int_is_pan`` reads as one, or
    a string ``pan_shaped`` reads as one -- whatever its prefix, Luhn or not --
    except thirteen bare digits from a 1 or a 2: epoch milliseconds, Google Pay's
    ``keyExpiration`` in ``signedKey``, without which no Google Pay token would
    ever be kept. Not ``holds_pan_run``, which flags hex ids.
    Anything that is no JSON value (an object whose text is not judged here),
    nesting past the depth cap, and a leaf of JSON text that names a key twice
    (``json_as_written``: what ships would not be what was read) count as
    holding card data: such a match is walked, not shipped.
    """
    # Imported here: patterns and filters import this module as they load.
    from ecsctx.masking.filters import _PAIR_IDENTIFIERS
    from ecsctx.masking.patterns import (
        ALL_PACKS,
        classify_key,
        int_is_pan,
        pan_shaped,
    )

    def labels_card_data(pair: Mapping) -> bool:
        keys = {str(key).lower(): key for key in pair}
        if "value" not in keys:
            return False
        # Uncached, as the key walk classifies free text: an identifier may be
        # a sentence, and must not evict a key name.
        return any(
            isinstance(label := pair[keys[identifier]], str)
            and classify_key.__wrapped__(label, ALL_PACKS) in _CARD_DATA_TYPES
            for identifier in _PAIR_IDENTIFIERS
            if identifier in keys
        )

    def holds(item: Any, depth: int) -> bool:
        if depth > _MAX_DEPTH:
            return True
        if isinstance(item, Mapping):
            if labels_card_data(item):
                return True
            return any(
                classify_key(str(key), ALL_PACKS) in _CARD_DATA_TYPES or holds(member, depth + 1)
                for key, member in item.items()
            )
        if isinstance(item, (list, tuple, set, frozenset)):
            return any(holds(member, depth + 1) for member in item)
        if item is None or isinstance(item, bool):
            return False
        if isinstance(item, int):
            return int_is_pan(item)
        if isinstance(item, float):
            return item.is_integer() and int_is_pan(int(item))
        if isinstance(item, str):
            if pan_shaped(item) and not _EPOCH_MILLISECONDS.fullmatch(item.strip()):
                return True
            if item.lstrip()[:1] not in ("{", "["):
                return False
            try:
                parsed = json_as_written(item)
            except (DuplicateKey, RecursionError):
                return True
            except ValueError:
                return False
            return holds(parsed, depth + 1)
        return True

    return holds(value, 0)


def ruling(value: Any, rules: Iterable[Any]) -> str | _Keep | None:
    """What the first of ``rules`` a mapping matches makes of it: its label,
    ``KEEP``, or None -- nothing matched, or a keep rule did and the guard
    refused it (``holds_card_data``), so it is walked as if nothing had."""
    found = _first_match(value, rules)
    if found is None:
        return None
    rule, keep = found
    if keep:
        return None if holds_card_data(value) else KEEP
    return f"[{make_label(rule.field_type)}]"


def _json_in(text: str) -> Any:
    """``text`` parsed, when it is JSON text; None otherwise. Cheap for every
    other string: most do not start with a bracket."""
    first = text[:1]
    if first.isspace():
        first = text.lstrip()[:1]
    if first not in ("{", "["):
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def parsed_json(text: str, rules: tuple) -> Any:
    """``text`` parsed, when it is JSON text a rule could match; None
    otherwise."""
    first = text[:1]
    if first.isspace():
        first = text.lstrip()[:1]
    if first not in ("{", "[") or not hinted(text, rules):
        return None
    return _json_in(text)


def text_ruling(text: str, rules: Iterable[Any]) -> str | _Keep | None:
    """``ruling`` for a string that is JSON text, asking only the rules whose
    hints it holds. Not ``KEEP`` for text naming a key twice: kept, it would
    ship the key json.loads dropped, which the guard never read. A label
    rule's reading is 0.16.0's."""
    asked = applicable(text, rules)
    if not asked:
        return None
    if not _split(asked).keep:
        return ruling(_json_in(text), asked)
    value, as_written = _json_as_read(text)
    found = ruling(value, asked)
    return None if found is KEEP and not as_written else found


def _json_as_read(text: str) -> tuple[Any, bool]:
    """``text`` parsed -- None where it is no JSON text -- and whether the
    parse is all the text writes: parsed once, strictly, and again as
    json.loads reads it only where a key is written twice."""
    first = text[:1]
    if first.isspace():
        first = text.lstrip()[:1]
    if first not in ("{", "["):
        return None, True
    try:
        return json_as_written(text), True
    except DuplicateKey:
        return _json_in(text), False
    except (ValueError, RecursionError):
        return None, True


def label_of(value: Any, rules: Iterable[Any]) -> str | None:
    """The label of the first rule a mapping matches; None for anything else,
    and where that rule is a keep rule."""
    found = _first_match(value, rules)
    return None if found is None or found[1] else f"[{make_label(found[0].field_type)}]"


def text_label(text: str, rules: Iterable[Any]) -> str | None:
    """The label of a string that is JSON text of a value a rule matches."""
    asked = applicable(text, rules)
    return label_of(_json_in(text), asked) if asked else None


def label_within(value: Any, rules: Iterable[Any], depth: int = 0) -> str | None:
    """The label of a value a rule matches anywhere in ``value`` -- a
    mapping, a list, or JSON text, however deep -- or None. A kept mapping is
    not descended into: what a keep rule ships holds no label."""
    if depth > _MAX_DEPTH:
        return None
    if isinstance(value, dict):
        found = _first_match(value, rules)
        if found is not None:
            if not found[1]:
                return f"[{make_label(found[0].field_type)}]"
            if not holds_card_data(value):
                return None
        items = value.values()
    elif isinstance(value, (list, tuple)):
        items = value
    elif isinstance(value, str):
        asked = applicable(value, rules)
        found = _json_in(value) if asked else None
        return None if found is None else label_within(found, asked, depth + 1)
    else:
        return None
    for item in items:
        if (label := label_within(item, rules, depth + 1)) is not None:
            return label
    return None
