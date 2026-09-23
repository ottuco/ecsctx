"""MaskPIIFilter — the single masking engine.

A stdlib logging.Filter, so it runs on every LogRecord reaching a handler it
is attached to, regardless of which library produced the record — structlog,
plain stdlib logging, or a third-party library. This is strictly more
coverage than a structlog processor alone can get: a processor only sees
structlog-originated events, and never sees positional %-style args
(log.info("user %s", email) puts the email in record.args, which only a
filter can reach before it gets interpolated into the message text).

Ported from ottu_pg's MaskPIIFilter, merged with ecsctx's PII key-name rules
and unified onto ecsctx's tokenization so every masked value carries a
token (`ptok:v1:…`) or, where none can be made, a `[LABEL]` — never a bare `***` — and so the same
underlying value (found by a key-name match or by a content regex) always
produces the same token.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import re
from collections.abc import Iterable
from numbers import Number
from typing import Any, NamedTuple

from ecsctx.masking.config import _normalise, get_masking_packs, get_masking_safe_keys
from ecsctx.masking.exemptions import (
    _get_exempt_patterns,
    _path_is_exempt,
)
from ecsctx.masking.fields_rules import get_field_rule
from ecsctx.masking.patterns import (
    _KEY_SEPARATORS,
    _MIN_PAN_DIGITS,
    _SAFE_KEYS_JOINED,
    ALL_PACKS,
    SAFE_KEYS,
    _joined_names,
    classify_key,
    name_context,
    known_clean,
    mask_by_patterns,
    mask_card_value,
    pan_shaped,
    rules_for,
    scalar_rules,
)
from ecsctx.masking.tokens import make_label, mask_by_field_type

_IS_MASKED_ = "_IS_MASKED_"


def mark_object_as_masked(obj: Any, packs: frozenset[str] = ALL_PACKS) -> None:
    """Record which packs masked ``obj``, so a filter with more packs (a PCI
    handler after a default one) still masks it."""
    done = getattr(obj, _IS_MASKED_, None)
    setattr(obj, _IS_MASKED_, packs | done if isinstance(done, frozenset) else packs)


def is_masked_object(obj: Any, packs: frozenset[str] = frozenset()) -> bool:
    done = getattr(obj, _IS_MASKED_, None)
    return isinstance(done, frozenset) and packs <= done

# service/project/log are ecsctx's own injected metadata, not user payload —
# service/project come from SERVICE_TYPE/PROJECT_NAME env vars; log.origin.
# file.name (a source-code path) is reshaped in by callsite_ecs_fields. All
# three contain a literal "name" key that would otherwise be mistaken for a
# PII name, so every filter skips them at the top level by default.
STRUCTURAL_ECS_KEYS = frozenset({"service", "project", "log"})

# Never scanned: ecsctx's own metadata, and the correlation ids services
# generate themselves — their whole purpose is to be joined on, and a masked
# session_id or trace.id breaks every query that follows a payment across
# services. exc_info/stack_info are the live exception and stack that
# error_ecs_fields and Sentry's processor turn into error.* — masked as text,
# they are strings neither can use; the rendered error.* is masked instead.
DEFAULT_SKIP_KEYS = STRUCTURAL_ECS_KEYS | frozenset(
    {"session_id", "trace", "span", "exc_info", "stack_info"}
)

# The longest string parsed as JSON for key masking. Every string of every
# record reaches that check, so a larger one gets the content rules only, as
# every string did before.
JSON_PARSE_LIMIT = 64 * 1024

# The path segment a whole-message JSON string is masked under.
_JSON_TEXT = "<json>"


def _json_container(text: str, rules: tuple) -> dict | list | None:
    """``text`` parsed, when it is a JSON object or list within the limit that
    no earlier pass with ``rules`` has already masked."""
    stripped = text.lstrip()
    if not stripped or stripped[0] not in "{[" or len(text) > JSON_PARSE_LIMIT:
        return None
    if known_clean(text, rules):
        return None  # the formatter's second pass: the filter masked it already
    try:
        parsed = json.loads(text)
    except (ValueError, RecursionError):  # RecursionError: nesting deeper than the parser allows
        return None
    return parsed if isinstance(parsed, (dict, list)) else None


# Keys whose name must not mask them, though their content is still scanned:
# user.name is a login, which audit trails need, but where the login is an
# email address the email rule still masks it.
_NAME_RULE_EXEMPT = frozenset({("user", "name")})


class _Pass(NamedTuple):
    """What one masking pass needs, resolved once per record, not per dict."""

    packs: frozenset[str]
    rules: tuple
    exempt: tuple
    safe: frozenset[str]  # the service's own safe keys (ECSCTX_MASK_SAFE_KEYS)


# Walked though not exemptable: a card object, and a credential, CVV or SAD key
# holding a container -- which cannot be the value itself. Flattened, the saved
# card ottu_pg sends under `token` became one hash, and MPGS's CVV *verdict*
# object became [CVV-MASKED].
_WALKED_TYPES = frozenset({"card", "cvv", "sad", "secret"})
# Under these nothing is weaker than the container: a CVV must not leave as a
# name token or under a core safe key such as `id`.
_FLOOR_TYPES = frozenset({"cvv", "sad"})
_CONTAINERS = (dict, list, tuple, set)
_CARD_NUMBER_KEYS = frozenset({"number", "pan", "cardnumber", "maskednumber", "maskedpan"})


# A `{name, value}` pair -- Connect's `order_description`, a HAR header list --
# names its value in a sibling, where the per-key rules never look: they
# tokenized the field id under `name` and shipped the customer's name under
# `value`. The identifier keys, in the order they are consulted.
_PAIR_IDENTIFIERS = (
    "key", "field", "field_name", "fieldname", "name", "label", "label_en", "title",
    "verbose_name", "verbose_name_en", "param", "parameter", "attribute", "header",
)
# An identifier looks like a field label, not free text: bounded, few words.
_IDENTIFIER_SHAPE = re.compile(r"[A-Za-z][A-Za-z0-9 _.\-/]{0,63}")
_IDENTIFIER_MAX_WORDS = 5
# When identifiers disagree the strictest wins: "customer_code" says generic,
# a label saying "CVV" must still mean a CVV, never a keyed hash of one.
_STRICTNESS = (
    "sad", "cvv", "card", "secret", "pem_key", "jwt", "iban", "ssn", "payment_id",
    "email", "phone", "address", "name", "generic",
)
# A `name` identifier with spaces reads through only when every word is a field
# word -- "Customer name", "Card Number" -- because "Eric Holder" and "Pan Wei"
# classify too, and they are people.
_FIELD_WORDS = frozenset({
    "card", "number", "no", "holder", "cardholder", "name", "on", "security", "code", "cvv", "cvc",
    "expiry", "expiration", "date", "month", "year", "email", "mail", "phone", "mobile", "tel",
    "telephone", "address", "line", "street", "city", "zip", "postal", "postcode", "customer", "first",
    "last", "middle", "full", "given", "family", "billing", "shipping", "contact", "pin", "account",
    "iban", "api", "key", "token", "secret", "password", "user", "username", "id", "national",
    "civil", "passport", "social", "tax", "payer", "beneficiary", "recipient", "sender", "of", "the",
})
# A `name` that classifies as nothing reads through only as a field id.
_SNAKE_CASE_ID = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)+")


def _strictness(field_type: str) -> int:
    return _STRICTNESS.index(field_type) if field_type in _STRICTNESS else len(_STRICTNESS)


def _pair(data: dict, ctx: _Pass, inherited: str | None) -> tuple[str | None, frozenset]:
    """For a `{..., "value": …}` dict: the type its value takes from its
    identifier siblings (None if none classifies), and which identifier keys
    are field labels that read through."""
    if not any(str(key).lower() == "value" for key in data):
        return None, frozenset()
    keys = {str(key).lower(): key for key in data}
    types = []
    readable = set()
    for identifier in _PAIR_IDENTIFIERS:
        original = keys.get(identifier)
        if original is None:
            continue
        text = data[original]
        if not (
            isinstance(text, str)
            and _IDENTIFIER_SHAPE.fullmatch(text)
            and len(text.split()) <= _IDENTIFIER_MAX_WORDS
        ):
            continue
        # Uncached: identifier text is data, and some of it is people's names.
        field_type = classify_key.__wrapped__(text, ctx.packs, ctx.safe)
        if field_type is None:
            if identifier == "name" and _SNAKE_CASE_ID.fullmatch(text):
                readable.add(original)
            continue
        types.append(field_type)
        words = [word.lower() for word in re.split(r"[\s_.\-/]+", text) if word]
        if identifier != "name" or len(words) == 1 or all(word in _FIELD_WORDS for word in words):
            readable.add(original)
    if not types:
        return None, frozenset(readable)
    if inherited is not None:
        types.append(inherited)
    return min(types, key=_strictness), frozenset(readable)


# Deeper than any payload Ottu logs, shallow enough that a cycle or a crafted
# body (600 levels of JSON is 3.6 KB) stops long before Python's recursion limit.
_MAX_DEPTH = 64
# What a record becomes when masking itself fails: never the unmasked text.
MASKING_FAILED = "[MASKING-FAILED: {}]"


def _is_record(value: Any) -> bool:
    """A namedtuple, or a dataclass instance with a generated repr -- an object
    whose fields have names the key rules can judge. Without a generated repr
    the object's text never showed its fields, and still does not."""
    if isinstance(value, tuple):
        return hasattr(type(value), "_fields") and hasattr(value, "_asdict")
    return (
        dataclasses.is_dataclass(value)
        and not isinstance(value, type)
        and value.__dataclass_params__.repr
    )


def _is_card_object(data: dict) -> bool:
    """A mapping shaped like a card: a card number and an expiry.

    ottu_pg's webhook sends the saved card under `token`. It is a card object
    that happens to sit under a credential key, and is walked as one -- its
    masked number, brand and expiry read, its own `token` is still a secret.
    """
    joined = {_KEY_SEPARATORS.sub("", str(key).lower()) for key in data}
    return bool(joined & _CARD_NUMBER_KEYS) and any(key.startswith("exp") for key in joined)


def _listed(key: str, safe: frozenset[str]) -> bool:
    """Listed by the service (either spelling), as opposed to a core safe key."""
    lowered = key.lower()
    return lowered in safe or _KEY_SEPARATORS.sub("", lowered) in _joined_names(safe)


def _mask_pii_leaf(text: str, field_type: str, ctx: _Pass) -> str:
    """One PII leaf, except that cardholder data outranks the key it arrived
    under.

    Customers mistype the card number into the name box, and the key used to
    win: the PAN was tokenized as a name. With a keyset configured that put a
    keyed hash of a PAN in the record while the same PAN elsewhere in it was a
    truncation -- the combination PCI DSS FAQ 1117 warns about, and the one
    `mask_card_value` refuses by never tokenizing. The card path honoured that
    rule; every other path ignored it, so a key ecsctx recognised as PII came
    off worse than one it did not recognise at all.

    Only the tokenize path is diverted: a type that is never tokenized (`cvv`)
    already renders safely and keeps its label. Gated on `pci` because "does
    this value look like a PAN" is a content-shaped test, like every other card
    rule -- a service that never opted in keeps tokenizing a long id in a name
    field, as it does today.

    A credential is the exception: shaped like a PAN it is masked whole, in
    every pack. Truncation shows ten digits of it -- the saved card's
    sixteen-digit gateway token, a numeric api key -- and a hash of something
    that may be a PAN is what FAQ 1117 forbids.
    """
    if field_type == "secret" and pan_shaped(text):
        return f"[{make_label('secret')}]"
    if (
        "pci" in ctx.packs
        and get_field_rule(field_type).tokenizable
        and pan_shaped(text)
    ):
        return mask_card_value(text)
    return mask_by_field_type(text, field_type)


def _mask_card_list_element(value: Any) -> Any:
    """A bare value in a list under a card key -- `card=(pan, month, cvv)`.

    A dict leaf under a card object is judged by its own key; a list element
    has none, so there is no telling a CVV or a holder's name from a brand.
    What carries enough digits to be a PAN keeps the truncation PCI DSS allows;
    anything else stays masked whole.
    """
    if value == "":
        return value
    text = str(value)
    if sum(character.isdigit() for character in text) >= _MIN_PAN_DIGITS:
        return mask_card_value(value)
    return f"[{make_label('card')}]"


class MaskPIIFilter(logging.Filter):
    """Masks PII and PCI-sensitive data in log records before they reach a handler.

    Handles both string and dict messages, recursively masking sensitive
    data in all string/dict/list values. Safe to attach to many handlers —
    once a record is masked, it is marked so later handlers skip re-masking.

    skip_keys: top-level dict keys to pass through completely untouched (not
    even content-scanned). This filter runs at the handler level, which for
    a structlog-originated record is *before* the formatter reshapes the
    event — so it sees ecsctx's own injected metadata (e.g. `service`,
    `project`, both containing a literal `name` child key) as plain
    top-level keys, not yet nested/exempted. Defaults to STRUCTURAL_ECS_KEYS;
    pass skip_keys=() for a fully generic filter with nothing skipped.
    """

    def __init__(
        self,
        *,
        skip_keys: "list[str] | frozenset[str]" = DEFAULT_SKIP_KEYS,
        name_rule_exempt: Iterable[tuple[str, ...]] = _NAME_RULE_EXEMPT,
        packs: Iterable[str] | None = None,
    ) -> None:
        super().__init__()
        self._skip_keys = frozenset(skip_keys)
        # Both defaults describe a log record. Masking anything else — a
        # gateway body — passes skip_keys=() and name_rule_exempt=().
        self._name_rule_exempt = frozenset(name_rule_exempt)
        # None follows ecsctx.masking.config at mask time, so a filter built by
        # dictConfig before settings are loaded still honours them.
        self._packs = None if packs is None else _normalise(packs)

    def _packs_in_force(self) -> frozenset[str]:
        return self._packs if self._packs is not None else get_masking_packs()

    def _context(self) -> _Pass:
        packs = self._packs_in_force()
        return _Pass(packs, rules_for(packs), _get_exempt_patterns(), get_masking_safe_keys())

    def _mask_string(self, text: str, ctx: _Pass | None = None, *, scalar: bool = False) -> str:
        # No already_masked() early-exit here: that helper is a whole-string
        # substring check, so a coincidental "-MASKED]"/"-MASKED:" fragment
        # (e.g. user-controlled text) would suppress content-regex masking
        # for real PII elsewhere in the same string. A second regex pass
        # over already-masked markers is a noop (pinned by test), and
        # leaf-level idempotency still lives in mask_by_field_type.
        ctx = ctx or self._context()
        if not ctx.rules:
            return text  # a key-only walk: see _mask_json_text
        # A whole field value is judged by its key, not by its shape: the
        # keyless rules would turn a PSP response code into a CVV and an epoch
        # timestamp into a PAN. Prose has no key, so it keeps every rule.
        rules = scalar_rules(ctx.rules) if scalar else ctx.rules
        return mask_by_patterns(text, rules)

    def _mask_dict(
        self, data: dict, path: tuple = (), ctx: _Pass | None = None, inherited: str | None = None
    ) -> dict:
        """Mask a dict. ``inherited`` is the field type of the PII container this
        dict sits in (a ``customer``, a ``billing`` address): a key of its own
        type wins, a safe key keeps its value, and any other key is masked as
        the container's type."""
        ctx = ctx or self._context()
        if inherited == "secret" and _is_card_object(data):
            inherited = "card"
        # The key this dict sits under, for a bare `name` (list and JSON-text
        # markers are not keys).
        container = next((step for step in reversed(path) if step not in ("[*]", _JSON_TEXT)), None)
        # Under a CVV or SAD container the floor already masks every leaf.
        pair_type, pair_labels = (None, frozenset()) if inherited in _FLOOR_TYPES else _pair(data, ctx, inherited)
        result = {}
        for key, value in data.items():
            if path == () and key in self._skip_keys:
                result[key] = value
                continue
            if isinstance(value, bool):
                # One bit: never PII, SAD or a credential, whatever its key or
                # container. Masking it only destroyed the flag.
                result[key] = value
                continue
            lookup_key = str(key)
            child_path = path + (lookup_key,)
            if key in pair_labels:
                # A field label, not a person: judged by content alone.
                result[key] = self._mask_value(value, child_path, ctx)
                continue
            field_type = classify_key(lookup_key, ctx.packs, ctx.safe)
            lowered = lookup_key.lower()
            joined = _KEY_SEPARATORS.sub("", lowered)
            if pair_type is not None and lowered == "value":
                field_type = pair_type
            elif field_type == "name" and joined in ("name", "names") and container is not None:
                context = name_context(container)
                if context == "thing" or (context == "definition" and isinstance(value, _CONTAINERS)):
                    field_type = None
            if inherited in _FLOOR_TYPES and field_type != "sad":
                # Only a key the service listed -- a list never_safe() vets --
                # reads through; anything else is the container's type, however
                # it classifies on its own.
                if field_type is None and _listed(lookup_key, ctx.safe):
                    result[key] = self._mask_value(value, child_path, ctx)
                    continue
                field_type = inherited
            elif field_type is None:
                # Both spellings, as classify_key has: `customerId` escapes a
                # customer container as `customer_id` always did.
                if (
                    inherited is None
                    or lowered in SAFE_KEYS
                    or lowered in ctx.safe
                    or joined in _SAFE_KEYS_JOINED
                    or joined in _joined_names(ctx.safe)
                ):
                    result[key] = self._mask_value(value, child_path, ctx)
                    continue
                if value is None:
                    # An empty field of a container carries nothing to mask.
                    result[key] = None
                    continue
                field_type = inherited
            elif (
                inherited == "secret"
                and field_type == "card"
                and not isinstance(value, _CONTAINERS)
                and not pan_shaped(str(value))
            ):
                # `{"token": {"card": "tok_live_…"}}`: not a PAN, so the card
                # rule would show it; under a credential it is the credential.
                field_type = "secret"
            if value is None:
                # A null holds nothing to mask; a marker would read as a value.
                result[key] = None
                continue
            field_rule = get_field_rule(field_type)
            if (
                field_rule.exemptable
                and inherited not in _WALKED_TYPES
                and (child_path in self._name_rule_exempt or _path_is_exempt(child_path, ctx.exempt))
            ):
                # Never below a card, credential, CVV or SAD container: a broad
                # exempt prefix must not expose `…token.name_on_card`.
                result[key] = self._mask_value(value, child_path, ctx)
            elif field_type == "card" and not isinstance(value, _CONTAINERS):
                result[key] = mask_card_value(value)
            elif (field_rule.exemptable or field_type in _WALKED_TYPES) and isinstance(
                value, _CONTAINERS
            ):
                # A PII container keeps its shape: each field is masked on its
                # own, so the same email or phone yields the same token across
                # records — what fraud correlation joins on — and an id stays
                # readable.
                #
                # A card object is walked too, though `card` is not exemptable:
                # collapsing it threw away the PAN's truncation — the one form
                # PCI DSS 3.5.1 lets us keep — along with expiry and scheme,
                # which it never asked us to hide. So is a credential, CVV or
                # SAD key holding a container: it cannot hold the value itself,
                # and its unnamed leaves still take its type. These are spelled
                # out rather than made exemptable because `exemptable` also
                # governs ECSCTX_MASK_EXEMPT_PATHS (above), and none of them may
                # ever be whitelistable.
                result[key] = self._mask_value(value, child_path, ctx, inherited=field_type)
            else:
                result[key] = _mask_pii_leaf(str(value), field_type, ctx)
        return result

    def _mask_iterable(
        self,
        data: list | tuple | set,
        path: tuple = (),
        ctx: _Pass | None = None,
        inherited: str | None = None,
    ) -> list | tuple | set:
        ctx = ctx or self._context()
        arr_path = path + ("[*]",)
        items = [self._mask_value(v, arr_path, ctx, inherited=inherited) for v in data]
        try:
            return type(data)(items)
        except TypeError:
            # A tuple subclass that cannot be rebuilt from one iterable -- a
            # struct sequence such as sys.version_info. Its shape is lost, not
            # the log line.
            return tuple(items) if isinstance(data, tuple) else items

    def _mask_value(
        self, value: Any, path: tuple = (), ctx: _Pass | None = None, inherited: str | None = None
    ) -> Any:
        """Apply appropriate masking based on value type.

        Non-primitive objects are scanned through their text: their
        ``__repr__`` can embed sensitive data that would otherwise bypass
        the filter. Numbers/bools/None are left untouched at the CONTENT
        level so legitimate values (status codes, counts) are not mangled by
        the CVV/card patterns — a key-based match still overrides this, see
        _mask_dict. Inside a PII container (``inherited``) a bare value in a
        list is masked as the container's type.
        """
        if value is None:
            return value
        if len(path) > _MAX_DEPTH:
            # A cycle, or nesting nothing legitimate reaches (a crafted body):
            # stop here rather than recurse into the caller's RecursionError.
            return f"[{make_label('depth')}]"
        ctx = ctx or self._context()
        if _is_record(value):
            # Before the tuple check: a namedtuple is a tuple.
            if inherited == "card":
                return _mask_card_list_element(value)
            if inherited is not None:
                return _mask_pii_leaf(str(value), inherited, ctx)
            return self._mask_record(value, path, ctx)
        if isinstance(value, (list, tuple, set)):
            return self._mask_iterable(value, path, ctx, inherited)
        if isinstance(value, dict):
            return self._mask_dict(value, path, ctx, inherited)
        if isinstance(value, bool):
            return value
        if inherited == "card":
            return _mask_card_list_element(value)
        if inherited is not None:
            return _mask_pii_leaf(str(value), inherited, ctx)
        if isinstance(value, (bool, int, float)):
            return value  # see scalar= below: the same reasoning, for strings
        if isinstance(value, str):
            if (parsed := _json_container(value, ctx.rules)) is not None:
                return self._mask_json_text(value, parsed, path, ctx)
            # path == () is the record's own message — prose. Anything deeper
            # is a field value, and its key has already had its say.
            return self._mask_string(value, ctx, scalar=path != ())
        # Any other object — a Decimal included — is replaced by its masked
        # text: a JSON renderer falls back to repr() ("Decimal('100.000')"),
        # and that can hold what str() hides. Positional args are the
        # exception, see _mask_arg.
        return self._mask_string(str(value), ctx)

    def _mask_record(self, value: Any, path: tuple, ctx: _Pass) -> str:
        """A dataclass or namedtuple, masked field by field under its own
        field names, then rendered back to the ``Name(field=...)`` text its
        repr would have given -- still a string, so an index that mapped the
        field as text keeps accepting it. Only the fields its repr shows:
        ``field(repr=False)`` stays out, as it did."""
        if isinstance(value, tuple):
            name, fields = type(value).__name__, value._asdict()
        else:
            name = type(value).__qualname__
            fields = {f.name: getattr(value, f.name, None) for f in dataclasses.fields(value) if f.repr}
        masked = self._mask_dict(dict(fields), path, ctx)
        rendered = ", ".join(f"{key}={masked[key]!r}" for key in fields)
        # The content rules still read the result, as they read any object's
        # text: a PAN in an unnamed field is truncated here.
        return self._mask_string(f"{name}({rendered})", ctx)

    def _mask_json_text(self, text: str, parsed: dict | list, path: tuple, ctx: _Pass) -> str:
        """A JSON object or list logged as text — a PSP callback's raw body —
        masked by its keys, as the same data logged as a dict would be.

        Re-serialised only when a key rule changed something, so text with
        nothing to mask by key keeps its layout. The content rules then run on
        the result as they ran on the text before: a card number written as a
        JSON number is a number to the key pass, and only they catch it.
        """
        # Never at path (): the record's skip keys (log, service, session_id)
        # describe the record, not a payload that happens to use the names.
        # Key rules only: the content rules run once, on the whole text below,
        # not once per value and again on the text.
        masked = self._mask_value(parsed, path or (_JSON_TEXT,), ctx._replace(rules=()))
        if masked == parsed:
            return self._mask_string(text, ctx)
        return self._mask_string(json.dumps(masked, ensure_ascii=False, default=str), ctx)

    def _mask_args(self, args: Any, ctx: _Pass) -> Any:
        if isinstance(args, tuple):
            return tuple(self._mask_arg(arg, ctx) for arg in args)
        if isinstance(args, dict):
            # "%(amount).3f": key rules still apply, numbers stay numbers.
            masked = self._mask_dict(args, (), ctx)
            return {
                key: args[key] if isinstance(args[key], Number) and masked[key] == str(args[key]) else masked[key]
                for key in masked
            }
        return self._mask_value(args, (), ctx)

    def _mask_arg(self, value: Any, ctx: _Pass) -> Any:
        """A %-format argument: a number whose text holds nothing to mask stays
        a number, so "%d"/"%f" still format — a Decimal turned into a string
        makes logging drop the whole line."""
        if isinstance(value, Number) and not isinstance(value, bool):
            text = str(value)
            masked = self._mask_string(text, ctx)
            return value if masked == text else masked
        return self._mask_value(value, (), ctx)

    def filter(self, record: logging.LogRecord) -> bool:
        ctx = self._context()
        if not is_masked_object(record, ctx.packs):
            try:
                record.msg = self._mask_value(record.msg, (), ctx)
                record.args = self._mask_args(record.args, ctx)
            except Exception as error:  # noqa: BLE001 -- nothing here may reach the caller
                # This runs outside emit()'s handleError, so an exception here
                # became the caller's: a failed log line failed the payment.
                # The message is replaced whole -- the one outcome that cannot
                # leak what masking failed to mask.
                record.msg = MASKING_FAILED.format(type(error).__name__)
                record.args = ()
            mark_object_as_masked(record, ctx.packs)
        return True
