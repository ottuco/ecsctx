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
`[LABEL]` or `[LABEL:token]` marker — never a bare `***` — and so the same
underlying value (found by a key-name match or by a content regex) always
produces the same token.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from numbers import Number
from typing import Any, NamedTuple

from ecsctx.masking.config import _normalise, get_masking_packs
from ecsctx.masking.exemptions import (
    _get_exempt_patterns,
    _path_is_exempt,
)
from ecsctx.masking.fields_rules import get_field_rule
from ecsctx.masking.patterns import (
    ALL_PACKS,
    classify_key,
    mask_by_patterns,
    mask_card_value,
    rules_for,
)
from ecsctx.masking.tokens import mask_by_field_type

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
# services.
DEFAULT_SKIP_KEYS = STRUCTURAL_ECS_KEYS | frozenset({"session_id", "trace", "span"})

# Keys whose name must not mask them, though their content is still scanned:
# user.name is a login, which audit trails need, but where the login is an
# email address the email rule still masks it.
_NAME_RULE_EXEMPT = frozenset({("user", "name")})


class _Pass(NamedTuple):
    """What one masking pass needs, resolved once per record, not per dict."""

    packs: frozenset[str]
    rules: tuple
    exempt: tuple


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
        return _Pass(packs, rules_for(packs), _get_exempt_patterns())

    def _mask_string(self, text: str, ctx: _Pass | None = None) -> str:
        # No already_masked() early-exit here: that helper is a whole-string
        # substring check, so a coincidental "-MASKED]"/"-MASKED:" fragment
        # (e.g. user-controlled text) would suppress content-regex masking
        # for real PII elsewhere in the same string. A second regex pass
        # over already-masked markers is a noop (pinned by test), and
        # leaf-level idempotency still lives in mask_by_field_type.
        ctx = ctx or self._context()
        return mask_by_patterns(text, ctx.rules)

    def _mask_dict(self, data: dict, path: tuple = (), ctx: _Pass | None = None) -> dict:
        ctx = ctx or self._context()
        result = {}
        for key, value in data.items():
            if path == () and key in self._skip_keys:
                result[key] = value
                continue
            lookup_key = str(key)
            child_path = path + (lookup_key,)
            field_type = classify_key(lookup_key, ctx.packs)
            if field_type is None:
                result[key] = self._mask_value(value, child_path, ctx)
                continue
            field_rule = get_field_rule(field_type)
            if field_rule.exemptable and (
                child_path in self._name_rule_exempt or _path_is_exempt(child_path, ctx.exempt)
            ):
                result[key] = self._mask_value(value, child_path, ctx)
            elif field_type == "card":
                result[key] = mask_card_value(value)
            else:
                result[key] = mask_by_field_type(str(value), field_type)
        return result

    def _mask_iterable(
        self, data: list | tuple | set, path: tuple = (), ctx: _Pass | None = None
    ) -> list | tuple | set:
        ctx = ctx or self._context()
        arr_path = path + ("[*]",)
        return type(data)(self._mask_value(v, arr_path, ctx) for v in data)

    def _mask_value(self, value: Any, path: tuple = (), ctx: _Pass | None = None) -> Any:
        """Apply appropriate masking based on value type.

        Non-primitive objects are scanned through their text: their
        ``__repr__`` can embed sensitive data that would otherwise bypass
        the filter. Numbers/bools/None are left untouched at the CONTENT
        level so legitimate values (status codes, counts) are not mangled by
        the CVV/card patterns — a key-based match still overrides this, see
        _mask_dict.
        """
        if value is None or isinstance(value, (bool, int, float)):
            return value
        ctx = ctx or self._context()
        if isinstance(value, (list, tuple, set)):
            return self._mask_iterable(value, path, ctx)
        if isinstance(value, dict):
            return self._mask_dict(value, path, ctx)
        if isinstance(value, str):
            return self._mask_string(value, ctx)
        # Any other object — a Decimal included — is replaced by its masked
        # text: a JSON renderer falls back to repr() ("Decimal('100.000')"),
        # and that can hold what str() hides. Positional args are the
        # exception, see _mask_arg.
        return self._mask_string(str(value), ctx)

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
            record.msg = self._mask_value(record.msg, (), ctx)
            record.args = self._mask_args(record.args, ctx)
            mark_object_as_masked(record, ctx.packs)
        return True
