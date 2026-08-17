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
from typing import Any

from ecsctx.masking.exemptions import _get_exempt_patterns, _path_is_exempt
from ecsctx.masking.fields_rules import get_field_rule
from ecsctx.masking.patterns import check_if_sensitive_keyword, mask_by_all_patterns
from ecsctx.masking.tokens import already_masked, mask_by_field_type

_IS_MASKED_ = "_IS_MASKED_"


def mark_object_as_masked(obj: Any) -> None:
    setattr(obj, _IS_MASKED_, True)


def is_masked_object(obj: Any) -> bool:
    return bool(getattr(obj, _IS_MASKED_, False))

# service/project/log are ecsctx's own injected metadata, not user payload —
# service/project come from SERVICE_TYPE/PROJECT_NAME env vars; log.origin.
# file.name (a source-code path) is reshaped in by callsite_ecs_fields. All
# three contain a literal "name" key that would otherwise be mistaken for a
# PII name, so every filter skips them at the top level by default.
STRUCTURAL_ECS_KEYS = frozenset({"service", "project", "log"})


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

    def __init__(self, *, skip_keys: "list[str] | frozenset[str]" = STRUCTURAL_ECS_KEYS) -> None:
        super().__init__()
        self._skip_keys = frozenset(skip_keys)

    def _mask_string(self, text: str) -> str:
        if not already_masked(text):
            text = mask_by_all_patterns(text)
        return text

    def _mask_dict(self, data: dict, path: tuple = ()) -> dict:
        exempt = _get_exempt_patterns()
        result = {}
        for key, value in data.items():
            if path == () and key in self._skip_keys:
                result[key] = value
                continue
            lookup_key = str(key)
            child_path = path + (lookup_key,)
            field_type = check_if_sensitive_keyword(lookup_key)
            if field_type is None:
                result[key] = self._mask_value(value, child_path)
                continue
            field_rule = get_field_rule(field_type)
            if field_rule.exemptable and _path_is_exempt(child_path, exempt):
                result[key] = self._mask_value(value, child_path)
            else:
                result[key] = mask_by_field_type(str(value), field_type)
        return result

    def _mask_iterable(self, data: list | tuple | set, path: tuple = ()) -> list | tuple | set:
        arr_path = path + ("[*]",)
        return type(data)(self._mask_value(v, arr_path) for v in data)

    def _mask_value(self, value: Any, path: tuple = ()) -> Any:
        """Apply appropriate masking based on value type.

        Non-primitive objects are stringified before masking: their
        ``__repr__`` can embed sensitive data that would otherwise bypass
        the filter. Numbers/bools/None are left untouched at the CONTENT
        level so legitimate values (status codes, counts) are not mangled by
        the CVV/card patterns — a key-based match still overrides this, see
        _mask_dict.
        """
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, (list, tuple, set)):
            return self._mask_iterable(value, path)
        if isinstance(value, dict):
            return self._mask_dict(value, path)
        return self._mask_string(str(value))

    def filter(self, record: logging.LogRecord) -> bool:
        if not is_masked_object(record):
            record.msg = self._mask_value(record.msg)
            record.args = self._mask_value(record.args)
            mark_object_as_masked(record)
        return True
