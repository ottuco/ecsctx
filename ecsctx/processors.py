"""
Framework-agnostic structlog processors for ECS-compliant logging.

All configuration is passed via environment variables or processor factory parameters.
For Django integration, use ecsctx.contrib.django.processors which reads from settings.
"""

import contextlib
import os
import re
import sys
import traceback

from structlog.contextvars import get_contextvars

from ecsctx import identity
from ecsctx.contrib.net import ecs_url, parse_json_or_raw
from ecsctx.context import get_logging_context, get_trace_id
from ecsctx.masking.exemptions import (
    _reset_masking,
    configure_masking,
    configure_masking_from_env,
    masking_is_configured,
)
from ecsctx.masking.tokens import safe_tokenize
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import _truncate_pan


def _get_app_version() -> str:
    """Application version. Kept as a name other modules import."""
    return identity.get_app_version()


def _detect_service():
    """(service.name, service.version). See ecsctx.identity for the order."""
    return identity.detect_service()


# ECS-compliant root allowlist for log events.
# Keys in this set stay at root level; all non-allowlisted keys go into 'extra'.
ROOT_ALLOWLIST = frozenset({
    # ECS field-set objects (must be dicts)
    "http",  # ECS: http.request, http.response
    "url",  # ECS: url.path
    "event",  # ECS: event.kind, event.category, event.type, event.outcome
    "span",  # ECS: span.id
    "user",  # ECS: user.id
    "user_agent",  # ECS: user_agent.original
    "client",  # ECS: client.ip
    "trace",  # ECS: trace.id
    "service",  # ECS: service.name, service.version
    "error",  # ECS: error.type
    "log",  # ECS: log.level
    # Custom namespaces
    "payment",  # Custom: payment.orn, payment.pg_code, payment.reference
    "project",  # Custom: project.name
    # structlog / ECS base scalars
    "message",
    "timestamp",
    "level",
    # Sanctioned flat custom IDs
    "merchant_id",
    "session_id",
    # ECS labels (flat dict of keyword values)
    "labels",
    # Payload containers (for PII masking path)
    "payload",
    "headers",
    # Custom scalar
    "view",
    # Target namespace for non-allowlisted keys
    "extra",
    # Staging key for ECS event field — renamed to "event" in namespace_ecs_fields
    # after structlog has consumed the message (structlog uses "event" as message key)
    "ecs_event",
})

# Deprecated alias for backward compatibility
PRIMARY_KEYS = ROOT_ALLOWLIST


# --- Configurable root fields (mirrors the masking-exemption config pattern) ---
# A consuming service can promote additional keys to root (instead of `extra.*`)
# without ecsctx hardcoding its domain schema. Precedence: an explicit
# configure_root_fields() call wins, then the Django ECSCTX_ROOT_FIELDS setting
# (bridged lazily in contrib.django), then the ECSCTX_ROOT_FIELDS env var (CSV).
_custom_root_fields: frozenset | None = None
_root_fields_auto_configure_attempted: bool = False


def configure_root_fields(*, extra_fields: list[str] | None = None) -> None:
    """Extend ROOT_ALLOWLIST with service-chosen root keys (highest precedence)."""
    global _custom_root_fields, _root_fields_auto_configure_attempted
    _custom_root_fields = frozenset(f for f in (extra_fields or []) if f)
    _root_fields_auto_configure_attempted = True


def configure_root_fields_from_env() -> None:
    """Load extra root fields from the ECSCTX_ROOT_FIELDS env var (CSV). Idempotent."""
    global _custom_root_fields, _root_fields_auto_configure_attempted
    if _root_fields_auto_configure_attempted or _custom_root_fields is not None:
        return
    _root_fields_auto_configure_attempted = True
    raw = os.environ.get("ECSCTX_ROOT_FIELDS", "")
    _custom_root_fields = frozenset(p.strip() for p in raw.split(",") if p.strip())


def root_fields_are_configured() -> bool:
    """True if extra root fields have been explicitly set or env-loaded."""
    return _custom_root_fields is not None


def _get_root_allowlist() -> frozenset:
    if _custom_root_fields is None:
        configure_root_fields_from_env()
    return ROOT_ALLOWLIST | (_custom_root_fields or frozenset())


def _reset_root_fields() -> None:
    """Reset root-fields config. For testing only."""
    global _custom_root_fields, _root_fields_auto_configure_attempted
    _custom_root_fields = None
    _root_fields_auto_configure_attempted = False


# "exception" is the rendered-traceback string an upstream ExceptionRenderer may
# have produced; StructlogFormatter maps it to error.stack_trace. It must not be
# swept into extra. Raw exc_info never reaches the reshape: error_ecs_fields
# consumes it into the error object first.
_EXCEPTION_PASSTHROUGH_KEYS = frozenset({"exception"})


def reshape_log_event(event_dict) -> dict:
    """Reshape log event: allowlisted keys stay at root, everything else goes into extra.

    - Keys in ROOT_ALLOWLIST (plus any configure_root_fields() additions)
      always stay at root.
    - Non-allowlisted keys (scalars, lists, and dicts) are wrapped into
      ``extra``.
    """
    if not isinstance(event_dict, dict):
        return event_dict

    allowlist = _get_root_allowlist()
    reshaped = {}
    extra = {}

    for key, value in event_dict.items():
        if (
            key in allowlist
            or key in _EXCEPTION_PASSTHROUGH_KEYS
            or key.startswith("_")
            or key.startswith("event.")
        ):
            reshaped[key] = value
        else:
            extra[key] = value

    if extra:
        existing_extra = reshaped.get("extra", {})
        if isinstance(existing_extra, dict):
            existing_extra.update(extra)
            reshaped["extra"] = existing_extra
        else:
            reshaped["extra"] = extra

    return reshaped


def _inject_logging_context(event_dict: dict) -> dict:
    """
    Inject values from LoggingContext into event_dict.

    Only injects values that are not already present in event_dict.
    This allows explicit log parameters to override context values.
    """
    with contextlib.suppress(Exception):
        ctx = get_logging_context()
        ctx_dict = ctx.to_dict()

        # Inject context values only if not already present
        for key, value in ctx_dict.items():
            if key not in event_dict and value is not None:
                event_dict[key] = value

    return event_dict


def error_ecs_fields(_logger, _method_name, event_dict):
    """
    Consume a pending ``exc_info`` into the ECS ``error`` object:
    ``error.type``, ``error.message`` and ``error.stack_trace``.

    ``exc_info`` is POPPED — the raw ``(type, exc, traceback)`` tuple must
    never reach a formatter (unrendered it JSON-dumps as a repr string, or
    crashes serialization). Rendering here instead of relying on a downstream
    ``ExceptionRenderer`` keeps custom pipelines safe: any chain that includes
    this processor gets full ECS error fields with no ordering trap. A chain
    that ALSO runs ExceptionRenderer afterwards is fine — it no-ops once
    ``exc_info`` is gone.

    An explicit caller ``error={...}`` (the connect logging-rules shape) wins —
    values are only setdefault'ed, and the caller's dict is copied, never
    mutated in place (callers may reuse a shared dict across log calls).
    """
    ei = event_dict.get("exc_info")
    exc = None
    if isinstance(ei, BaseException):
        exc = ei
    elif isinstance(ei, tuple) and len(ei) == 3 and isinstance(ei[1], BaseException):
        exc = ei[1]
    elif ei is True:
        exc = sys.exc_info()[1]
    if exc is None:
        return event_dict

    event_dict.pop("exc_info", None)
    error = event_dict.get("error")
    error = dict(error) if isinstance(error, dict) else {}
    error.setdefault("type", type(exc).__name__)
    error.setdefault("message", str(exc))
    if "stack_trace" not in error:
        with contextlib.suppress(Exception):
            error["stack_trace"] = "".join(
                traceback.format_exception(type(exc), exc, exc.__traceback__)
            ).rstrip("\n")
    event_dict["error"] = error
    return event_dict


def callsite_ecs_fields(_logger, _method_name, event_dict):
    """
    Map structlog attribution keys into the ECS ``log`` container.

    ``add_logger_name`` and ``CallsiteParameterAdder`` emit flat ``logger``,
    ``func_name``, ``pathname`` and ``lineno`` keys. Left flat, they are not
    ECS and ``namespace_ecs_fields`` would bury them in ``extra.*`` (four
    dynamically-mapped fields). Reshape them to ``log.logger`` and
    ``log.origin.{function,file.name,file.line}`` — the fields the o11y
    ``common-logs`` pipeline was built around in the logstash era.

    An explicit caller-provided ``log.origin`` (e.g. ``@log_io`` records the
    decoration site) wins over the frame-derived one: the wrapper's frame is
    noise compared to the decorated method's location.
    """
    name = event_dict.pop("logger", None)
    func = event_dict.pop("func_name", None)
    path = event_dict.pop("pathname", None)
    line = event_dict.pop("lineno", None)

    log = event_dict.get("log")
    if not isinstance(log, dict):
        log = {}

    if name is not None and "logger" not in log:
        log["logger"] = name

    if "origin" not in log:
        origin = {}
        if func is not None:
            origin["function"] = func
        file_part = {}
        if path is not None:
            file_part["name"] = path
        if line is not None:
            file_part["line"] = line
        if file_part:
            origin["file"] = file_part
        if origin:
            log["origin"] = origin

    if log:
        event_dict["log"] = log
    return event_dict


def namespace_ecs_fields(_logger, _method_name, event_dict):
    """
    Handle ECS field normalization and reshaping.

    1. Removes flat 'level' key since StructlogFormatter sets log.level from
       method name.
    2. Reshapes event: allowlisted keys stay at root, everything else into
       'extra'.
    3. Renames 'ecs_event' staging key to 'event' (avoids structlog's 'event'
       message key).

    Note: ecs.version is handled by ECSFormatter - setting it here doesn't work
    because ecs-logging's normalize_dict converts dotted keys to nested objects,
    then format_to_ecs adds a new flat key via setdefault.
    """
    # Remove flat 'level' key added by add_log_level processor
    # StructlogFormatter will set log.level correctly using the method name
    # This prevents duplication: log.level: ["info", "info"]
    event_dict.pop("level", None)

    # Reshape: move non-allowlisted keys into extra
    event_dict = reshape_log_event(event_dict)

    # Emit ECS event fields as DOTTED keys so the human-readable message survives.
    # structlog stores the message under "event"; ecs-logging's StructlogFormatter
    # pops "event" -> "message" *before* de-dotting remaining keys, so "event.*"
    # de-dots into the ECS event object while the message is preserved.
    # (Previously this overwrote event_dict["event"] with the ecs_event dict,
    # clobbering the message -> message rendered as the dict repr, event.* lost.)
    if "ecs_event" in event_dict:
        ecs_event = event_dict.pop("ecs_event")
        if isinstance(ecs_event, dict):
            for sub_key, sub_value in ecs_event.items():
                event_dict[f"event.{sub_key}"] = sub_value
        else:
            event_dict["event.original"] = ecs_event

    return event_dict


def contextvars_injector(_logger, _method_name, event_dict):
    """
    Structlog processor that injects context from multiple sources.

    Injection order (later sources don't override earlier ones):
    1. Explicit log parameters (already in event_dict)
    2. LoggingContext from decorators/middleware
    3. Structlog contextvars
    4. CID trace_id
    5. Service metadata

    Note: merchant_id is injected dynamically via LoggingContext.extra
    using bind_logging_context(extra={"merchant_id": "..."})
    """
    # 1. Inject from LoggingContext (decorators set this)
    event_dict = _inject_logging_context(event_dict)

    # 2. Add trace.id from CID (parses W3C traceparent format)
    with contextlib.suppress(Exception):
        trace_id = get_trace_id()
        if trace_id and "trace" not in event_dict:
            event_dict["trace"] = {"id": trace_id}

    # 3. Add structlog context vars (skip during early startup)
    with contextlib.suppress(Exception):
        context = get_contextvars()
        if context:
            for key, value in context.items():
                if key not in event_dict:
                    event_dict[key] = value

    # 4. Add service metadata (always injected)
    #
    # Merged, not assigned: `service` is a shared ECS root. We own `name` and
    # `version` and always win on those, but ECS also puts `service.target.*`
    # ("the target service in case of an outgoing request") and `service.node.*`
    # there, and a caller that sets them on an outbound boundary line has just as
    # much right to the root as we do. Replacing the dict dropped them silently.
    service_name, service_version = _detect_service()
    service = event_dict.get("service")
    if not isinstance(service, dict):
        service = {}
    event_dict["service"] = {
        **service,
        "name": service_name,
        "version": service_version,
    }
    event_dict["project"] = {
        "name": identity.get_project_name(),
    }

    return event_dict


# =============================================================================
# SENSITIVE DATA MASKING/TOKENIZATION
# =============================================================================
#
# The actual masking rules live in ecsctx.masking (MaskPIIFilter). This
# processor is the engine for every handler whose formatter runs it —
# get_logging_config()'s among them — and it delegates to a filter instance,
# so a pipeline that only calls configure_structlog() still gets masked, and
# a payload nested under `extra` (moved there by namespace_ecs_fields) is
# covered too. Structural fields and correlation ids are skipped — see
# DEFAULT_SKIP_KEYS in ecsctx.masking.filters.
_default_filter = MaskPIIFilter()


def mask_pan(number: str) -> str:
    """Truncate a PAN: first 6 + last 4 from 15 digits up, last 4 below.

    Bare-core counterpart of the engine's card rule, which emits the same
    truncation label-wrapped (`[CARD-MASKED:411111******1111]`): use this
    helper at call sites that must mask a PAN before logging (e.g.
    replacing a hand-rolled helper). The core truncation is shared with
    `ecsctx.masking.patterns._truncate_pan` so the two can never drift.
    Logs are stored data (PCI DSS 3.5.1); FAQ 1091 allows first 6 + last 4
    for 15/16-digit PANs of every listed brand and covers shorter ones only
    for Discover. Separators are stripped, so grouped input comes back as one
    contiguous masked value. Values of 10 or fewer digits are fully starred:
    this path only receives PAN-length input, so anything else is a caller
    bug, and starring fails closed.
    """
    digits = re.sub(r"[ -]", "", number)
    if len(digits) > 10:
        return _truncate_pan(digits)
    return "*" * len(digits)


def normalize_url_field(_logger, _method_name, event_dict: dict) -> dict:
    """Auto-normalize a bare-string ``url=`` into the ECS url object.

    Call sites log the raw string; the processor shapes it via ``ecs_url()``
    (credential query redacted by default), so no call site imports helpers
    itself. An already-shaped dict passes through unchanged.
    """
    url = event_dict.get("url")
    if isinstance(url, str):
        event_dict["url"] = ecs_url(url)
    return event_dict


def normalize_payload_field(_logger, _method_name, event_dict: dict) -> dict:
    """Auto-parse a bytes ``payload=`` into real JSON for structured logging.

    Deliberately bytes-only, not str: JSON also parses bare primitives
    ("123" -> 123), so auto-parsing arbitrary strings risks silently changing
    a plain-text payload's type. Bytes always means raw wire data, so the
    intent there is unambiguous. Falls back to the original bytes unchanged
    if it isn't valid JSON (e.g. an HTML error page).

    Must run BEFORE ``mask_sensitive_data`` in the processor chain: the
    masker only walks parsed structures, so a bytes payload reaching it
    first gets regex-only scrubbing, then parses here into an unmasked
    dict with no second masking pass.
    """
    payload = event_dict.get("payload")
    if isinstance(payload, bytes):
        event_dict["payload"] = parse_json_or_raw(payload)
    return event_dict


def mask_sensitive_data(_logger, _method_name, event_dict):
    """Structlog processor for PII/PCI masking and tokenization.

    Delegates to MaskPIIFilter, which walks the whole event_dict (except
    the structural fields in DEFAULT_SKIP_KEYS/DEFAULT_SKIP_LEAVES and the
    `event.*` dotted ECS event fields) recursively, masking sensitive
    content and dict keys with the packs in force. Idempotent: masked
    markers are left as they are.

    Bytes ``payload=`` must be parsed by ``normalize_payload_field``
    earlier in the chain — this processor never parses raw bytes itself.
    """
    to_mask = {k: v for k, v in event_dict.items() if not (isinstance(k, str) and k.startswith("event."))}
    masked = _default_filter._mask_dict(to_mask)
    event_dict.update(masked)
    return event_dict
