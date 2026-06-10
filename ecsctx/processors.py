"""
Framework-agnostic structlog processors for ECS-compliant logging.

All configuration is passed via environment variables or processor factory parameters.
For Django integration, use ecsctx.contrib.django.processors which reads from settings.
"""

import contextlib
import json
import os
import re
import sys

from structlog.contextvars import get_contextvars

from ecsctx.context import get_logging_context, get_trace_id
from ecsctx.pii import tokenize as _pii_tokenize


def _get_app_version() -> str:
    """Get application version from environment."""
    return os.environ.get("APP_VERSION", "0.0.0")


def _detect_service():
    """Detect service name and version from environment or process name.

    Returns tuple of (name, version).
    """
    service_type = os.environ.get("SERVICE_TYPE")
    if service_type:
        if service_type == "rq":
            import rq  # noqa: E402 - Deferred: optional dependency, absent in non-rq deployments

            return "rq", rq.VERSION
        if service_type == "rqscheduler":
            import rq_scheduler  # noqa: E402 - Deferred: optional dependency, absent in non-rq deployments

            return "rqscheduler", ".".join(map(str, rq_scheduler.VERSION))
        return service_type, _get_app_version()

    # Auto-detect from command line
    if any("rqworker" in arg for arg in sys.argv):
        import rq  # noqa: E402 - Deferred: optional dependency, absent in non-rq deployments

        return "rq", rq.VERSION
    if any("rqscheduler" in arg for arg in sys.argv):
        import rq_scheduler  # noqa: E402 - Deferred: optional dependency, absent in non-rq deployments

        return "rqscheduler", ".".join(map(str, rq_scheduler.VERSION))
    return "app", _get_app_version()


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


def reshape_log_event(event_dict) -> dict:
    """Reshape log event: allowlisted keys stay at root, everything else goes into extra.

    - Keys in ROOT_ALLOWLIST always stay at root.
    - Non-allowlisted keys (scalars, lists, and dicts) are wrapped into
      ``extra``.
    """
    if not isinstance(event_dict, dict):
        return event_dict

    reshaped = {}
    extra = {}

    for key, value in event_dict.items():
        if key in ROOT_ALLOWLIST or key.startswith("_") or key.startswith("event."):
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
    service_name, service_version = _detect_service()
    event_dict["service"] = {
        "name": service_name,
        "version": service_version,
    }
    event_dict["project"] = {
        "name": os.environ.get("PROJECT_NAME", "connect"),
    }

    return event_dict


# =============================================================================
# SENSITIVE DATA MASKING/TOKENIZATION
# =============================================================================

# Auth header keys to mask
AUTH_HEADER_KEYS = frozenset({
    "authorization",
    "api-key",
    "x-api-key",
    "api_key",
    "apikey",
})

# Safe keys that might contain "name" but should NOT be masked
SAFE_NAME_KEYS = frozenset({
    "gateway_name",
    "vendor_name",
    "module_name",
    "func_name",
    "task_name",
    "service_name",
    "app_name",
    "project_name",
    "class_name",
    "method_name",
    "view_name",
    "username",  # username usually safe/auditable
    "site_name",
    "domain_name",
    "bank_name",
    "display_name",
    "install_name",
    "installation_name",
    "event_name",
    "customer_id",
    "id",
    "pk",
})

# Regex patterns for PII in string values
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
# Phone: roughly 10-15 digits, optional +, spaces/dashes.
# Avoids matching timestamps/IDs often.
PHONE_PATTERN = re.compile(
    r"\b(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4,6}\b"
)

# Substrings that mark a dict key as sensitive (case-insensitive). A string
# value under such a key is tokenized unless the key is in SAFE_NAME_KEYS or its
# JSON path is exempted. Single source of truth for key sensitivity. Broad on
# purpose to catch variations like "Pyr_Name", "delivery_tel", "billing_email",
# "udf3".
SENSITIVE_KEYWORDS = (
    "name",
    "payer",
    "billing",
    "shipping",
    "customer",
    "cardholder",
    "email",
    "phone",
    "mobile",
    "tel",
    "contact",
    "recipient",
    "beneficiary",
    "address",
    "udf",
)


def _key_is_sensitive(key) -> bool:
    """True if a dict key suggests PII (and is not whitelisted)."""
    if not isinstance(key, str):
        return False
    low = key.lower()
    if low in SAFE_NAME_KEYS:
        return False
    return any(kw in low for kw in SENSITIVE_KEYWORDS)

# Token prefixes for idempotency checks
_TOKEN_PREFIXES = ("ptok:", '"ptok:')
_REDACTED = "[PII_REDACTED]"


def safe_tokenize(value: str, field_type: str = "generic") -> str:
    """Tokenize a value using HMAC-SHA-256 via the PII module.

    If PII is not configured, returns [PII_REDACTED] to prevent
    raw PII from appearing in logs.
    """
    if not value:
        return value

    # Idempotency: already tokenized or redacted
    if value.startswith(_TOKEN_PREFIXES):
        return value

    # Handle quoted values from regex matches
    is_quoted = value.startswith('"') and value.endswith('"')
    clean_val = value.strip('"') if is_quoted else value

    try:
        token = _pii_tokenize(clean_val, field_type)
    except Exception:
        return f'"{_REDACTED}"' if is_quoted else _REDACTED
    return f'"{token}"' if is_quoted else token


def _mask_auth_value(value: str) -> str:
    """Mask auth value, preserving scheme (Bearer, Api-Key, etc.)."""
    parts = value.split(" ", 1)
    if len(parts) == 2:
        scheme, secret = parts
        if len(secret) > 8:
            return f"{scheme} {secret[:4]}****{secret[-4:]}"
        return f"{scheme} ****"
    if len(value) > 8:
        return f"{value[:4]}****{value[-4:]}"
    return "****"


def _mask_headers(headers: dict) -> dict:
    """Mask auth headers only."""
    result = {}
    for key, value in headers.items():
        if key.lower() in AUTH_HEADER_KEYS and isinstance(value, str):
            result[key] = _mask_auth_value(value)
        else:
            result[key] = value
    return result


def _scrub_string_content(text: str) -> str:
    """
    Scrub PII from a string using regex.
    Handles Emails, Phones, Credit Cards.
    """
    text = EMAIL_PATTERN.sub(lambda m: safe_tokenize(m.group(), "email"), text)
    # Only scrub phones that look like phones (length check is in regex)
    # But be careful with IDs.
    return PHONE_PATTERN.sub(lambda m: safe_tokenize(m.group(), "phone"), text)


# --- Path-aware mask exemptions (mirrors the PII singleton config pattern) ---
# Exemption paths let a consuming service mark specific JSON paths as non-PII so
# their string values are NOT key-tokenized. Email/phone scrubbing still runs on
# every string leaf regardless (defense in depth). Paths are matched relative to
# the masked container root (payload/args/kwargs/http body).
#
# Path syntax: dict step "key", array step "[*]", single dict-key wildcard "*".
# Matching is a PREFIX match, so a pattern also exempts the whole subtree below it
# ("payment_methods" exempts everything under it; "payment_methods[*].name" only
# that leaf).
_exempt_patterns: tuple | None = None
_mask_auto_configure_attempted: bool = False


def _compile_path(pattern: str) -> tuple:
    """Parse an exemption pattern into a tuple of segments.

    "payment_methods[*].name" -> ("payment_methods", "[*]", "name")
    "customer.name"           -> ("customer", "name")
    "a.*.b"                   -> ("a", "*", "b")
    """
    return tuple(re.findall(r"\[\*\]|[^.\[\]]+", pattern))


def configure_masking(*, exempt_paths: list[str] | None = None) -> None:
    """Configure path exemptions for PII masking (highest precedence)."""
    global _exempt_patterns, _mask_auto_configure_attempted
    paths = exempt_paths or []
    _exempt_patterns = tuple(_compile_path(p) for p in paths if p)
    _mask_auto_configure_attempted = True


def configure_masking_from_env() -> None:
    """Load exemptions from the PII_MASK_EXEMPT_PATHS env var (CSV). Idempotent."""
    global _exempt_patterns, _mask_auto_configure_attempted
    if _mask_auto_configure_attempted or _exempt_patterns is not None:
        return
    _mask_auto_configure_attempted = True
    raw = os.environ.get("PII_MASK_EXEMPT_PATHS", "")
    paths = [p.strip() for p in raw.split(",") if p.strip()]
    _exempt_patterns = tuple(_compile_path(p) for p in paths)


def masking_is_configured() -> bool:
    """True if mask exemptions have been explicitly set or env-loaded."""
    return _exempt_patterns is not None


def _get_exempt_patterns() -> tuple:
    if _exempt_patterns is None:
        configure_masking_from_env()
    return _exempt_patterns or ()


def _reset_masking() -> None:
    """Reset masking config. For testing only."""
    global _exempt_patterns, _mask_auto_configure_attempted
    _exempt_patterns = None
    _mask_auto_configure_attempted = False


def _path_matches(path: tuple, pattern: tuple) -> bool:
    """Prefix match: True if `pattern` matches the leading segments of `path`.

    "[*]" matches an array step only; "*" matches exactly one dict-key step
    (never an array step); a literal matches an equal dict key.
    """
    if len(pattern) > len(path):
        return False
    for pat_seg, path_seg in zip(pattern, path):
        if pat_seg == "[*]":
            if path_seg != "[*]":
                return False
        elif pat_seg == "*":
            if path_seg == "[*]":
                return False
        elif pat_seg != path_seg:
            return False
    return True


def _path_is_exempt(path: tuple, patterns: tuple) -> bool:
    return any(_path_matches(path, p) for p in patterns)


def _mask_leaf(value: str, key, path: tuple, exempt: tuple) -> str:
    """Mask a single string leaf that has a known dict key."""
    # Idempotency: already tokenized/redacted -> leave alone.
    if value.startswith(_TOKEN_PREFIXES):
        return value
    if _key_is_sensitive(key) and not _path_is_exempt(path, exempt):
        return safe_tokenize(value, "generic")
    # Non-sensitive or exempted key: still catch emails/phones in the value.
    return _scrub_string_content(value)


def _mask_structure(node, path: tuple, exempt: tuple):
    """Recursively mask a JSON-normalized structure, tracking the path.

    - dict: recurse per key (path += (key,))
    - list: recurse per element (path += ("[*]",))
    - str leaf with a key: tokenize if sensitive and not exempt, else scrub
    - other scalars (int/float/bool/None): unchanged
    """
    if isinstance(node, dict):
        for k, v in node.items():
            child_path = path + (k,)
            if isinstance(v, str):
                node[k] = _mask_leaf(v, k, child_path, exempt)
            else:
                node[k] = _mask_structure(v, child_path, exempt)
        return node
    if isinstance(node, list):
        arr_path = path + ("[*]",)
        for i, v in enumerate(node):
            if isinstance(v, str):
                # Array elements have no key -> email/phone scrub only.
                node[i] = _scrub_string_content(v)
            else:
                node[i] = _mask_structure(v, arr_path, exempt)
        return node
    return node


def _safe_dump_and_mask(data):
    """Normalize via a JSON round-trip (default=str handles UUID/Decimal/models),
    then recursively mask with path-aware exemptions. Email/phone scrubbing runs
    on every string leaf as defense in depth.
    """
    try:
        normalized = json.loads(json.dumps(data, default=str))
    except Exception:
        # Normalization failed (very unlikely with default=str) -> string scrub.
        try:
            return _scrub_string_content(str(data))
        except Exception:
            return "LOG_MASKING_ERROR"

    exempt = _get_exempt_patterns()
    try:
        if isinstance(normalized, (dict, list)):
            return _mask_structure(normalized, (), exempt)
        if isinstance(normalized, str):
            return _scrub_string_content(normalized)
        return normalized
    except Exception:
        try:
            return _scrub_string_content(str(data))
        except Exception:
            return "LOG_MASKING_ERROR"


def mask_sensitive_data(_logger, _method_name, event_dict):
    """
    Structlog processor for surgical masking and tokenization.

    Path-aware: each scrubbed container is JSON-normalized and recursively
    walked, tokenizing sensitive string values unless their JSON path is
    exempted (see configure_masking). Emails/phones are scrubbed on every
    string leaf regardless.
    - Headers: mask Authorization/Api-Key values
    - Payload/Http bodies: normalize -> recursive path-aware mask
    """
    # Mask top-level headers
    if "headers" in event_dict and isinstance(event_dict["headers"], dict):
        event_dict["headers"] = _mask_headers(event_dict["headers"])

    # High-efficiency masking for payload fields
    # We iterate a fixed list of potential payload containers
    for key in ["payload", "args", "kwargs"]:
        if key in event_dict:
            event_dict[key] = _safe_dump_and_mask(event_dict[key])

    # Handle nested http structure
    if "http" in event_dict and isinstance(event_dict["http"], dict):
        http = event_dict["http"]
        # We modify the dict in place, but we need to mask specific sub-fields
        if "request" in http and isinstance(http["request"], dict):
            req = http["request"]
            if "headers" in req and isinstance(req["headers"], dict):
                req["headers"] = _mask_headers(req["headers"])
            if "body" in req:
                req["body"] = _safe_dump_and_mask(req["body"])

        if "response" in http and isinstance(http["response"], dict):
            resp = http["response"]
            if "body" in resp:
                resp["body"] = _safe_dump_and_mask(resp["body"])

    return event_dict
