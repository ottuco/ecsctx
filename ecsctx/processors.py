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
        if key in ROOT_ALLOWLIST or key.startswith("_"):
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

    # Rename staging key to final ECS field name.
    # 'ecs_event' is used in log calls to avoid colliding with structlog's
    # internal 'event' key (which holds the message string).
    if "ecs_event" in event_dict:
        event_dict["event"] = event_dict.pop("ecs_event")

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

# Pattern to find keys that suggest PII (Names, Contact Info) in a JSON string
# Capture Group 1: The Key (with quotes)
# Capture Group 2: The Value (with quotes)
# Looks for keys containing: name, payer, billing, shipping, customer, cardholder,
# email, phone, mobile, tel
# We use a broad pattern to catch variations like "Pyr_Name", "delivery_tel",
# "billing_email", "udf3"
SENSITIVE_KEY_PATTERN = re.compile(
    r'("[\w-]*(?:name|payer|billing|shipping|customer|cardholder|email|phone|mobile|tel|contact|recipient|beneficiary|address|udf)[\w-]*")\s*:\s*("[^"]*")',
    re.IGNORECASE,
)

# Token prefixes for idempotency checks
_TOKEN_PREFIXES = ("ptok:", '"ptok:')
_REDACTED = "[PII_REDACTED]"


def _tokenize(value: str, field_type: str = "generic") -> str:
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
    text = EMAIL_PATTERN.sub(lambda m: _tokenize(m.group(), "email"), text)
    # Only scrub phones that look like phones (length check is in regex)
    # But be careful with IDs.
    return PHONE_PATTERN.sub(lambda m: _tokenize(m.group(), "phone"), text)


def _scrub_sensitive_keys(json_text: str) -> str:
    """
    Scrub values of keys that look sensitive (likeNames) in a JSON string.
    Checks against SAFE_NAME_KEYS whitelist.
    """

    def replace_sensitive(match):
        full_key_quoted = match.group(1)  # "customer_name"
        key_raw = full_key_quoted.strip('"')
        value_quoted = match.group(2)  # "John Doe"

        # Check if key is safe
        if key_raw.lower() in SAFE_NAME_KEYS:
            return match.group(0)  # Return unchanged

        # Tokenize the value
        return f"{full_key_quoted}: {_tokenize(value_quoted)}"

    return SENSITIVE_KEY_PATTERN.sub(replace_sensitive, json_text)


def _safe_dump_and_mask(data):
    """
    1. Dump data to JSON string (handling non-serializable types via default=str)
    2. Scrub PII from string (Values & Keys)
    3. Load back to dict/list if possible to preserve structure for logs
    """
    try:
        # Dump to string
        # default=str handles UUIDs, Decimals, Model instances, etc. safely
        dumped = json.dumps(data, default=str)

        # Apply scrubbing
        scrubbed = _scrub_sensitive_keys(dumped)  # Handle "Name" keys first
        scrubbed = _scrub_string_content(scrubbed)  # Handle Emails/Phones anywhere

        # Try to restore structure
        return json.loads(scrubbed)
    except Exception:
        # If any step fails (shouldn't strictly happen with default=str),
        # or if loading back fails, return the string representation (safest fallback)
        # We ensure at least the regexes ran if dumped succeeded.
        try:
            return _scrub_string_content(str(data))
        except Exception:
            return "LOG_MASKING_ERROR"


def mask_sensitive_data(_logger, _method_name, event_dict):
    """
    Structlog processor for surgical masking and tokenization.

    OPTIMIZED VERSION: Uses string-based regex replacement instead of recursive walking.
    - Headers: mask Authorization/Api-Key values
    - Payload/Http: Serialize -> Regex Mask -> Deserialize
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
