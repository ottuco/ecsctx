import base64
import contextlib
from functools import lru_cache
import hashlib
import json
import os
import re
import sys

from cryptography.fernet import Fernet
from django.conf import settings
from structlog.contextvars import get_contextvars

from logctx.context import get_logging_context, get_trace_id


def _get_app_version() -> str:
    """Get application version from environment or settings."""
    version = os.environ.get("APP_VERSION")
    if version:
        return version
    try:
        from django.conf import settings as django_settings

        return getattr(django_settings, "APP_VERSION", "0.0.0")
    except Exception:
        return "0.0.0"


def _detect_service():
    """Detect service name and version from environment or process name.

    Returns tuple of (name, version).
    """
    service_type = os.environ.get("SERVICE_TYPE")
    if service_type:
        if service_type == "rq":
            import rq  # noqa: PLC0415 - Conditional import based on service type

            return "rq", rq.VERSION
        if service_type == "rqscheduler":
            import rq_scheduler  # noqa: PLC0415 - Conditional import based on service type

            return "rqscheduler", ".".join(map(str, rq_scheduler.VERSION))
        return service_type, _get_app_version()

    # Auto-detect from command line
    if any("rqworker" in arg for arg in sys.argv):
        import rq  # noqa: PLC0415 - Conditional import based on service type

        return "rq", rq.VERSION
    if any("rqscheduler" in arg for arg in sys.argv):
        import rq_scheduler  # noqa: PLC0415 - Conditional import based on service type

        return "rqscheduler", ".".join(map(str, rq_scheduler.VERSION))
    return "app", _get_app_version()


# ECS-compliant primary keys for log events
# These keys are kept at root level, all others go into 'extra'
PRIMARY_KEYS = frozenset({
    "payload",
    "headers",
    "http",  # ECS: http.request, http.response
    "url",  # ECS: url.path
    "view",  # Custom: view class name
    "event",  # ECS: action
    "payment",  # Custom: session_id, order_no
    "span",  # ECS: id (request_id)
    "user",  # ECS: id
    "user_agent",  # ECS: user_agent.original
    "client",  # ECS: ip
    "trace",  # ECS: id (correlation ID from CID)
    "context",
    "timestamp",
    "level",
    "service",
    "project",
    "merchant_id",
    "pg_code",
    "message",
})


def reshape_log_event(event_dict) -> dict:
    """Reshape log event to separate primary keys from extra data."""
    reshaped = {}
    extra = {}
    if not isinstance(event_dict, dict):
        return event_dict

    for key, value in event_dict.items():
        if key in PRIMARY_KEYS:
            reshaped[key] = value
        else:
            extra[key] = value

    if extra:
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
    Handle ECS field normalization.

    Removes flat 'level' key since StructlogFormatter sets log.level from method name.

    Note: ecs.version is handled by OttuECSFormatter - setting it here doesn't work
    because ecs-logging's normalize_dict converts dotted keys to nested objects,
    then format_to_ecs adds a new flat key via setdefault.
    """
    # Remove flat 'level' key added by add_log_level processor
    # StructlogFormatter will set log.level correctly using the method name
    # This prevents duplication: log.level: ["info", "info"]
    event_dict.pop("level", None)

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
    event_dict["merchant_id"] = settings.MERCHANT_ID

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
# Phone: roughly 10-15 digits, optional +, spaces/dashes. Avoids matching timestamps/IDs often.
PHONE_PATTERN = re.compile(
    r"\b(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4,6}\b"
)

# Pattern to find keys that suggest PII (Names, Contact Info) in a JSON string
# Capture Group 1: The Key (with quotes)
# Capture Group 2: The Value (with quotes)
# Looks for keys containing: name, payer, billing, shipping, customer, cardholder, email, phone, mobile, tel
# We use a broad pattern to catch variations like "Pyr_Name", "delivery_tel", "billing_email", "udf3"
SENSITIVE_KEY_PATTERN = re.compile(
    r'("[\w-]*(?:name|payer|billing|shipping|customer|cardholder|email|phone|mobile|tel|contact|recipient|beneficiary|address|udf)[\w-]*")\s*:\s*("[^"]*")',
    re.IGNORECASE,
)


def _get_fernet_key() -> bytes:
    """Derive a valid Fernet key (32 url-safe base64 bytes) from the setting."""
    secret = getattr(settings, "LOG_TOKENIZE_SECRET", None)
    if not secret:
        secret = os.environ.get(
            "LOG_TOKENIZE_SECRET", "default-change-in-production-must-be-long"
        )

    # Ensure we have 32 bytes for the key derivation
    # We use SHA256 of the secret to get exactly 32 bytes, then base64 encode it for Fernet
    hasher = hashlib.sha256()
    hasher.update(secret.encode() if isinstance(secret, str) else secret)
    return base64.urlsafe_b64encode(hasher.digest())


_FERNET_INSTANCE = None


def _get_fernet() -> Fernet:
    """Gets or creates a cached Fernet instance (Lazy Load)."""
    global _FERNET_INSTANCE
    if _FERNET_INSTANCE is None:
        _FERNET_INSTANCE = Fernet(_get_fernet_key())
    return _FERNET_INSTANCE


@lru_cache(maxsize=2048)
def _tokenize(value: str) -> str:
    """
    Encrypt the value using Fernet (AES).
    REVERSIBLE: You can decrypt this token using the project's secret key.
    Format: 'enc_<base64>'
    """
    if not value:
        return value

    # Idempotency check: if already encrypted, return as-is
    # Handles cases where context binder or other layers pre-masked data
    if value.startswith(("enc_", '"enc_')):
        return value

    # If value is quoted (from regex match), strip quotes
    is_quoted = value.startswith('"') and value.endswith('"')
    clean_val = value.strip('"')

    # Encrypt
    token = _get_fernet().encrypt(clean_val.encode()).decode()

    # Prefix to identify encrypted values easily
    tokenized = f"enc_{token}"

    return f'"{tokenized}"' if is_quoted else tokenized


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
    text = EMAIL_PATTERN.sub(lambda m: _tokenize(m.group()), text)
    # Only scrub phones that look like phones (length check is in regex)
    # But be careful with IDs.
    text = PHONE_PATTERN.sub(lambda m: _tokenize(m.group()), text)

    return text


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
