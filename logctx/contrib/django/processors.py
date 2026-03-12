"""
Django-specific processor wrappers.

Note: merchant_id is injected dynamically via LoggingContext.extra
using bind_logging_context(extra={"merchant_id": "..."})
"""

import contextlib
import os

from django.contrib.auth import get_user_model
from django.contrib.auth.models import User as _DefaultUser
from structlog.contextvars import get_contextvars

from logctx.context import get_trace_id
from logctx.pii import configure_pii
from logctx.pii import is_configured as _pii_configured
from logctx.processors import _detect_service, _inject_logging_context

_pii_auto_configured = False


def _auto_configure_pii():
    """Auto-configure PII from environment on first use."""
    global _pii_auto_configured
    if _pii_auto_configured or _pii_configured():
        return
    _pii_auto_configured = True
    if os.environ.get("PII_TOKEN_KEYSET_PATH"):
        configure_pii()


def _get_django_user_model():
    """Get the Django User model from settings."""
    try:
        return get_user_model()
    except Exception:
        # Fallback to default User model if get_user_model fails
        return _DefaultUser


def _is_django_user(obj) -> bool:
    """Detect if object is an instance of Django User model."""
    try:
        user_model = _get_django_user_model()
        return isinstance(obj, user_model)
    except Exception:
        return False


def _serialize_django_user(user_obj) -> dict:
    """Serialize Django User object to ECS-compliant format."""
    if not _is_django_user(user_obj):
        return user_obj

    user_data = {
        "id": str(user_obj.pk) if hasattr(user_obj, 'pk') and user_obj.pk else None,
    }

    # Add common Django User fields if they exist
    optional_fields = [
        "username", "email", "first_name", "last_name",
    ]

    for field in optional_fields:
        if hasattr(user_obj, field):
            value = getattr(user_obj, field)
            user_data[field] = value

    return user_data


def contextvars_injector(_logger, _method_name, event_dict):
    """
    Structlog processor that injects context from multiple sources.

    Injection order (later sources don't override earlier ones):
    1. Explicit log parameters (already in event_dict)
    2. LoggingContext from decorators/middleware
    3. Structlog contextvars
    4. CID trace_id
    5. Service metadata
    6. Django User object serialization (NEW)
    """

    # 0. Auto-configure PII from env vars on first call
    _auto_configure_pii()

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

    # 5. Serialize Django User objects
    for key, value in event_dict.items():
        if key == "user" and _is_django_user(value):
            event_dict["user"] = _serialize_django_user(value)
            break  # Only process the first user object found

    return event_dict
