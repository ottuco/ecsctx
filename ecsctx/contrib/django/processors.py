"""
Django-specific processor wrappers.

Note: merchant_id is injected dynamically via LoggingContext.extra
using bind_logging_context(extra={"merchant_id": "..."})
"""

import contextlib
import os

from structlog.contextvars import get_contextvars

from ecsctx.context import get_trace_id
from ecsctx.pii import configure_pii_from_env
from ecsctx.processors import _detect_service, _inject_logging_context


def _auto_configure_pii():
    """Auto-configure PII from environment on first use."""
    configure_pii_from_env()


_mask_settings_attempted = False


def _auto_configure_masking() -> None:
    """Bridge the Django ``ECSCTX_MASK_EXEMPT_PATHS`` setting into the core
    masking config, lazily on first use.

    Runs at log time (when Django settings are fully loaded), so the setting is
    honored regardless of how logging was wired (setup_logging,
    get_logging_config, or manual). Retries until settings are accessible.
    Precedence is preserved: an explicit configure_masking() call wins, then
    this setting, then the PII_MASK_EXEMPT_PATHS env var.
    """
    global _mask_settings_attempted
    if _mask_settings_attempted:
        return

    from ecsctx.processors import configure_masking, masking_is_configured

    # An explicit configure_masking() (or a prior load) already won.
    if masking_is_configured():
        _mask_settings_attempted = True
        return

    try:
        from django.conf import settings

        exempt = getattr(settings, "ECSCTX_MASK_EXEMPT_PATHS", None)
    except Exception:
        # Settings not ready yet (e.g. during settings.py import) — leave the
        # flag unset so we retry on the next call (at real log time).
        return

    _mask_settings_attempted = True
    if exempt is not None:
        configure_masking(exempt_paths=list(exempt))


def _reset_masking_settings_flag() -> None:
    """Reset the settings-bridge guard. For testing only."""
    global _mask_settings_attempted
    _mask_settings_attempted = False


_root_fields_settings_attempted = False


def _auto_configure_root_fields() -> None:
    """Bridge the Django ``ECSCTX_ROOT_FIELDS`` setting into the core
    root-fields config, lazily on first use.

    Same shape as _auto_configure_masking: runs at log time (settings fully
    loaded), retries until settings are accessible, and preserves precedence —
    an explicit configure_root_fields() call wins, then this setting, then the
    ECSCTX_ROOT_FIELDS env var.
    """
    global _root_fields_settings_attempted
    if _root_fields_settings_attempted:
        return

    from ecsctx.processors import configure_root_fields, root_fields_are_configured

    if root_fields_are_configured():
        _root_fields_settings_attempted = True
        return

    try:
        from django.conf import settings

        extra_fields = getattr(settings, "ECSCTX_ROOT_FIELDS", None)
    except Exception:
        # Settings not ready yet — retry on the next call (at real log time).
        return

    _root_fields_settings_attempted = True
    if extra_fields is not None:
        configure_root_fields(extra_fields=list(extra_fields))


def _reset_root_fields_settings_flag() -> None:
    """Reset the settings-bridge guard. For testing only."""
    global _root_fields_settings_attempted
    _root_fields_settings_attempted = False


def _get_django_user_model():
    """Get the Django User model from settings."""
    try:
        from django.contrib.auth import get_user_model

        return get_user_model()
    except Exception:
        from django.contrib.auth.models import User as _DefaultUser

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
        "id": str(user_obj.pk) if hasattr(user_obj, "pk") and user_obj.pk else None,
    }

    # Add common Django User fields if they exist
    optional_fields = [
        "username",
        "email",
        "first_name",
        "last_name",
    ]

    for field_name in optional_fields:
        if hasattr(user_obj, field_name):
            user_data[field_name] = getattr(user_obj, field_name)

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

    # 0. Auto-configure PII + masking exemptions + root fields on first call
    _auto_configure_pii()
    _auto_configure_masking()
    _auto_configure_root_fields()

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
