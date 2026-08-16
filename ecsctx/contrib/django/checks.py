"""Boot-time validation that PII masking is actually wired into LOGGING.

Ported from ottu_pg's conf/apps.py AppConfig.ready() guard, generalized to a
Django system check (registered automatically on import — no AppConfig or
INSIDE_APPS change needed, since a project already imports this package via
the MIDDLEWARE string "ecsctx.contrib.django.LoggingContextMiddleware").

Refuses to boot cleanly (django.core.checks reports an Error) if LOGGING
could ship unmasked logs off-host: mask_pii_filter must be defined with a
'()' path that resolves to ecsctx.masking.filters.MaskPIIFilter (or a
subclass), and every shipping handler (anything other than a console/no-op
handler) must either carry it itself, or only be reached by loggers that
carry it.

find_masking_config_errors() is the framework-agnostic core, reusable from
plain code or tests; validate_masking_config() raises for direct calls (e.g.
from a project's own AppConfig.ready(), matching the original ottu_pg
pattern); check_masking_configured() is the registered Django system check.
"""

from __future__ import annotations

import os
from importlib import import_module
from typing import Any

_NON_SHIPPING_CLASSES = frozenset({"logging.StreamHandler", "logging.NullHandler"})

DEFAULT_SKIP_ENVS = frozenset({"local", "test", "dev"})
DEFAULT_ENV_VAR = "ENVIRONMENT"


def _is_shipping_handler(handler_config: dict) -> bool:
    """A handler ships logs off-host unless it is a console StreamHandler or a no-op NullHandler."""
    return handler_config.get("class") not in _NON_SHIPPING_CLASSES


def _resolve_dotted_path(path: str) -> Any:
    module_path, _, class_name = path.rpartition(".")
    if not module_path:
        return None
    try:
        module = import_module(module_path)
    except ImportError:
        return None
    return getattr(module, class_name, None)


def _filter_class_error(filters: dict) -> str | None:
    """None if filters['mask_pii_filter']['()'] resolves to a MaskPIIFilter subclass, else an error string."""
    from ecsctx.masking.filters import MaskPIIFilter

    filter_def = filters.get("mask_pii_filter")
    path = filter_def.get("()") if isinstance(filter_def, dict) else None
    if not isinstance(path, str) or not path:
        return (
            "LOGGING['filters']['mask_pii_filter'] must define '()' as a dotted "
            "import path to a logging.Filter class, e.g. "
            "{'()': 'ecsctx.masking.filters.MaskPIIFilter'}."
        )

    resolved = _resolve_dotted_path(path)
    if not (isinstance(resolved, type) and issubclass(resolved, MaskPIIFilter)):
        return (
            f"LOGGING['filters']['mask_pii_filter']['()'] ({path!r}) must resolve to "
            "ecsctx.masking.filters.MaskPIIFilter or a subclass of it."
        )
    return None


def _filter_used_in_handler(handler_config: dict) -> bool:
    return "mask_pii_filter" in handler_config.get("filters", [])


def _filter_used_in_logger(logger_config: dict) -> bool:
    return "mask_pii_filter" in logger_config.get("filters", [])


def _is_unmasked_shipping_logger(logger_config: dict, handlers_configs: dict) -> bool:
    """True if this logger reaches a shipping handler without mask_pii_filter applied
    anywhere between the logger itself and that handler."""
    if _filter_used_in_logger(logger_config):
        return False
    for handler_name in logger_config.get("handlers", []):
        handler_config = handlers_configs.get(handler_name, {})
        if _is_shipping_handler(handler_config) and not _filter_used_in_handler(handler_config):
            return True
    return False


def find_masking_config_errors(logging_config: dict[str, Any]) -> list[str]:
    """Return human-readable problems with logging_config's PII masking setup.

    Empty list means the config is safe. An empty/absent logging_config is
    considered nothing to validate (e.g. a project using install_maskers()
    with manually-built handlers instead of the declarative LOGGING setting).
    """
    if not logging_config:
        return []

    errors: list[str] = []
    filters = logging_config.get("filters", {})
    if "mask_pii_filter" not in filters:
        errors.append(
            "mask_pii_filter must be defined in LOGGING['filters'] for PCI DSS "
            "compliance. Add 'mask_pii_filter': "
            "{'()': 'ecsctx.masking.filters.MaskPIIFilter'} to filters — or use "
            "ecsctx.contrib.django.get_logging_config(), which does this "
            "automatically — or call ecsctx.masking.install_maskers() to sweep "
            "handlers built outside of LOGGING."
        )
        return errors

    filter_class_error = _filter_class_error(filters)
    if filter_class_error:
        errors.append(filter_class_error)
        return errors

    handlers_configs = logging_config.get("handlers", {})
    loggers_configs = logging_config.get("loggers", {})

    unmasked = [
        name
        for name, logger_config in loggers_configs.items()
        if _is_unmasked_shipping_logger(logger_config, handlers_configs)
    ]
    if _is_unmasked_shipping_logger(logging_config.get("root", {}), handlers_configs):
        unmasked.append("root")

    if unmasked:
        errors.append(
            "mask_pii_filter is defined but not used by logger(s): "
            + ", ".join(sorted(unmasked))
            + ". For PCI DSS compliance, every logger that reaches a shipping "
            "handler (anything other than logging.StreamHandler/"
            "logging.NullHandler) must carry mask_pii_filter itself, or only "
            "use handlers that do."
        )
    return errors


def validate_masking_config(logging_config: dict[str, Any]) -> None:
    """Raise ValueError if logging_config could ship unmasked logs off-host.

    For direct use from a project's own AppConfig.ready() or settings.py —
    the same core check that also backs the Django system check below.
    """
    errors = find_masking_config_errors(logging_config)
    if errors:
        raise ValueError(" ".join(errors))


def _should_skip(settings) -> bool:
    if getattr(settings, "ECSCTX_SKIP_MASKING_CHECK", False):
        return True
    env_var = getattr(settings, "ECSCTX_MASKING_CHECK_ENV_VAR", DEFAULT_ENV_VAR)
    skip_envs = getattr(settings, "ECSCTX_MASKING_CHECK_SKIP_ENVS", DEFAULT_SKIP_ENVS)
    current_env = os.environ.get(env_var, "").lower()
    skip_envs = {str(e).lower() for e in skip_envs}
    return current_env in skip_envs


def check_masking_configured(app_configs, **kwargs) -> list:
    """Django system check: runs on manage.py check / check --deploy /
    runserver / migrate. Skipped in local/test/dev environments (see
    _should_skip) so it never blocks day-to-day development.
    """
    from django.conf import settings
    from django.core.checks import Error

    if _should_skip(settings):
        return []

    logging_config = getattr(settings, "LOGGING", {}) or {}
    problems = find_masking_config_errors(logging_config)
    return [Error(msg, id=f"ecsctx.E{i + 1:03d}") for i, msg in enumerate(problems)]


def _register() -> None:
    from django.core.checks import Tags, register

    register(check_masking_configured, Tags.security)


_register()
