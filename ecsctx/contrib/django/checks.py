"""Boot-time validation that PII masking is actually wired into LOGGING.

Ported from ottu_pg's conf/apps.py AppConfig.ready() guard, generalized to a
Django system check (registered automatically on import — no AppConfig or
INSIDE_APPS change needed, since a project already imports this package via
the MIDDLEWARE string "ecsctx.contrib.django.LoggingContextMiddleware").

Refuses to boot cleanly (django.core.checks reports an Error) if LOGGING
could ship unmasked logs off-host: mask_pii_filter must be defined with a
'()' path that resolves to ecsctx.masking.filters.MaskPIIFilter (or a
subclass), and every handler must either carry it itself, or only be reached
by loggers that carry it. Every handler counts as shipping, because even
console output is usually collected and forwarded off-host.

find_masking_errors() is the core every entry point goes through, summing the
two halves: find_masking_config_errors() reads the declarative LOGGING dict
(framework-agnostic, reusable from plain code or tests) and
find_unmasked_live_handlers() reads the live logging tree, which is where
Django's own DEFAULT_LOGGING pass and late-importing packages leave handlers
that no config mentions. validate_masking_config() raises ValueError for direct
calls (e.g. from a project's own AppConfig.ready(), matching the original
ottu_pg pattern); assert_no_masking_errors() raises AssertionError for use
in a project's own test suite — unlike the system check below, it is never
skipped by environment, while the system check skips itself in any environment
listed in ECSCTX_MASKING_CHECK_SKIP_ENVS (none by default);
check_masking_configured() is the registered Django system check.
"""

from __future__ import annotations

import logging
import os
from importlib import import_module
from typing import Any

DEFAULT_ENV_VAR = "ENVIRONMENT"


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


def _filter_used_in_conf(logger_or_handler_config: dict) -> bool:
    """Logger and handler configs both hold a "filters" list of names."""
    return "mask_pii_filter" in logger_or_handler_config.get("filters", [])


def _filter_used_in_live_object(logger_or_handler) -> bool:
    """Live loggers and handlers both carry .filters holding real instances."""
    from ecsctx.masking.filters import MaskPIIFilter

    return any(isinstance(f, MaskPIIFilter) for f in logger_or_handler.filters)


def _is_unmasked_logger(logger_config: dict, handlers_configs: dict) -> bool:
    """True if this logger reaches a handler without mask_pii_filter applied
    anywhere between the logger itself and that handler."""
    if _filter_used_in_conf(logger_config):
        return False
    for handler_name in logger_config.get("handlers", []):
        if not _filter_used_in_conf(handlers_configs.get(handler_name, {})):
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
        if _is_unmasked_logger(logger_config, handlers_configs)
    ]
    if _is_unmasked_logger(logging_config.get("root", {}), handlers_configs):
        unmasked.append("root")

    if unmasked:
        errors.append(
            "mask_pii_filter is defined but not used by logger(s): "
            + ", ".join(sorted(unmasked))
            + ". For PCI DSS compliance, every logger that has handlers must "
            "carry mask_pii_filter itself, or only use handlers that do."
        )
    return errors


def _is_pytest_handler(handler: logging.Handler) -> bool:
    """A capture handler pytest attached, not one the project configured."""
    return type(handler).__module__.split(".")[0] in {"_pytest", "pytest"}


def _live_handler_class_path(handler: logging.Handler) -> str:
    cls = type(handler)
    return f"{cls.__module__}.{cls.__qualname__}"


def find_unmasked_live_handlers(
    logging_config: dict[str, Any], *, ignore_pytest_handlers: bool = False
) -> list[str]:
    """Handlers live in this process that no LOGGING dict accounts for.

    ignore_pytest_handlers skips the capture handlers pytest attaches during a
    run. They belong to the test runner, exist only mid-test so no install
    sweep can reach them, and would otherwise fail a correctly masked project.
    """
    logging_config = logging_config or {}
    configured = set(logging_config.get("loggers", {}))
    candidates: list[tuple[str, logging.Logger]] = []
    if "root" not in logging_config:
        candidates.append(("root", logging.root))
    for name, logger in sorted(logging.Logger.manager.loggerDict.items()):
        if name not in configured and isinstance(logger, logging.Logger):
            candidates.append((name, logger))

    unmasked = []
    for name, logger in candidates:
        if logger.disabled or _filter_used_in_live_object(logger):
            continue
        for handler in logger.handlers:
            if _filter_used_in_live_object(handler):
                continue
            if ignore_pytest_handlers and _is_pytest_handler(handler):
                continue
            unmasked.append(f"{name} -> {_live_handler_class_path(handler)}")

    if not unmasked:
        return []
    return [
        "Live logger(s) absent from LOGGING are reaching unmasked shipping "
        "handlers: " + ", ".join(unmasked) + ". These come from Django's own "
        "DEFAULT_LOGGING pass, or from a package that attaches handlers when "
        "it is imported — both happen outside settings.LOGGING. Name them in "
        "LOGGING['loggers'] so they get rebuilt with mask_pii_filter, or call "
        "ecsctx.masking.install_maskers() after logging setup to sweep them."
    ]


def find_masking_errors(
    logging_config: dict[str, Any], *, ignore_pytest_handlers: bool = False
) -> list[str]:
    """Every masking problem, from both halves: what the LOGGING dict declares
    and what the live logging tree actually ended up with.

    The entry points below all go through this, so none of them can pass while
    the other half is broken.
    """
    return find_masking_config_errors(logging_config) + find_unmasked_live_handlers(
        logging_config, ignore_pytest_handlers=ignore_pytest_handlers
    )


def validate_masking_config(logging_config: dict[str, Any]) -> None:
    """Raise ValueError if logging_config could ship unmasked logs off-host.

    For direct use from a project's own AppConfig.ready() or settings.py —
    the same core check that also backs the Django system check below.
    """
    errors = find_masking_errors(logging_config)
    if errors:
        raise ValueError(" ".join(errors))


def assert_no_masking_errors(
    logging_config: dict[str, Any], *, ignore_pytest_handlers: bool = False
) -> None:
    """Assert that a Django-style LOGGING dict has PII masking fully wired in.

    Raises AssertionError with the specific problem(s) found, listing every
    logger/handler that could ship logs off-host unmasked. Intended for a
    project's own test suite, e.g.:

        def test_logging_is_masked(settings):
            assert_no_masking_errors(settings.LOGGING)

    This mirrors check_masking_configured() below, but is never skipped by
    environment — use it when you want the same guarantee enforced in CI
    even where a project has told the system check to skip itself
    (ECSCTX_MASKING_CHECK_SKIP_ENVS).
    """
    errors = find_masking_errors(
        logging_config, ignore_pytest_handlers=ignore_pytest_handlers
    )
    assert not errors, " ".join(errors)


def masking_check_skip_reason(settings=None) -> str | None:
    """Why the system check silences itself here, or None when it runs.

    Public so a project's own tests can assert the guard is live — see
    ecsctx.contrib.django.testing.MaskingTestsMixin.
    """
    if settings is None:
        from django.conf import settings

    if getattr(settings, "ECSCTX_SKIP_MASKING_CHECK", False):
        return "ECSCTX_SKIP_MASKING_CHECK is set"
    env_var = getattr(settings, "ECSCTX_MASKING_CHECK_ENV_VAR", DEFAULT_ENV_VAR)
    skip_envs = [
        str(e) for e in getattr(settings, "ECSCTX_MASKING_CHECK_SKIP_ENVS", [])
    ]
    current_env = os.environ.get(env_var, "").lower()
    if current_env in {e.lower() for e in skip_envs}:
        return (
            f"the {env_var} env var is {current_env!r}, which ECSCTX_MASKING_CHECK_SKIP_ENVS "
            f"lists ({skip_envs})"
        )
    return None


def _should_skip(settings) -> bool:
    return masking_check_skip_reason(settings) is not None


def check_masking_configured(app_configs, **kwargs) -> list:
    """Django system check: runs on manage.py check / check --deploy /
    runserver / migrate, in every environment unless
    ECSCTX_MASKING_CHECK_SKIP_ENVS lists the current one (see masking_check_skip_reason).
    """
    from django.conf import settings
    from django.core.checks import Error

    if _should_skip(settings):
        return []

    logging_config = getattr(settings, "LOGGING", {}) or {}
    problems = find_masking_errors(logging_config)
    return [Error(msg, id=f"ecsctx.E{i + 1:03d}") for i, msg in enumerate(problems)]


def _register() -> None:
    from django.core.checks import Tags, register

    register(check_masking_configured, Tags.security)


_register()
