"""Tests for ecsctx.contrib.django.checks: the declarative LOGGING-dict
masking guard, its Django system check, and its plain-assertion/exception
entry points."""

import logging
import os

import pytest
from django.core.checks import Error
from django.test import override_settings

from ecsctx.contrib.django.checks import (
    assert_no_masking_errors,
    check_masking_configured,
    find_masking_config_errors,
    find_masking_errors,
    find_unmasked_live_handlers,
    validate_masking_config,
)
from ecsctx.contrib.django.logging import get_logging_config
from ecsctx.masking.filters import MaskPIIFilter


class CustomMaskFilter(MaskPIIFilter):
    """Referenced by dotted path in test_maskpiifilter_subclass_is_accepted."""


UNMASKED_CFG = {
    "filters": {},
    "handlers": {"file": {"class": "logging.FileHandler", "filters": []}},
    "loggers": {},
    "root": {"handlers": ["file"]},
}

MASKED_CFG = {
    "filters": {"mask_pii_filter": {"()": "ecsctx.masking.filters.MaskPIIFilter"}},
    "handlers": {"file": {"class": "logging.FileHandler", "filters": ["mask_pii_filter"]}},
    "loggers": {},
    "root": {"handlers": ["file"]},
}


class TestFindMaskingConfigErrors:
    def test_empty_config_is_nothing_to_validate(self):
        assert find_masking_config_errors({}) == []
        assert find_masking_config_errors(None) == []

    def test_missing_filter_definition_is_an_error(self):
        errors = find_masking_config_errors(UNMASKED_CFG)
        assert len(errors) == 1
        assert "mask_pii_filter must be defined" in errors[0]

    def test_filter_defined_and_used_is_clean(self):
        assert find_masking_config_errors(MASKED_CFG) == []

    def test_filter_defined_but_unused_by_a_shipping_logger(self):
        cfg = {
            "filters": {"mask_pii_filter": {"()": "ecsctx.masking.filters.MaskPIIFilter"}},
            "handlers": {"file": {"class": "logging.FileHandler", "filters": []}},
            "loggers": {"app": {"handlers": ["file"]}},
            "root": {"handlers": ["file"]},
        }
        errors = find_masking_config_errors(cfg)
        assert len(errors) == 1
        assert "app" in errors[0]
        assert "root" in errors[0]

    def test_unknown_handler_name_is_treated_as_shipping(self):
        """A logger naming a handler that isn't defined is flagged, not
        skipped — an unresolvable handler could be anything, so the check
        fails closed."""
        cfg = {
            "filters": {"mask_pii_filter": {"()": "ecsctx.masking.filters.MaskPIIFilter"}},
            "handlers": {},
            "loggers": {"app": {"handlers": ["typo_handler"]}},
            "root": {},
        }
        assert find_masking_config_errors(cfg) == [
            "mask_pii_filter is defined but not used by logger(s): app. "
            "For PCI DSS compliance, every logger that reaches a shipping "
            "handler (anything other than logging.StreamHandler/"
            "logging.NullHandler) must carry mask_pii_filter itself, or only "
            "use handlers that do."
        ]

    def test_console_stream_handler_never_flagged_unmasked(self):
        """logging.StreamHandler/NullHandler are non-shipping — a logger
        reaching only those never needs the filter."""
        cfg = {
            "filters": {"mask_pii_filter": {"()": "ecsctx.masking.filters.MaskPIIFilter"}},
            "handlers": {"console": {"class": "logging.StreamHandler", "filters": []}},
            "loggers": {"app": {"handlers": ["console"]}},
            "root": {"handlers": ["console"]},
        }
        assert find_masking_config_errors(cfg) == []

    def test_filter_class_must_resolve_to_maskpiifilter(self):
        cfg = {"filters": {"mask_pii_filter": {"()": "logging.Filter"}}, "handlers": {}}
        errors = find_masking_config_errors(cfg)
        assert len(errors) == 1
        assert "must resolve to" in errors[0]

    def test_filter_class_missing_dotted_path(self):
        cfg = {"filters": {"mask_pii_filter": {}}, "handlers": {}}
        errors = find_masking_config_errors(cfg)
        assert len(errors) == 1
        assert "dotted import path" in errors[0]

    def test_filter_class_unimportable_path_is_an_error(self):
        cfg = {"filters": {"mask_pii_filter": {"()": "no.such.module.Filter"}}, "handlers": {}}
        errors = find_masking_config_errors(cfg)
        assert len(errors) == 1
        assert "must resolve to" in errors[0]

    def test_filter_class_path_without_a_dot_is_an_error(self):
        cfg = {"filters": {"mask_pii_filter": {"()": "MaskPIIFilter"}}, "handlers": {}}
        errors = find_masking_config_errors(cfg)
        assert len(errors) == 1
        assert "must resolve to" in errors[0]

    def test_filter_class_missing_from_a_real_module_is_an_error(self):
        """The module imports fine, the attribute just isn't there."""
        cfg = {"filters": {"mask_pii_filter": {"()": "logging.NoSuchFilter"}}, "handlers": {}}
        errors = find_masking_config_errors(cfg)
        assert len(errors) == 1
        assert "must resolve to" in errors[0]

    def test_maskpiifilter_subclass_is_accepted(self):
        """A project may subclass the filter (e.g. custom skip_keys) and
        still satisfy the check."""
        cfg = {
            "filters": {"mask_pii_filter": {"()": f"{__name__}.CustomMaskFilter"}},
            "handlers": {"file": {"class": "logging.FileHandler", "filters": ["mask_pii_filter"]}},
            "loggers": {},
            "root": {"handlers": ["file"]},
        }
        assert find_masking_config_errors(cfg) == []

    def test_null_handler_is_non_shipping(self):
        cfg = {
            "filters": {"mask_pii_filter": {"()": "ecsctx.masking.filters.MaskPIIFilter"}},
            "handlers": {"null": {"class": "logging.NullHandler", "filters": []}},
            "loggers": {"app": {"handlers": ["null"]}},
            "root": {"handlers": ["null"]},
        }
        assert find_masking_config_errors(cfg) == []

    def test_filter_carried_by_the_logger_itself_is_enough(self):
        """The filter may sit on the logger instead of the handler — the
        record is masked either way."""
        cfg = {
            "filters": {"mask_pii_filter": {"()": "ecsctx.masking.filters.MaskPIIFilter"}},
            "handlers": {"file": {"class": "logging.FileHandler", "filters": []}},
            "loggers": {"app": {"handlers": ["file"], "filters": ["mask_pii_filter"]}},
            "root": {},
        }
        assert find_masking_config_errors(cfg) == []


class TestFindUnmaskedLiveHandlers:
    """The dict check cannot see loggers left behind by Django's
    DEFAULT_LOGGING pass, or attached by a package imported after logging was
    configured — only the live tree can."""

    def _shipping_handler(self, logger_name):
        handler = logging.FileHandler(os.devnull)
        logging.getLogger(logger_name).addHandler(handler)
        return handler

    def _flagged(self, cfg):
        """Joined report. Asserted against by logger name rather than for
        emptiness — Django's own setup leaves real unlisted loggers in this
        process, and those are exactly what the check is meant to report."""
        return "".join(find_unmasked_live_handlers(cfg))

    @pytest.mark.parametrize("flag", [True, False, None])
    def test_disable_existing_loggers_never_suppresses_the_scan(self, logging_state, flag):
        """The flag only disables loggers that existed when dictConfig ran —
        it says nothing about packages imported afterwards, which land in the
        tree either way. Scanning is unconditional; logger.disabled is what
        accounts for the flag's actual effect."""
        self._shipping_handler("ecsctx-live-flag")
        cfg = MASKED_CFG if flag is None else dict(MASKED_CFG, disable_existing_loggers=flag)
        assert "ecsctx-live-flag" in self._flagged(cfg)

    def test_scans_when_there_is_no_logging_dict_at_all(self, logging_state):
        """No LOGGING means Django applied DEFAULT_LOGGING and then skipped
        the second pass entirely — its handlers are live and unmasked, which
        is precisely when the scan matters most."""
        self._shipping_handler("ecsctx-live-nocfg")
        for cfg in ({}, None):
            assert "ecsctx-live-nocfg" in self._flagged(cfg)

    def test_flags_unlisted_logger_with_a_shipping_handler(self, logging_state):
        self._shipping_handler("ecsctx-live-unlisted")
        errors = find_unmasked_live_handlers(MASKED_CFG)
        assert len(errors) == 1
        assert "ecsctx-live-unlisted -> logging.FileHandler" in errors[0]

    def test_ignores_logger_named_in_the_config(self, logging_state):
        self._shipping_handler("ecsctx-live-listed")
        cfg = dict(MASKED_CFG, loggers={"ecsctx-live-listed": {}})
        assert "ecsctx-live-listed" not in self._flagged(cfg)

    def test_ignores_non_shipping_handler(self, logging_state):
        logging.getLogger("ecsctx-live-console").addHandler(logging.StreamHandler())
        assert "ecsctx-live-console" not in self._flagged(MASKED_CFG)

    def test_ignores_handler_that_already_carries_the_masker(self, logging_state):
        handler = self._shipping_handler("ecsctx-live-masked")
        handler.addFilter(MaskPIIFilter())
        assert "ecsctx-live-masked" not in self._flagged(MASKED_CFG)

    def test_ignores_logger_that_carries_the_masker_itself(self, logging_state):
        self._shipping_handler("ecsctx-live-logger-masked")
        logging.getLogger("ecsctx-live-logger-masked").addFilter(MaskPIIFilter())
        assert "ecsctx-live-logger-masked" not in self._flagged(MASKED_CFG)

    def test_ignores_disabled_logger(self, logging_state):
        self._shipping_handler("ecsctx-live-off")
        logging.getLogger("ecsctx-live-off").disabled = True
        assert "ecsctx-live-off" not in self._flagged(MASKED_CFG)

    def test_catches_djangos_admin_email_handler(self, logging_state):
        """The case this exists for: Django configures DEFAULT_LOGGING first,
        and with disable_existing_loggers off its 'django' logger survives
        with AdminEmailHandler attached, invisible to settings.LOGGING."""
        import logging.config

        from django.utils.log import DEFAULT_LOGGING

        from ecsctx.contrib.django.logging import get_logging_config

        cfg = get_logging_config()
        logging.config.dictConfig(DEFAULT_LOGGING)
        logging.config.dictConfig(cfg)

        errors = find_unmasked_live_handlers(cfg)
        assert len(errors) == 1
        assert "django -> django.utils.log.AdminEmailHandler" in errors[0]


@pytest.fixture
def only_the_dict_half(monkeypatch):
    """Silence the live-tree half.

    Both entry points sum the two halves now, and the pytest process carries
    its own real unlisted loggers — so a test pinning dict-level behaviour has
    to take the live half out of the picture to say anything precise."""
    monkeypatch.setattr(
        "ecsctx.contrib.django.checks.find_unmasked_live_handlers",
        lambda logging_config: [],
    )


@pytest.mark.usefixtures("only_the_dict_half")
class TestValidateAndAssert:
    def test_validate_raises_value_error(self):
        with pytest.raises(ValueError, match="mask_pii_filter"):
            validate_masking_config(UNMASKED_CFG)

    def test_validate_silent_when_clean(self):
        validate_masking_config(MASKED_CFG)  # must not raise

    def test_assert_raises_assertion_error(self):
        with pytest.raises(AssertionError, match="mask_pii_filter"):
            assert_no_masking_errors(UNMASKED_CFG)

    def test_assert_silent_when_clean(self):
        assert_no_masking_errors(MASKED_CFG)  # must not raise


class TestGetLoggingConfigPassesTheCheck:
    """Regression: get_logging_config() must produce a LOGGING dict that
    satisfies find_masking_config_errors() out of the box — it wires
    mask_pii_filter into every handler it builds via install_maskers_in_config."""

    def test_default_config_is_clean(self):
        cfg = get_logging_config()
        assert find_masking_config_errors(cfg) == []

    def test_console_handler_carries_the_filter(self):
        cfg = get_logging_config()
        assert "mask_pii_filter" in cfg["handlers"]["console"]["filters"]


class TestCheckIsAutoRegistered:
    """No AppConfig / INSTALLED_APPS entry is needed — importing
    ecsctx.contrib.django registers the check by itself (a project already
    imports the package via its MIDDLEWARE string)."""

    def test_registered_with_django_check_registry(self):
        from django.core.checks import registry

        names = [
            getattr(check, "__name__", "") for check in registry.registry.get_checks()
        ]
        assert "check_masking_configured" in names

    def test_registered_under_the_security_tag(self):
        """Tagged security so `manage.py check --tag security` includes it."""
        from django.core.checks import Tags, registry

        [check] = [
            c
            for c in registry.registry.get_checks()
            if getattr(c, "__name__", "") == "check_masking_configured"
        ]
        assert Tags.security in check.tags


@pytest.mark.usefixtures("only_the_dict_half")
class TestCheckMaskingConfiguredSystemCheck:
    @pytest.fixture(autouse=True)
    def _clean_environment_var(self):
        for var in ("ENVIRONMENT", "APP_ENV"):
            os.environ.pop(var, None)
        yield
        for var in ("ENVIRONMENT", "APP_ENV"):
            os.environ.pop(var, None)


    @pytest.mark.parametrize("env", ["local", "test", "dev"])
    def test_skipped_in_default_skip_envs(self, monkeypatch, env):
        monkeypatch.setenv("ENVIRONMENT", env)
        with override_settings(LOGGING=UNMASKED_CFG):
            assert check_masking_configured(None) == []

    def test_not_skipped_when_environment_is_unset(self):
        """No ENVIRONMENT var at all must not read as "skip" — a box that
        never set it is the case the check most needs to catch."""
        with override_settings(LOGGING=UNMASKED_CFG):
            errors = check_masking_configured(None)
        assert len(errors) == 1

    def test_not_skipped_in_production_by_default(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")
        with override_settings(LOGGING=UNMASKED_CFG):
            errors = check_masking_configured(None)
        assert len(errors) == 1
        assert isinstance(errors[0], Error)
        assert errors[0].id == "ecsctx.E001"

    def test_clean_config_produces_no_errors_even_in_production(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")
        with override_settings(LOGGING=MASKED_CFG):
            assert check_masking_configured(None) == []

    def test_ecsctx_skip_masking_check_setting_wins(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")
        with override_settings(LOGGING=UNMASKED_CFG, ECSCTX_SKIP_MASKING_CHECK=True):
            assert check_masking_configured(None) == []

    def test_env_var_value_is_matched_case_insensitively(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "LOCAL")
        with override_settings(LOGGING=UNMASKED_CFG):
            assert check_masking_configured(None) == []

    def test_skip_envs_entries_are_matched_case_insensitively(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "staging")
        with override_settings(
            LOGGING=UNMASKED_CFG, ECSCTX_MASKING_CHECK_SKIP_ENVS=["Staging"]
        ):
            assert check_masking_configured(None) == []

    def test_custom_env_var_and_skip_envs(self, monkeypatch):
        monkeypatch.setenv("APP_ENV", "staging")
        with override_settings(
            LOGGING=UNMASKED_CFG,
            ECSCTX_MASKING_CHECK_ENV_VAR="APP_ENV",
            ECSCTX_MASKING_CHECK_SKIP_ENVS=["staging"],
        ):
            assert check_masking_configured(None) == []

    def test_custom_skip_envs_still_flags_other_envs(self, monkeypatch):
        monkeypatch.setenv("APP_ENV", "production")
        with override_settings(
            LOGGING=UNMASKED_CFG,
            ECSCTX_MASKING_CHECK_ENV_VAR="APP_ENV",
            ECSCTX_MASKING_CHECK_SKIP_ENVS=["staging"],
        ):
            errors = check_masking_configured(None)
        assert len(errors) == 1


class TestEveryEntryPointSeesBothHalves:
    """find_masking_errors() sums the dict and live checks, and all three
    entry points go through it — so a clean LOGGING dict cannot mask a live
    tree problem. Kept apart from the classes above, which stub the live half
    out to pin dict-level behaviour."""

    @pytest.fixture(autouse=True)
    def _unlisted_shipping_logger(self, logging_state):
        logging.getLogger("ecsctx-both-halves").addHandler(
            logging.FileHandler(os.devnull)
        )

    def test_find_masking_errors_sums_both(self):
        assert find_masking_errors(MASKED_CFG) == find_unmasked_live_handlers(MASKED_CFG)
        assert any("ecsctx-both-halves" in e for e in find_masking_errors(MASKED_CFG))

    def test_system_check_reports_it(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")
        with override_settings(LOGGING=MASKED_CFG):
            errors = check_masking_configured(None)
        assert any("ecsctx-both-halves" in error.msg for error in errors)
        assert all(isinstance(error, Error) for error in errors)

    def test_validate_raises_on_it(self):
        with pytest.raises(ValueError, match="ecsctx-both-halves"):
            validate_masking_config(MASKED_CFG)

    def test_assert_raises_on_it(self):
        with pytest.raises(AssertionError, match="ecsctx-both-halves"):
            assert_no_masking_errors(MASKED_CFG)
