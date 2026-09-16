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

# The exact messages the checks emit. Spelled out here so every assertion can
# compare whole values: a wording change has to be made deliberately in both
# places, and a test can never pass on a partial match of the wrong error.
MISSING_FILTER_ERROR = (
    "mask_pii_filter must be defined in LOGGING['filters'] for PCI DSS "
    "compliance. Add 'mask_pii_filter': "
    "{'()': 'ecsctx.masking.filters.MaskPIIFilter'} to filters — or use "
    "ecsctx.contrib.django.get_logging_config(), which does this "
    "automatically — or call ecsctx.masking.install_maskers() to sweep "
    "handlers built outside of LOGGING."
)

MISSING_DOTTED_PATH_ERROR = (
    "LOGGING['filters']['mask_pii_filter'] must define '()' as a dotted "
    "import path to a logging.Filter class, e.g. "
    "{'()': 'ecsctx.masking.filters.MaskPIIFilter'}."
)


def unresolvable_class_error(path):
    return (
        f"LOGGING['filters']['mask_pii_filter']['()'] ({path!r}) must resolve to "
        "ecsctx.masking.filters.MaskPIIFilter or a subclass of it."
    )


def unused_filter_error(*logger_names):
    return (
        "mask_pii_filter is defined but not used by logger(s): "
        + ", ".join(sorted(logger_names))
        + ". For PCI DSS compliance, every logger that reaches a shipping "
        "handler (anything other than logging.StreamHandler/"
        "logging.NullHandler) must carry mask_pii_filter itself, or only "
        "use handlers that do."
    )


def live_handlers_error(*entries):
    return (
        "Live logger(s) absent from LOGGING are reaching unmasked shipping "
        "handlers: " + ", ".join(entries) + ". These come from Django's own "
        "DEFAULT_LOGGING pass, or from a package that attaches handlers when "
        "it is imported — both happen outside settings.LOGGING. Name them in "
        "LOGGING['loggers'] so they get rebuilt with mask_pii_filter, or call "
        "ecsctx.masking.install_maskers() after logging setup to sweep them."
    )


class TestFindMaskingConfigErrors:
    def test_empty_config_is_nothing_to_validate(self):
        assert find_masking_config_errors({}) == []
        assert find_masking_config_errors(None) == []

    def test_missing_filter_definition_is_an_error(self):
        assert find_masking_config_errors(UNMASKED_CFG) == [MISSING_FILTER_ERROR]

    def test_filter_defined_and_used_is_clean(self):
        assert find_masking_config_errors(MASKED_CFG) == []

    def test_filter_defined_but_unused_by_a_shipping_logger(self):
        cfg = {
            "filters": {"mask_pii_filter": {"()": "ecsctx.masking.filters.MaskPIIFilter"}},
            "handlers": {"file": {"class": "logging.FileHandler", "filters": []}},
            "loggers": {"app": {"handlers": ["file"]}},
            "root": {"handlers": ["file"]},
        }
        assert find_masking_config_errors(cfg) == [unused_filter_error("app", "root")]

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
        assert find_masking_config_errors(cfg) == [unused_filter_error("app")]

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
        assert find_masking_config_errors(cfg) == [unresolvable_class_error("logging.Filter")]

    def test_filter_class_missing_dotted_path(self):
        cfg = {"filters": {"mask_pii_filter": {}}, "handlers": {}}
        assert find_masking_config_errors(cfg) == [MISSING_DOTTED_PATH_ERROR]

    def test_filter_class_unimportable_path_is_an_error(self):
        cfg = {"filters": {"mask_pii_filter": {"()": "no.such.module.Filter"}}, "handlers": {}}
        assert find_masking_config_errors(cfg) == [
            unresolvable_class_error("no.such.module.Filter")
        ]

    def test_filter_class_path_without_a_dot_is_an_error(self):
        cfg = {"filters": {"mask_pii_filter": {"()": "MaskPIIFilter"}}, "handlers": {}}
        assert find_masking_config_errors(cfg) == [unresolvable_class_error("MaskPIIFilter")]

    def test_filter_class_missing_from_a_real_module_is_an_error(self):
        """The module imports fine, the attribute just isn't there."""
        cfg = {"filters": {"mask_pii_filter": {"()": "logging.NoSuchFilter"}}, "handlers": {}}
        assert find_masking_config_errors(cfg) == [
            unresolvable_class_error("logging.NoSuchFilter")
        ]

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
    configured — only the live tree can.

    Every test here runs on an emptied tree (isolated_logging_tree), so the
    whole report can be compared for equality instead of searched for a
    substring — nothing is in it but what the test put there.
    """

    def _shipping_handler(self, logger_name):
        handler = logging.FileHandler(os.devnull)
        logging.getLogger(logger_name).addHandler(handler)
        return handler

    def _set_root_handlers(self, *handlers):
        """Assign rather than add: pytest re-attaches its own capture
        handlers to root after fixtures run, so a test that expects root in
        the report has to clear them from inside the test body."""
        logging.root.handlers = list(handlers)

    @pytest.mark.parametrize("flag", [True, False, None])
    def test_disable_existing_loggers_never_suppresses_the_scan(
        self, isolated_logging_tree, flag
    ):
        """The flag only disables loggers that existed when dictConfig ran —
        it says nothing about packages imported afterwards, which land in the
        tree either way. Scanning is unconditional; logger.disabled is what
        accounts for the flag's actual effect."""
        self._shipping_handler("ecsctx-live-flag")
        cfg = MASKED_CFG if flag is None else dict(MASKED_CFG, disable_existing_loggers=flag)
        assert find_unmasked_live_handlers(cfg) == [
            live_handlers_error("ecsctx-live-flag -> logging.FileHandler")
        ]

    @pytest.mark.parametrize("cfg", [{}, None])
    def test_scans_when_there_is_no_logging_dict_at_all(self, isolated_logging_tree, cfg):
        """No LOGGING means Django applied DEFAULT_LOGGING and then skipped
        the second pass entirely — its handlers are live and unmasked, which
        is precisely when the scan matters most."""
        self._set_root_handlers()
        self._shipping_handler("ecsctx-live-nocfg")
        assert find_unmasked_live_handlers(cfg) == [
            live_handlers_error("ecsctx-live-nocfg -> logging.FileHandler")
        ]

    def test_flags_unlisted_logger_with_a_shipping_handler(self, isolated_logging_tree):
        self._shipping_handler("ecsctx-live-unlisted")
        assert find_unmasked_live_handlers(MASKED_CFG) == [
            live_handlers_error("ecsctx-live-unlisted -> logging.FileHandler")
        ]

    def test_reports_every_offender_in_one_error_sorted_by_name(
        self, isolated_logging_tree
    ):
        self._shipping_handler("ecsctx-live-b")
        self._shipping_handler("ecsctx-live-a")
        assert find_unmasked_live_handlers(MASKED_CFG) == [
            live_handlers_error(
                "ecsctx-live-a -> logging.FileHandler",
                "ecsctx-live-b -> logging.FileHandler",
            )
        ]

    def test_reports_root_when_the_config_omits_it(self, isolated_logging_tree):
        self._set_root_handlers(logging.FileHandler(os.devnull))
        cfg = {k: v for k, v in MASKED_CFG.items() if k != "root"}
        assert find_unmasked_live_handlers(cfg) == [
            live_handlers_error("root -> logging.FileHandler")
        ]

    def test_ignores_root_when_the_config_declares_it(self, isolated_logging_tree):
        self._set_root_handlers(logging.FileHandler(os.devnull))
        assert find_unmasked_live_handlers(MASKED_CFG) == []

    def test_ignores_logger_named_in_the_config(self, isolated_logging_tree):
        self._shipping_handler("ecsctx-live-listed")
        cfg = dict(MASKED_CFG, loggers={"ecsctx-live-listed": {}})
        assert find_unmasked_live_handlers(cfg) == []

    def test_ignores_non_shipping_handler(self, isolated_logging_tree):
        logging.getLogger("ecsctx-live-console").addHandler(logging.StreamHandler())
        logging.getLogger("ecsctx-live-null").addHandler(logging.NullHandler())
        assert find_unmasked_live_handlers(MASKED_CFG) == []

    def test_ignores_handler_that_already_carries_the_masker(self, isolated_logging_tree):
        handler = self._shipping_handler("ecsctx-live-masked")
        handler.addFilter(MaskPIIFilter())
        assert find_unmasked_live_handlers(MASKED_CFG) == []

    def test_ignores_logger_that_carries_the_masker_itself(self, isolated_logging_tree):
        self._shipping_handler("ecsctx-live-logger-masked")
        logging.getLogger("ecsctx-live-logger-masked").addFilter(MaskPIIFilter())
        assert find_unmasked_live_handlers(MASKED_CFG) == []

    def test_ignores_disabled_logger(self, isolated_logging_tree):
        self._shipping_handler("ecsctx-live-off")
        logging.getLogger("ecsctx-live-off").disabled = True
        assert find_unmasked_live_handlers(MASKED_CFG) == []

    def test_clean_tree_reports_nothing(self, isolated_logging_tree):
        assert find_unmasked_live_handlers(MASKED_CFG) == []

    def test_catches_djangos_admin_email_handler(self, isolated_logging_tree):
        """The case this exists for: Django configures DEFAULT_LOGGING first,
        and with disable_existing_loggers off its 'django' logger survives
        with AdminEmailHandler attached, invisible to settings.LOGGING."""
        import logging.config

        from django.utils.log import DEFAULT_LOGGING

        cfg = get_logging_config()
        logging.config.dictConfig(DEFAULT_LOGGING)
        logging.config.dictConfig(cfg)

        assert find_unmasked_live_handlers(cfg) == [
            live_handlers_error("django -> django.utils.log.AdminEmailHandler")
        ]


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
        with pytest.raises(ValueError) as raised:
            validate_masking_config(UNMASKED_CFG)
        assert str(raised.value) == MISSING_FILTER_ERROR

    def test_validate_silent_when_clean(self):
        validate_masking_config(MASKED_CFG)  # must not raise

    def test_assert_raises_assertion_error(self):
        with pytest.raises(AssertionError) as raised:
            assert_no_masking_errors(UNMASKED_CFG)
        assert str(raised.value) == MISSING_FILTER_ERROR

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
        assert cfg["handlers"]["console"]["filters"] == ["correlation", "mask_pii_filter"]
        assert cfg["filters"] == {
            "correlation": {"()": "cid.log.CidContextFilter"},
            "mask_pii_filter": {"()": "ecsctx.masking.filters.MaskPIIFilter"},
        }


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
        assert [(e.id, e.msg) for e in errors] == [("ecsctx.E001", MISSING_FILTER_ERROR)]

    def test_not_skipped_in_production_by_default(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")
        with override_settings(LOGGING=UNMASKED_CFG):
            errors = check_masking_configured(None)
        assert [(e.id, e.msg) for e in errors] == [("ecsctx.E001", MISSING_FILTER_ERROR)]
        assert isinstance(errors[0], Error)

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
        assert [(e.id, e.msg) for e in errors] == [("ecsctx.E001", MISSING_FILTER_ERROR)]


class TestEveryEntryPointSeesBothHalves:
    """find_masking_errors() sums the dict and live checks, and all three
    entry points go through it — so a clean LOGGING dict cannot mask a live
    tree problem. Kept apart from the classes above, which stub the live half
    out to pin dict-level behaviour.

    Runs on an emptied tree so the one planted logger is the whole report."""

    LIVE_ERROR = None  # set in the fixture, once the handler exists

    @pytest.fixture(autouse=True)
    def _unlisted_shipping_logger(self, isolated_logging_tree):
        logging.getLogger("ecsctx-both-halves").addHandler(
            logging.FileHandler(os.devnull)
        )
        type(self).LIVE_ERROR = live_handlers_error(
            "ecsctx-both-halves -> logging.FileHandler"
        )

    def test_find_masking_errors_sums_both(self):
        """Clean dict, dirty tree: the sum is exactly the live half."""
        assert find_masking_errors(MASKED_CFG) == [self.LIVE_ERROR]

    def test_find_masking_errors_concatenates_dict_then_live(self):
        assert find_masking_errors(UNMASKED_CFG) == [
            MISSING_FILTER_ERROR,
            self.LIVE_ERROR,
        ]

    def test_system_check_reports_it(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")
        with override_settings(LOGGING=MASKED_CFG):
            errors = check_masking_configured(None)
        assert [(e.id, e.msg) for e in errors] == [("ecsctx.E001", self.LIVE_ERROR)]
        assert isinstance(errors[0], Error)

    def test_system_check_numbers_both_halves(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")
        with override_settings(LOGGING=UNMASKED_CFG):
            errors = check_masking_configured(None)
        assert [(e.id, e.msg) for e in errors] == [
            ("ecsctx.E001", MISSING_FILTER_ERROR),
            ("ecsctx.E002", self.LIVE_ERROR),
        ]

    def test_validate_raises_on_it(self):
        with pytest.raises(ValueError) as raised:
            validate_masking_config(MASKED_CFG)
        assert str(raised.value) == self.LIVE_ERROR

    def test_assert_raises_on_it(self):
        with pytest.raises(AssertionError) as raised:
            assert_no_masking_errors(MASKED_CFG)
        assert str(raised.value) == self.LIVE_ERROR
