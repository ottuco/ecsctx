"""Tests for chain integrations and SentryIntegration (#158767).

Sentry's LoggingIntegration reads the raw pre-formatter ``record.msg`` — a
dict repr with unmasked top-level containers. ecsctx.contrib.sentry replaces
that path: SentryIntegration installs mask_sensitive_data + SentryProcessor
into the native chain, before error_ecs_fields (exc_info must still be alive
for exception attachment). Core stays vendor-neutral — it only folds
ChainIntegration objects over the default chain.
"""

import importlib
import logging
import sys

import pytest
import sentry_sdk
import structlog
from structlog_sentry import SentryProcessor

from ecsctx.contrib.django.logging import (
    configure_structlog,
    default_processors,
    setup_logging,
)
from ecsctx.contrib.sentry import SentryIntegration


def _names(processors):
    return [getattr(p, "__name__", type(p).__name__) for p in processors]


@pytest.fixture(autouse=True)
def restore_structlog_config():
    yield
    configure_structlog()


@pytest.fixture
def sentry_captured():
    captured = []

    def grab(event, hint):
        captured.append(event)
        return None

    sentry_sdk.init(
        dsn="http://key@localhost:9/1",
        default_integrations=False,
        auto_enabling_integrations=False,
        before_send=grab,
    )
    # Breadcrumbs live on the isolation scope, which outlives init() — without
    # this every test inherits the crumbs of the ones before it.
    sentry_sdk.get_isolation_scope().clear_breadcrumbs()
    yield captured
    sentry_sdk.init(dsn="")


PRE_0_6_0_CHAIN = [
    "merge_contextvars",
    "contextvars_injector",
    "add_log_level",
    "add_logger_name",
    "PositionalArgumentsFormatter",
    "CallsiteParameterAdder",
    "callsite_ecs_fields",
    "error_ecs_fields",
    "TimeStamper",
    "StackInfoRenderer",
    "ExceptionRenderer",
    "ExceptionRenderer",  # structlog's format_exc_info is an ExceptionRenderer
    "wrap_for_formatter",
]


class TestDefaultChainUnchanged:
    def test_default_chain_identical_to_pre_0_6_0(self):
        configure_structlog()
        assert _names(structlog.get_config()["processors"]) == PRE_0_6_0_CHAIN

    def test_empty_integrations_chain_unchanged(self):
        configure_structlog(integrations=[])
        assert _names(structlog.get_config()["processors"]) == PRE_0_6_0_CHAIN

    def test_setup_logging_default_unchanged(self):
        setup_logging(capture_warnings=False)
        assert _names(structlog.get_config()["processors"]) == PRE_0_6_0_CHAIN


class TestIntegrationFold:
    def test_integrations_applied_in_order(self):
        class Tagger:
            def __init__(self, tag):
                self.tag = tag

            def install(self, processors):
                def tap(logger, method_name, event_dict):
                    return event_dict

                tap.__name__ = self.tag
                return [*processors, tap]

        configure_structlog(integrations=[Tagger("first_tap"), Tagger("second_tap")])
        names = _names(structlog.get_config()["processors"])
        assert names[-2:] == ["first_tap", "second_tap"]

    def test_setup_logging_passes_integrations(self):
        setup_logging(capture_warnings=False, integrations=[SentryIntegration()])
        assert "SentryProcessor" in _names(structlog.get_config()["processors"])


class TestSentryIntegrationInstall:
    def test_masking_then_sentry_before_error_ecs_fields(self):
        configure_structlog(integrations=[SentryIntegration()])
        names = _names(structlog.get_config()["processors"])
        i_mask = names.index("mask_sensitive_data")
        i_sentry = names.index("SentryProcessor")
        i_error = names.index("error_ecs_fields")
        assert i_mask == i_sentry - 1
        assert i_sentry == i_error - 1

    def test_install_does_not_mutate_input(self):
        chain = default_processors()
        before = list(chain)
        SentryIntegration().install(chain)
        assert chain == before

    def test_double_install_raises(self):
        installed = SentryIntegration().install(default_processors())
        with pytest.raises(ValueError, match="already installed"):
            SentryIntegration().install(installed)

    def test_chain_without_anchor_raises(self):
        with pytest.raises(ValueError, match="error_ecs_fields"):
            SentryIntegration().install([])

    def test_missing_structlog_sentry_raises(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "structlog_sentry", None)
        monkeypatch.delitem(sys.modules, "ecsctx.contrib.sentry", raising=False)
        monkeypatch.delitem(
            sys.modules, "ecsctx.contrib.sentry.integration", raising=False
        )
        with pytest.raises(ImportError, match=r"ecsctx\[sentry\]"):
            importlib.import_module("ecsctx.contrib.sentry")


class TestSentryEventContent:
    def test_message_is_event_string_and_data_masked(self, sentry_captured):
        configure_structlog(integrations=[SentryIntegration()])
        logger = structlog.get_logger("sentrytest.masked")

        logger.error(
            "gateway call failed",
            headers={"Authorization": "Bearer RAW-TOKEN-123"},
        )

        [event] = sentry_captured
        assert event["message"] == "gateway call failed"
        assert event["contexts"]["structlog"]["headers"] == {
            "Authorization": "[SECRET-MASKED]"
        }

    def test_exception_attached_from_exc_info(self, sentry_captured):
        configure_structlog(integrations=[SentryIntegration()])
        logger = structlog.get_logger("sentrytest.exc")

        try:
            1 / 0
        except ZeroDivisionError:
            logger.error("division blew up", exc_info=True)

        [event] = sentry_captured
        assert event["exception"]["values"][0]["type"] == "ZeroDivisionError"
        assert event["message"] == "division blew up"

    def test_error_ecs_fields_still_runs_after_sentry(self, sentry_captured):
        """exc_info must survive SentryProcessor so the ES line keeps error.*"""
        configure_structlog(integrations=[SentryIntegration()])

        records = []
        handler = logging.Handler()
        handler.emit = records.append
        stdlib_logger = logging.getLogger("sentrytest.esline")
        stdlib_logger.addHandler(handler)
        try:
            logger = structlog.get_logger("sentrytest.esline")
            try:
                1 / 0
            except ZeroDivisionError:
                logger.error("division blew up again", exc_info=True)
        finally:
            stdlib_logger.removeHandler(handler)

        [record] = records
        error = record.msg["error"]
        assert error["type"] == "ZeroDivisionError"
        assert "1 / 0" in error["stack_trace"]

    def test_custom_event_level(self, sentry_captured):
        configure_structlog(
            integrations=[SentryIntegration(event_level=logging.WARNING)]
        )
        logger = structlog.get_logger("sentrytest.warnlevel")

        logger.warning("suspicious but not fatal")

        [event] = sentry_captured
        assert event["message"] == "suspicious but not fatal"

    def test_info_level_does_not_send_event(self, sentry_captured):
        configure_structlog(integrations=[SentryIntegration()])
        logger = structlog.get_logger("sentrytest.info")

        logger.info("routine line")

        assert sentry_captured == []

    def test_stdlib_foreign_logger_not_captured(self, sentry_captured):
        """Documented scope: SentryIntegration covers the native chain only.

        Foreign records go through get_logging_config()'s foreign_pre_chain,
        which SentryIntegration does not touch (see README). This pins that
        boundary so a future foreign-chain integration changes it knowingly.
        """
        configure_structlog(integrations=[SentryIntegration()])

        logging.getLogger("sentrytest.foreign").error("stdlib error line")

        assert sentry_captured == []


class TestIgnoreLoggers:
    """Unhandled Django exceptions must file one Sentry issue, not two (#158768).

    LoggingContextMiddleware.process_exception logs the exception for the log
    pipeline; DjangoIntegration captures the same exception natively off
    got_request_exception. Without a default ignore the chain would report it
    a second time.
    """

    def test_middleware_logger_ignored_by_default(self, sentry_captured):
        configure_structlog(integrations=[SentryIntegration()])
        logger = structlog.get_logger("ecsctx.contrib.django.middleware")

        try:
            raise ValueError("boom")
        except ValueError as exc:
            logger.exception("unhandled_exception", exc_info=exc)

        assert sentry_captured == []

    def test_other_loggers_still_captured(self, sentry_captured):
        configure_structlog(integrations=[SentryIntegration()])

        structlog.get_logger("core.gateway.acme").error("gateway_boom")

        [event] = sentry_captured
        assert event["message"] == "gateway_boom"

    def test_ignore_loggers_override(self, sentry_captured):
        configure_structlog(
            integrations=[SentryIntegration(ignore_loggers=["core.noisy"])]
        )

        structlog.get_logger("core.noisy").error("dropped")
        structlog.get_logger("ecsctx.contrib.django.middleware").error("kept")

        [event] = sentry_captured
        assert event["message"] == "kept"

    def test_empty_ignore_loggers_captures_everything(self, sentry_captured):
        configure_structlog(integrations=[SentryIntegration(ignore_loggers=())])

        structlog.get_logger("ecsctx.contrib.django.middleware").error("kept")

        [event] = sentry_captured
        assert event["message"] == "kept"


def _crumbs(event, *expected):
    """Breadcrumb messages, narrowed to the ones a test emitted itself.

    The buffer collects records from anything else logging in the process, so
    a test can only compare an exact list if it filters to its own messages
    first."""
    messages = [b["message"] for b in event.get("breadcrumbs", {}).get("values", [])]
    if not expected:
        return messages
    return [m for m in messages if m in set(expected)]


class TestBreadcrumbLevel:
    def test_default_breadcrumb_level_is_info(self):
        [processor] = [
            p
            for p in SentryIntegration().install(default_processors())
            if isinstance(p, SentryProcessor)
        ]
        assert processor.level == logging.INFO

    def test_breadcrumb_level_is_passed_through(self):
        [processor] = [
            p
            for p in SentryIntegration(level=logging.ERROR).install(
                default_processors()
            )
            if isinstance(p, SentryProcessor)
        ]
        assert processor.level == logging.ERROR

    def test_below_breadcrumb_level_records_nothing(self, sentry_captured):
        configure_structlog(
            integrations=[SentryIntegration(level=logging.ERROR)]
        )
        logger = structlog.get_logger("sentrytest.breadcrumbs")

        logger.info("routine line")
        logger.error("now it ships")

        [event] = sentry_captured
        # The event is captured before its own breadcrumb is recorded, so
        # only the sub-threshold line is what this asserts on.
        assert _crumbs(event, "routine line", "now it ships") == []

    def test_at_breadcrumb_level_records_crumb(self, sentry_captured):
        configure_structlog(integrations=[SentryIntegration(level=logging.INFO)])
        logger = structlog.get_logger("sentrytest.breadcrumbs")

        logger.info("routine line")
        logger.error("now it ships")

        [event] = sentry_captured
        assert _crumbs(event, "routine line", "now it ships") == ["routine line"]
