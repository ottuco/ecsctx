"""Masking bugs found adopting 0.7.x in Connect.

Each was present since 0.7.0 and hits every consumer: an exception passed as
``exc_info`` was turned into strings, a Django exemption setting could be
ignored, and a PII container (``customer``, ``billing``) was collapsed into one
string — losing the per-field tokens fraud correlation relies on, and turning
an object field into a string, which Elasticsearch rejects.
"""

import logging
import re
import sys

import pytest
import sentry_sdk
import structlog

from ecsctx.contrib.django.logging import configure_structlog
from ecsctx.contrib.sentry import SentryIntegration
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.pii import configure_pii, tokenize


def _caught():
    try:
        1 / 0
    except ZeroDivisionError as error:
        return error, sys.exc_info()


class TestExceptionsAreNotMasked:
    def test_an_exception_tuple_is_kept(self):
        _error, exc_info = _caught()
        assert MaskPIIFilter()._mask_dict({"event": "x", "exc_info": exc_info})["exc_info"] is exc_info

    def test_an_exception_instance_is_kept(self):
        error, _ = _caught()
        assert MaskPIIFilter()._mask_dict({"event": "x", "exc_info": error})["exc_info"] is error

    def test_stack_info_is_kept(self):
        assert MaskPIIFilter()._mask_dict({"stack_info": "Stack (most recent call last): a@b.co"}) == {
            "stack_info": "Stack (most recent call last): a@b.co"
        }


@pytest.fixture
def sentry_captured():
    captured = []
    sentry_sdk.init(
        dsn="http://key@localhost:9/1",
        default_integrations=False,
        auto_enabling_integrations=False,
        before_send=lambda event, hint: captured.append(event),
    )
    sentry_sdk.get_isolation_scope().clear_breadcrumbs()
    yield captured
    sentry_sdk.init(dsn="")
    configure_structlog()


class TestSentryChainKeepsTheException:
    def test_a_caught_exception_passed_later_reaches_sentry_and_the_log_line(self, sentry_captured):
        configure_structlog(integrations=[SentryIntegration()])
        records = []
        handler = logging.Handler()
        handler.emit = records.append
        stdlib_logger = logging.getLogger("adoption.exc")
        stdlib_logger.addHandler(handler)
        error, _ = _caught()
        try:
            structlog.get_logger("adoption.exc").error("payment failed", exc_info=error)
        finally:
            stdlib_logger.removeHandler(handler)

        [event] = sentry_captured
        assert event["exception"]["values"][0]["type"] == "ZeroDivisionError"
        [record] = records
        assert record.msg["error"]["type"] == "ZeroDivisionError"
        assert "1 / 0" in record.msg["error"]["stack_trace"]


class TestExemptionSettingAppliesFirstTime:
    def test_a_record_masked_before_any_structlog_line_honours_the_setting(self, settings):
        settings.ECSCTX_MASK_EXEMPT_PATHS = ["payment_methods[*].name"]
        record = logging.LogRecord(
            "t", logging.INFO, __file__, 0, {"payment_methods": [{"name": "KNET"}]}, None, None
        )
        MaskPIIFilter().filter(record)
        assert record.msg == {"payment_methods": [{"name": "KNET"}]}


class TestPIIContainersKeepTheirShape:
    def test_connects_customer_context_keeps_id_and_per_field_tokens(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        email_token = tokenize("payer@example.com", "email")
        phone_token = tokenize("+96555551234", "phone")
        masked = MaskPIIFilter()._mask_dict(
            {"customer": {"id": 7, "email": email_token, "phone": phone_token, "image": "https://cdn/x.png"}}
        )
        customer = masked["customer"]
        assert customer["id"] == 7
        # Already tokens: left exactly as they are, bare.
        assert customer["email"] == email_token
        assert customer["phone"] == phone_token
        assert re.fullmatch(r"ptok:v1:[\w:.-]+", customer["image"])

    def test_the_same_email_gets_the_same_token_in_two_payments(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        first = MaskPIIFilter()._mask_dict({"customer": {"id": 1, "email": "payer@example.com"}})
        second = MaskPIIFilter()._mask_dict({"customer": {"id": 2, "email": "PAYER@example.com "}})
        assert first["customer"]["email"] == second["customer"]["email"]

    def test_every_leaf_of_an_address_container_is_masked(self):
        masked = MaskPIIFilter()._mask_dict(
            {"billing": {"line1": "1 Main St", "city": "Kuwait City", "zip": 12345}}
        )
        assert masked == {
            "billing": {"line1": "[GENERIC-MASKED]", "city": "[GENERIC-MASKED]", "zip": "[GENERIC-MASKED]"}
        }

    def test_a_card_inside_a_customer_keeps_its_shape_too(self):
        """The card resists the container's sweep -- its number truncates as a
        PAN rather than being tokenized as the customer's generic data -- but it
        is still walked, so expiry survives."""
        masked = MaskPIIFilter()._mask_dict(
            {"customer": {"id": 3, "card": {"number": "4111111111111111", "expiry": "12/27"}}}
        )
        assert masked == {
            "customer": {"id": 3, "card": {"number": "411111******1111", "expiry": "12/27"}}
        }

    def test_a_list_of_contacts_is_walked(self):
        masked = MaskPIIFilter()._mask_dict({"contacts": [{"name": "Jane", "email": "a@b.co"}]})
        assert masked == {"contacts": [{"name": "[NAME-MASKED]", "email": "[EMAIL-MASKED]"}]}

    def test_a_secret_container_is_still_masked_whole(self):
        assert MaskPIIFilter()._mask_dict({"credentials": {"user": "u", "password": "p"}}) == {
            "credentials": "[SECRET-MASKED]"
        }


class TestEmptyFields:
    def test_an_empty_container_field_stays_empty(self):
        assert MaskPIIFilter()._mask_dict({"customer": {"id": 1, "image": None}}) == {
            "customer": {"id": 1, "image": None}
        }
