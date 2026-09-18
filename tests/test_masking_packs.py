"""Masking packs: which content rules run, and where the choice comes from.

Card and CVV content scanning (and the financial-id rules) cost every service
CPU and correlation fields, but only PCI services ever see such data, so they
are opt-in packs a PCI service enables in its logging config. The default pack
(credentials, PEM, JWT, email, phone) is always on.
"""

import logging

import pytest

from ecsctx.contrib.django import get_logging_config
from ecsctx.masking.config import (
    _reset_masking_config,
    configure_masking_packs,
    get_masking_packs,
)
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS, classify_key
from ecsctx.processors import mask_pan


@pytest.fixture(autouse=True)
def _reset_packs():
    yield
    _reset_masking_config()


def _mask(msg, packs=None):
    record = logging.LogRecord("t", logging.INFO, __file__, 0, msg, None, None)
    MaskPIIFilter(packs=packs).filter(record)
    return record.msg


class TestPacks:
    def test_default_pack_leaves_card_shaped_text_alone(self):
        text = "card 4111111111111111 cvv 123 HTTP 200 OK took 1500 ms"
        assert _mask(text) == text

    def test_pci_pack_truncates_the_pan_and_masks_the_cvv(self):
        assert _mask("card 4111111111111111 cvv 123", packs=("pci",)) == (
            "card [CARD-MASKED:411111******1111] cvv [CVV-MASKED]"
        )

    def test_pci_pack_masks_a_cvv_sent_with_a_saved_card_token(self):
        assert _mask("token=tok_9f8e7d cvv 123", packs=("pci",)) == (
            "token=[SECRET-MASKED] cvv [CVV-MASKED]"
        )

    def test_financial_ids_pack_masks_iban(self):
        assert _mask("iban GB33BUKB20201555555555", packs=("financial_ids",)) == (
            "iban [IBAN-MASKED]"
        )
        assert _mask("iban GB33BUKB20201555555555") == "iban GB33BUKB20201555555555"

    def test_default_pack_still_masks_email_and_bearer(self):
        assert _mask("a@b.co Bearer abc12345def") == "[EMAIL-MASKED] Bearer [SECRET-MASKED]"

    def test_all_packs_is_every_pack(self):
        assert ALL_PACKS == frozenset({"default", "pci", "financial_ids"})


class TestPackSelection:
    def test_packs_default_to_default_only(self, monkeypatch):
        monkeypatch.delenv("ECSCTX_MASKING_PACKS", raising=False)
        assert get_masking_packs() == frozenset({"default"})

    def test_env_selects_packs(self, monkeypatch):
        monkeypatch.setenv("ECSCTX_MASKING_PACKS", "pci, financial_ids")
        assert get_masking_packs() == frozenset({"default", "pci", "financial_ids"})

    def test_django_setting_wins_over_env(self, monkeypatch, settings):
        monkeypatch.setenv("ECSCTX_MASKING_PACKS", "financial_ids")
        settings.ECSCTX_MASKING_PACKS = ["pci"]
        assert get_masking_packs() == frozenset({"default", "pci"})

    def test_explicit_configuration_wins_over_settings(self, settings):
        settings.ECSCTX_MASKING_PACKS = ["pci"]
        configure_masking_packs(["financial_ids"])
        assert get_masking_packs() == frozenset({"default", "financial_ids"})

    def test_get_logging_config_selects_packs(self):
        get_logging_config(masking_packs=("pci",))
        assert get_masking_packs() == frozenset({"default", "pci"})

    def test_unknown_pack_is_rejected(self):
        with pytest.raises(ValueError, match="unknown masking pack"):
            configure_masking_packs(["pcii"])

    def test_filter_without_packs_follows_the_configuration(self):
        configure_masking_packs(["pci"])
        assert _mask("cvv 123") == "cvv [CVV-MASKED]"


class TestKeyNames:
    """Key names match by whole word (or a known glued spelling), never by a
    substring of an unrelated word, and the decision is cached per key."""

    DEFAULT = frozenset({"default"})

    @pytest.mark.parametrize(
        "key",
        [
            "namespace",
            "hostname",
            "filename",
            "telemetry",
            "hotel",
            "tokenization_status",
            "token_type",
            "card_id",
            "ip_address",
            "expires_in",
            "cache_key",
            "operation",
        ],
    )
    def test_unrelated_words_are_not_sensitive(self, key):
        assert classify_key(key, self.DEFAULT) is None

    @pytest.mark.parametrize(
        "key,expected",
        [
            ("first_name", "name"),
            ("cardHolderName", "name"),
            ("firstname", "name"),
            ("access_token", "secret"),
            ("cardtoken", "secret"),
            ("x-api-key", "secret"),
            ("apiKey", "secret"),
            ("Authorization", "secret"),
            ("client_secret", "secret"),
            ("cvv", "cvv"),
            ("cvv2", "cvv"),
            ("securityCode", "cvv"),
            ("security_code", "cvv"),
            ("card", "card"),
            ("pan", "card"),
            ("card_number", "card"),
            ("cardNumber", "card"),
            ("expiry", "expiry"),
            ("exp_month", "expiry"),
            ("expirationDate", "expiry"),
            ("cardExpiry", "expiry"),
            ("telephone", "phone"),
            ("mobile", "phone"),
            ("customer_email", "email"),
            ("billing_address", "address"),
            ("customer_ref", "generic"),
        ],
    )
    def test_sensitive_keys(self, key, expected):
        assert classify_key(key, self.DEFAULT) == expected

    def test_payment_id_keys_follow_the_financial_ids_pack(self):
        assert classify_key("transaction_id", self.DEFAULT) is None
        assert classify_key("transaction_id", self.DEFAULT | {"financial_ids"}) == "payment_id"

    def test_card_fields_are_masked_by_key_in_every_service(self):
        masked = _mask({"card_number": "4111 1111 1111 1111", "expiry": "12/27", "cvv": "123"})
        assert masked == {
            "card_number": "[CARD-MASKED:411111******1111]",
            "expiry": "[EXPIRY-MASKED]",
            "cvv": "[CVV-MASKED]",
        }

    def test_a_card_object_under_a_card_key_is_masked_whole(self):
        masked = _mask({"card": {"number": "4111111111111111", "expiry": {"month": "01", "year": "27"}}})
        assert masked == {"card": "[CARD-MASKED]"}

    def test_a_card_key_holding_no_pan_is_labelled_not_truncated(self):
        assert _mask({"pan": "n/a"}) == {"pan": "[CARD-MASKED]"}


class TestBoundariesAndTruncation:
    @pytest.mark.parametrize(
        "value",
        [
            "8231045567ab34cd9f0e1a2b3c4d5e6f7a8b9c0d",  # session_id: 10 digits, then hex
            "1726650000123456789abcdef0123456",  # trace.id: 19 digits, then hex
            "5551234567abc",  # phone-shaped run glued to letters
        ],
    )
    def test_a_digit_run_touching_letters_is_not_a_phone_or_pan(self, value):
        assert _mask(value, packs=ALL_PACKS) == value

    def test_a_pan_between_separators_is_still_truncated(self):
        assert _mask('"pan":"4111111111111111",', packs=("pci",)) == (
            '"pan":"[CARD-MASKED:411111******1111]",'
        )

    def test_a_short_pan_keeps_only_its_last_four(self):
        assert _mask("pay 5018123456789 ok", packs=("pci",)) == (
            "pay [CARD-MASKED:*********6789] ok"
        )

    def test_mask_pan_agrees_with_the_rule(self):
        assert mask_pan("4111111111111111") == "411111******1111"
        assert mask_pan("378282246310005") == "378282*****0005"
        assert mask_pan("5018123456789") == "*********6789"
