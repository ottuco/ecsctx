"""Masking packs: which content rules run, and where the choice comes from.

Card and CVV content scanning (and the financial-id rules) cost every service
CPU and correlation fields, but only PCI services ever see such data, so they
are opt-in packs a PCI service enables in its logging config. The default pack
(credentials, PEM, JWT, email, phone) is always on.
"""

import logging
import random
from decimal import Decimal

import pytest

from ecsctx.contrib.django import get_logging_config
from ecsctx.contrib.django.checks import find_unmasked_live_handlers
from ecsctx.masking.config import (
    _reset_masking_config,
    configure_masking_packs,
    get_masking_packs,
)
from ecsctx.masking.exemptions import configure_masking
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS, RULES, classify_key
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


class TestStructuralFields:
    def test_structural_fields_are_not_scanned(self):
        event = {
            "session_id": "8231045567abcd",
            "trace": {"id": "4111111111111111"},
            "span": {"id": "5551234567"},
            "transaction": {"id": "4111111111111111"},
            "labels": {"namespace": "cybersource", "hostname": "jade", "customer": "x"},
            "user": {"id": "7", "name": "admin@jade.ottu.dev"},
            "http": {"request": {"method": "POST"}, "response": {"status_code": 200}},
            "url": {"domain": "a@b.co"},
            "service": {"name": "app"},
            "host": {"name": "jade", "ip": ["10.0.0.1"]},
        }
        assert MaskPIIFilter(packs=ALL_PACKS)._mask_dict(dict(event)) == event

    def test_the_rest_of_a_structural_parent_is_still_scanned(self):
        masked = MaskPIIFilter()._mask_dict(
            {"user": {"email": "a@b.co"}, "url": {"full": "https://h/p?e=a@b.co"}}
        )
        assert masked == {
            "user": {"email": "[EMAIL-MASKED]"},
            "url": {"full": "https://h/p?e=[EMAIL-MASKED]"},
        }

    def test_extra_skip_paths_come_from_settings(self, settings):
        settings.ECSCTX_MASK_SKIP_PATHS = ["payment.reference"]
        masked = MaskPIIFilter()._mask_dict({"payment": {"reference": "a@b.co", "note": "a@b.co"}})
        assert masked == {"payment": {"reference": "a@b.co", "note": "[EMAIL-MASKED]"}}


class TestExemptionPaths:
    def test_a_container_relative_exemption_applies_anywhere_below(self):
        configure_masking(exempt_paths=["payment_methods[*].name"])
        masked = MaskPIIFilter()._mask_dict(
            {"payload": {"payment_methods": [{"name": "KNET"}]}, "profile": {"name": "John"}}
        )
        assert masked == {
            "payload": {"payment_methods": [{"name": "KNET"}]},
            "profile": {"name": "[NAME-MASKED]"},
        }

    def test_a_root_relative_exemption_still_applies(self):
        configure_masking(exempt_paths=["payload.payment_methods[*].name"])
        masked = MaskPIIFilter()._mask_dict({"payload": {"payment_methods": [{"name": "KNET"}]}})
        assert masked == {"payload": {"payment_methods": [{"name": "KNET"}]}}


class TestArgs:
    def test_numeric_format_args_survive(self):
        record = logging.LogRecord(
            "t", logging.INFO, __file__, 0, "refunded %.3f of %d", (Decimal("12.5"), Decimal("3")), None
        )
        MaskPIIFilter().filter(record)
        assert record.getMessage() == "refunded 12.500 of 3"

    def test_an_object_whose_text_holds_pii_is_still_masked(self):
        class Holder:
            def __str__(self):
                return "owner a@b.co"

        record = logging.LogRecord("t", logging.INFO, __file__, 0, "%s", (Holder(),), None)
        MaskPIIFilter().filter(record)
        assert record.getMessage() == "owner [EMAIL-MASKED]"


class TestAdminEmailHandler:
    def _configure_like_django(self):
        import logging.config

        from django.utils.log import DEFAULT_LOGGING

        cfg = get_logging_config()
        logging.config.dictConfig(DEFAULT_LOGGING)
        logging.config.dictConfig(cfg)
        return cfg

    def test_sends_nothing_without_admins_so_is_not_flagged(self, isolated_logging_tree, settings):
        settings.ADMINS = []
        assert find_unmasked_live_handlers(self._configure_like_django()) == []

    def test_is_flagged_when_admins_would_receive_it(self, isolated_logging_tree, settings):
        settings.ADMINS = [("Ops", "ops@example.com")]
        errors = find_unmasked_live_handlers(self._configure_like_django())
        assert len(errors) == 1
        assert "django -> django.utils.log.AdminEmailHandler" in errors[0]


class TestCredentialScanMatchesFullScan:
    """The credential rules try only positions near a credential word; that
    must never change their output. Checked against pattern.sub on the
    ported samples and on generated text."""

    FRAGMENTS = (
        '"', "'", ":", "=", " ", "  ", "-", "_", ",", "{", "}", "\n",
        "token", "Token", "access_token", "x-api-key", "api_key", "apiKey", "Bearer",
        "basic", "Digest", "credentials", "Authorization", "authorisation_header",
        "secret", "client_secret", "password", "PASSWD", "key", "monkey", "keyboard",
        "tokenization", "abc123", "abcdefghij", "a1b2c3d4e5f6", "eyJhbGciOi.x.y",
        "12345678", "value", "İ", "straße", "==", "/+~.",
    )

    def _credential_rules(self):
        return [rule for rule in RULES if rule.scan is not None]

    def test_matches_on_generated_text(self):
        rng = random.Random(159795)
        rules = self._credential_rules()
        for _ in range(3000):
            text = "".join(rng.choice(self.FRAGMENTS) for _ in range(rng.randint(1, 14)))
            for rule in rules:
                assert rule.scan(rule.pattern, rule.repl, text) == rule.pattern.sub(rule.repl, text), (
                    rule.name,
                    text,
                )

    def test_matches_on_the_ported_samples(self):
        from tests.test_masking_filter import CREDENTIAL_MASKED_CASES, NOT_MASKED

        samples = [sample for _label, sample, _expected in CREDENTIAL_MASKED_CASES if isinstance(sample, str)]
        samples += [sample for _label, sample in NOT_MASKED if isinstance(sample, str)]
        for sample in samples:
            for rule in self._credential_rules():
                assert rule.scan(rule.pattern, rule.repl, sample) == rule.pattern.sub(rule.repl, sample)


class TestGatesNeverChangeAResult:
    """A gate may only skip a rule that could not have matched."""

    def test_each_rule_matches_the_same_with_and_without_its_gate(self):
        samples = [
            "EYJhbGciOiJIUzI1NiJ9.EYJzdWIiOiIxIn0.abcdefghij",
            "-----begin rsa private key-----\nMIIB\n-----end rsa private key-----",
            "CVV: 123", "Security Code 1234", "TRANSACTION_ID=abc12345xyz",
            "gb33BUKB20201555555555", "(555) 123-4567", "+965 5555 1234",
            "A@B.CO", "4111-1111-1111-1111", "123-45-6789", "call 123 now",
            "AUTHORIZATION: Bearer abc12345def", "Api-Key=abc123",
        ]
        for rule in RULES:
            for text in samples:
                gated = rule.gate(text, text.lower())
                if not gated:
                    assert rule.pattern.sub(rule.repl, text) == text, (rule.name, text)
