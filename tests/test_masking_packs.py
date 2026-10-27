"""Masking packs: which content rules run, and where the choice comes from.

Card and CVV content scanning (and the financial-id rules) cost every service
CPU and correlation fields, but only PCI services ever see such data, so they
are opt-in packs a PCI service enables in its logging config. The default pack
(credentials, PEM, JWT, email, phone) is always on.
"""

import logging
import random

import pytest

from ecsctx.contrib.django import get_logging_config
from ecsctx.contrib.django.checks import find_unmasked_live_handlers
from ecsctx.masking.config import (
    _reset_masking_config,
    configure_masking_packs,
    configure_masking_safe_keys,
    get_masking_packs,
    get_masking_safe_keys,
    masking_safe_key_errors,
)
from ecsctx.masking.exemptions import configure_masking
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS, RULES, classify_key
from ecsctx.processors import mask_pan
from tests.conftest import skip_if_safe


@pytest.fixture(autouse=True)
def _reset_packs():
    yield
    _reset_masking_config()


def _mask(msg, packs=None):
    record = logging.LogRecord("t", logging.INFO, __file__, 0, msg, None, None)
    MaskPIIFilter(packs=packs).filter(record)
    return record.msg


class TestPacks:
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
    """The one key name a pack gates. Every other name is a case in
    ecsctx.masking.samples, where it is masked in any service."""

    DEFAULT = frozenset({"default"})

    def test_payment_id_keys_follow_the_financial_ids_pack(self):
        assert classify_key("transaction_id", self.DEFAULT) is None
        assert classify_key("transaction_id", self.DEFAULT | {"financial_ids"}) == "payment_id"


class TestConfiguredSafeKeys:
    """Key names a service lists because its payloads use them for things that
    are not PII (ECSCTX_MASK_SAFE_KEYS). ecsctx itself ships only names that
    mean the same in every service; the rest is each service's to list."""

    def test_none_by_default(self, monkeypatch):
        monkeypatch.delenv("ECSCTX_MASK_SAFE_KEYS", raising=False)
        assert get_masking_safe_keys() == frozenset()

    def test_env_lists_them(self, monkeypatch):
        monkeypatch.setenv("ECSCTX_MASK_SAFE_KEYS", "pg_name, X-Script-Name")
        assert get_masking_safe_keys() == {"pg_name", "x-script-name"}

    def test_django_setting_wins_over_env(self, monkeypatch, settings):
        monkeypatch.setenv("ECSCTX_MASK_SAFE_KEYS", "bank_name")
        settings.ECSCTX_MASK_SAFE_KEYS = ["pg_name"]
        assert get_masking_safe_keys() == {"pg_name"}

    def test_explicit_configuration_wins_over_settings(self, settings):
        settings.ECSCTX_MASK_SAFE_KEYS = ["pg_name"]
        configure_masking_safe_keys(["bank_name"])
        assert get_masking_safe_keys() == {"bank_name"}

    def test_a_listed_key_is_not_masked(self):
        configure_masking_safe_keys(["pg_name"])
        assert _mask({"pg_name": "mpgs", "payer_name": "Jane"}) == {
            "pg_name": "mpgs",
            "payer_name": "[NAME-MASKED]",
        }

    def test_a_listed_key_keeps_its_value_inside_a_pii_container(self):
        configure_masking_safe_keys(["pg_name"])
        out = _mask({"customer": {"pg_name": "mpgs", "note": "vip"}})
        assert out["customer"] == {"pg_name": "mpgs", "note": "[GENERIC-MASKED]"}

    def test_a_listed_keys_value_is_still_scanned(self):
        configure_masking_safe_keys(["pg_name"])
        assert _mask({"pg_name": "a@b.com"}) == {"pg_name": "[EMAIL-MASKED]"}

    def test_the_decision_follows_a_reconfiguration(self, monkeypatch):
        monkeypatch.delenv("ECSCTX_MASK_SAFE_KEYS", raising=False)
        configure_masking_safe_keys(["pg_name"])
        assert _mask({"pg_name": "mpgs"}) == {"pg_name": "mpgs"}
        configure_masking_safe_keys(None)
        assert _mask({"pg_name": "mpgs"}) == {"pg_name": "[NAME-MASKED]"}

    def test_a_named_flag_about_a_cvv_can_be_listed(self):
        configure_masking_safe_keys(["cvv_required"])
        assert _mask({"cvv_required": True, "cvv": "123"}) == {
            "cvv_required": True,
            "cvv": "[CVV-MASKED]",
        }

    @pytest.mark.parametrize(
        "key",
        [
            "cvv",
            "CVC",
            "security_code",
            "card_cvv",
            "card",
            "card_number",
            "pan",
            "pan_no",
            "expiry",
            "exp_month",
            "expiry_month",
            "expiry_year",
            "cardExpiry",
            "password",
            "db_password",
            "api_key",
            "x-api-key",
            "oauth_token",
            "webhook_secret",
            "Authorization",
        ],
    )
    def test_a_card_cvv_expiry_or_credential_name_is_refused(self, key):
        """Listing one would switch off the mask PCI requires for it: any card
        or expiry key the classifier knows, and any name ending in a CVV or
        credential word — the name of the value itself."""
        with pytest.raises(ValueError, match="cannot be a safe key"):
            configure_masking_safe_keys([key])

    @pytest.mark.parametrize(
        "key", ["cvv_required", "cvv_required_for_card_payment", "tokenization_status", "pg_name", "card_id"]
    )
    def test_a_flag_or_status_about_one_can_be_listed(self, key):
        configure_masking_safe_keys([key])
        assert get_masking_safe_keys() == {key.lower()}

    @pytest.mark.parametrize("value", [True, {"pg_name": 1}, [["pg_name"]]])
    def test_a_malformed_setting_never_breaks_a_log_line(self, settings, value):
        settings.ECSCTX_MASK_SAFE_KEYS = value
        get_masking_safe_keys()
        assert _mask({"payer_name": "Jane"}) == {"payer_name": "[NAME-MASKED]"}

    def test_a_refused_name_in_the_setting_is_ignored_and_reported(self, settings):
        settings.ECSCTX_MASK_SAFE_KEYS = ["cvv", "pg_name"]
        with pytest.warns(RuntimeWarning, match="cvv"):
            assert get_masking_safe_keys() == {"pg_name"}
        assert _mask({"cvv": "123"}) == {"cvv": "[CVV-MASKED]"}
        [error] = masking_safe_key_errors()
        assert "cvv" in error


class TestBoundariesAndTruncation:
    def test_mask_pan_agrees_with_the_rule(self):
        assert mask_pan("4111111111111111") == "411111******1111"
        assert mask_pan("378282246310005") == "378282*****0005"
        assert mask_pan("5018123456789") == "*********6789"


class TestStructuralFields:
    def test_correlation_ids_and_ecsctx_metadata_are_not_scanned(self):
        event = {
            "session_id": "4111111111111111",
            "trace": {"id": "4111111111111111"},
            "span": {"id": "5551234567"},
            "service": {"name": "app"},
            "project": {"name": "connect"},
        }
        assert MaskPIIFilter(packs=ALL_PACKS)._mask_dict(dict(event)) == event

    def test_labels_and_the_rest_of_the_record_are_scanned(self):
        masked = MaskPIIFilter()._mask_dict(
            {
                "labels": {"namespace": "cybersource", "customer_email": "jane@example.com"},
                "user": {"id": "7", "name": "admin", "email": "a@b.co"},
                "url": {"full": "https://h/p?e=a@b.co"},
            }
        )
        assert masked == {
            "labels": {"namespace": "cybersource", "customer_email": "[EMAIL-MASKED]"},
            "user": {"id": "7", "name": "admin", "email": "[EMAIL-MASKED]"},
            "url": {"full": "https://h/p?e=[EMAIL-MASKED]"},
        }


class TestExemptionPaths:
    def test_a_container_relative_exemption_applies_anywhere_below(self):
        skip_if_safe("name")
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
        from ecsctx.masking.samples import CREDENTIAL_MASKED_CASES, NOT_MASKED

        samples = [case[1] for case in CREDENTIAL_MASKED_CASES if isinstance(case[1], str)]
        samples += [case[1] for case in NOT_MASKED if isinstance(case[1], str)]
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
