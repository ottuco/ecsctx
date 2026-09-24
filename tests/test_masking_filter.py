"""Tests for the MaskPIIFilter engine: content rules, key-name rules, and
the stdlib logging.Filter itself (ecsctx.masking.filters/patterns/tokens/
fields_rules).

The case tables live in ecsctx.masking.samples and run through
MaskingTestsMixin (tests/test_shipped_masking_suite.py). They are ported
from ottu_pg's tests/test_utils/test_log_filters.py — the filter ecsctx's
engine originated from — and re-verified against ecsctx's actual output.
Two deliberate differences from the original expectations:

* every masked value is a ``[LABEL]`` marker, not ``***`` / bare ``CARD-MASKED``;
* card numbers are truncated to first 6 + last 4 (#159795, PCI DSS 3.4.1),
  so a PAN renders as ``[CARD-MASKED:112345******3456]`` — no token
  alongside, and a second pass leaves it untouched.

These run with PII tokenization unconfigured, so every label is the bare
``[LABEL]`` form. With PII configured the same rules emit
``[LABEL:ptok:v1:…]`` — covered separately in TestMaskByFieldType.
"""

import json
import logging
import re

import pytest

from ecsctx.masking.fields_rules import FIELD_RULES, get_field_rule
from ecsctx.masking.filters import (
    DEFAULT_SKIP_KEYS,
    JSON_PARSE_LIMIT,
    STRUCTURAL_ECS_KEYS,
    MaskPIIFilter,
    is_masked_object,
)
from ecsctx.masking.patterns import (
    ALL_PACKS,
    SAFE_KEYS,
    check_if_sensitive_keyword,
    mask_by_all_patterns,
)
from ecsctx.masking.samples import OVER_MASKED_BECAUSE_OF_CVV
from ecsctx.masking.tokens import (
    already_masked,
    make_label,
    mask_by_field_type,
    safe_tokenize,
)
from ecsctx.pii import configure_pii
from tests.conftest import skip_if_safe


def _mask(msg):
    """Run a message through MaskPIIFilter with every pack on, and return the
    (mutated) record.msg."""
    record = logging.LogRecord("test", logging.INFO, __file__, 0, msg, None, None)
    MaskPIIFilter(packs=ALL_PACKS).filter(record)
    return record.msg


class TestCheckIfSensitiveKeyword:
    @pytest.mark.parametrize(
        "key,expected",
        [
            ("cvv", "cvv"),
            ("cvc", "cvv"),
            ("security_code", "cvv"),
            ("api_key", "secret"),
            ("Authorization", "secret"),
            ("payment_id", "payment_id"),
            ("transaction_id", "payment_id"),
            ("email", "email"),
            ("customer_email", "email"),  # "email" wins over "customer" (generic)
            ("phone", "phone"),
            ("mobile", "phone"),
            ("address", "address"),
            ("name", "name"),
            ("cardholder", "name"),
            ("customer_name", "name"),  # "name" wins over "customer" (generic)
            ("billing", "generic"),
            ("customer", "generic"),
            ("random_field", None),
        ],
    )
    def test_keyword_mapping(self, key, expected):
        assert check_if_sensitive_keyword(key) == expected

    def test_case_insensitive(self):
        assert check_if_sensitive_keyword("EMAIL") == "email"

    @pytest.mark.parametrize("key", sorted(SAFE_KEYS))
    def test_safe_keys_whitelisted(self, key):
        assert check_if_sensitive_keyword(key) is None

    def test_bare_key_not_over_masked(self):
        """Bare "key" is intentionally excluded from the credential pattern —
        only sensitive *_key compounds are — so cache_key/sort_key/primary_key
        aren't over-masked."""
        assert check_if_sensitive_keyword("cache_key") is None
        assert check_if_sensitive_keyword("sort_key") is None
        assert check_if_sensitive_keyword("secret_key") == "secret"


class TestFieldRules:
    @pytest.mark.parametrize("field_type", ["cvv", "card", "expiry"])
    def test_cardholder_data_is_neither_tokenized_nor_exemptable(self, field_type):
        rule = get_field_rule(field_type)
        assert rule.tokenizable is False
        assert rule.exemptable is False

    @pytest.mark.parametrize(
        "field_type", ["secret", "payment_id", "pem_key", "iban", "jwt", "ssn"]
    )
    def test_secrets_tokenizable_not_exemptable(self, field_type):
        rule = get_field_rule(field_type)
        assert rule.tokenizable is True
        assert rule.exemptable is False

    @pytest.mark.parametrize("field_type", ["email", "phone", "address", "name", "generic"])
    def test_pii_categories_tokenizable_and_exemptable(self, field_type):
        rule = get_field_rule(field_type)
        assert rule.tokenizable is True
        assert rule.exemptable is True

    def test_unknown_field_type_defaults_permissive(self):
        rule = get_field_rule("something_new")
        assert rule.field_type == "something_new"
        assert rule.tokenizable is True
        assert rule.exemptable is True

    def test_all_declared_rules_have_matching_field_type(self):
        for key, rule in FIELD_RULES.items():
            assert rule.field_type == key


class TestMakeLabelAndAlreadyMasked:
    def test_make_label_replaces_underscore(self):
        assert make_label("payment_id") == "PAYMENT-ID-MASKED"
        assert make_label("email") == "EMAIL-MASKED"

    def test_already_masked_detects_bracket_and_token_forms(self):
        assert already_masked("[CVV-MASKED]")
        assert already_masked("[EMAIL-MASKED:ptok:v1:abc]")
        assert not already_masked("plain text")


class TestMaskByFieldType:
    def test_empty_value_still_labeled(self):
        assert mask_by_field_type("", "email") == "[EMAIL-MASKED]"

    def test_cvv_never_tokenized(self, token_keyset_path):
        """PCI forbids storing CVV in any form — not even an HMAC digest."""
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        assert mask_by_field_type("123", "cvv") == "[CVV-MASKED]"

    def test_tokenizable_field_gets_token_when_pii_configured(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        result = mask_by_field_type("user@example.com", "email")
        assert re.fullmatch(r"ptok:v1:[\w-]+", result)

    def test_tokenizable_field_falls_back_when_unconfigured(self):
        assert mask_by_field_type("user@example.com", "email") == "[EMAIL-MASKED]"

    def test_already_masked_value_passthrough(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        already = "[EMAIL-MASKED:ptok:v1:xyz]"
        assert mask_by_field_type(already, "email") == already

    def test_falls_back_to_bare_label_when_tokenization_raises(
        self, token_keyset_path, monkeypatch
    ):
        """Fail closed: if tokenize() blows up, emit the label alone — never
        the raw value, and never the [PII_REDACTED] sentinel embedded in a
        label."""
        configure_pii(token_keyset_path=token_keyset_path, env="test")

        def boom(_value, _field_type):
            raise RuntimeError("keyset unavailable")

        monkeypatch.setattr("ecsctx.masking.tokens._pii_tokenize", boom)
        assert safe_tokenize("user@example.com", "email") == "[PII_REDACTED]"
        assert mask_by_field_type("user@example.com", "email") == "[EMAIL-MASKED]"


_TOKEN = re.compile(r"ptok:v1:[\w-]+")


class TestTokensAreBare:
    """A tokenized value is the token itself, `ptok:v1:…`, as in 0.6.x. A
    `[LABEL]` is what stands where no token can: PII tokenization not
    configured or failing, or a type that is never tokenized (CVV, expiry, a
    truncated card)."""

    @pytest.fixture(autouse=True)
    def _pii(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")

    def test_a_masked_key_holds_the_bare_token(self):
        out = _mask({"customer_email": "user@example.com", "payer_name": "Jane"})
        assert _TOKEN.fullmatch(out["customer_email"])
        assert _TOKEN.fullmatch(out["payer_name"])

    def test_a_content_match_in_text_is_the_bare_token(self):
        out = _mask("contact user@example.com today")
        assert re.fullmatch(r"contact ptok:v1:[\w-]+ today", out)

    def test_the_same_value_gives_the_same_token_by_key_and_by_content(self):
        by_key = _mask({"customer_email": "user@example.com"})["customer_email"]
        assert _mask("mail user@example.com") == f"mail {by_key}"

    def test_what_is_never_tokenized_keeps_its_label(self):
        out = _mask({"cvv": "123", "expiry": "12/28", "card_number": "4111111111111111"})
        assert out == {
            "cvv": "[CVV-MASKED]",
            "expiry": "[EXPIRY-MASKED]",
            "card_number": "[CARD-MASKED:411111******1111]",
        }

    @pytest.mark.parametrize(
        "text",
        [
            "token=abcd1234",
            "token: abcd1234",
            "token abcd1234",
            '{"token": "abcd1234", "email": "user@example.com"}',
            "Bearer abcd1234efgh",
        ],
    )
    def test_masking_masked_text_again_changes_nothing(self, text):
        """The formatter's second pass, and a JSON body re-scanned as text,
        see tokens where the key rules put them: `ptok` must not be read as a
        credential value and masked again."""
        once = _mask(text)
        assert "abcd1234" not in once
        assert _mask(once) == once


def test_without_pii_configured_a_masked_key_holds_its_label():
    assert _mask({"customer_email": "user@example.com"}) == {"customer_email": "[EMAIL-MASKED]"}


class TestContentRules:
    """Spot checks on mask_by_all_patterns; the exhaustive per-rule tables
    live in ecsctx.masking.samples."""

    def test_email_regex_no_pipe_leak(self):
        """Regression: [A-Z|a-z] would let a literal '|' into the TLD."""
        assert mask_by_all_patterns("a@b.com") == "[EMAIL-MASKED]"

    def test_card_number_separators_dont_matter(self):
        spaced = mask_by_all_patterns("4111 1111 1111 1111")
        dashed = mask_by_all_patterns("4111-1111-1111-1111")
        assert spaced == dashed == "[CARD-MASKED:411111******1111]"

    def test_pem_key_reflow_produces_same_token(self, token_keyset_path):
        """Token computed over the base64 body only, so the same key
        re-wrapped at a different line width still matches."""
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        pem_a = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIB\nAAJBAK\n-----END RSA PRIVATE KEY-----"
        pem_b = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----"
        assert mask_by_all_patterns(pem_a) == mask_by_all_patterns(pem_b)

    def test_already_masked_text_is_a_noop(self):
        text = "[EMAIL-MASKED:ptok:v1:abc]"
        assert mask_by_all_patterns(text) == text


def test_cvv_never_carries_a_token_even_when_pii_configured(token_keyset_path):
    """The one field type that must never be correlatable."""
    configure_pii(token_keyset_path=token_keyset_path, env="test")
    assert _mask({"cvv": "123"}) == {"cvv": "[CVV-MASKED]"}
    assert _mask("cvv=123") == "cvv=[CVV-MASKED]"


def test_email_under_a_sensitive_parent_key_is_masked_as_an_email():
    """"contact" is a PII container (generic category): it keeps its shape and
    each field is masked on its own, so the email gets an email token that
    correlates with the same email anywhere else."""
    assert _mask({"contact": {"email": "user@example.com"}}) == {"contact": {"email": "[EMAIL-MASKED]"}}


def test_card_number_reveals_only_bin_and_last4():
    """The truncation contract (#159795), stated directly rather than only
    implied by the table above: first 6 + last 4 visible, full PAN gone,
    and the labeled output is stable under a second pass."""
    assert _mask("4111111111111111") == "[CARD-MASKED:411111******1111]"
    assert _mask("[CARD-MASKED:411111******1111]") == "[CARD-MASKED:411111******1111]"


# Open bug, so it runs here only, never in the shipped suite. Details in samples.py.
@pytest.mark.xfail(strict=True, reason="space-cascade bug: bare digit groups get masked as CVV")
@pytest.mark.parametrize(
    "label,sample", OVER_MASKED_BECAUSE_OF_CVV, ids=[g[0] for g in OVER_MASKED_BECAUSE_OF_CVV]
)
def test_over_masked_because_of_cvv(label, sample):
    assert _mask(sample) == sample


@pytest.mark.parametrize(
    "sample",
    [
        'body {"public_key": null, "a": 1}',
        'body {"session_key": 12345}',
        'data {"cvv": 123}',
    ],
)
def test_masked_json_text_still_parses(sample):
    assert json.loads(_mask(sample).split(" ", 1)[1])


# A PSP callback as a gateway view logs it: the raw request body, a JSON
# string, inside a dict (Connect, 19 Sep 2026). Shapes from ottu_pg's MPGS and
# CyberSource callbacks.
_CALLBACK_BODY = json.dumps({
    "operation": "purchase",
    "status": "error",
    "reference_number": "jade-o45CEG",
    "pg_response": {
        "result": "FAILURE",
        "sourceOfFunds": {
            "provided": {
                "card": {
                    "brand": "VISA",
                    "expiry": {"month": "1", "year": "28"},
                    "nameOnCard": "Jane Payer",
                    "number": "450875xxxxxx1019",
                }
            }
        },
    },
    "token": {"name_on_card": "Jane Payer", "expiry_month": "01", "brand": "Visa"},
})


class TestJsonTextIsMaskedByKey:
    """A JSON object or list logged as a string gets the key-name rules a dict
    gets. Before, only the content rules saw it, so a cardholder name or an
    expiry date inside a callback body reached the index in clear."""

    def test_a_callback_body_string_is_masked_as_the_same_dict_would_be(self):
        as_text = _mask({"http": {"request": {"body": {"body": _CALLBACK_BODY}}}})
        as_dict = _mask({"http": {"request": {"body": {"body": json.loads(_CALLBACK_BODY)}}}})
        body = json.loads(as_text["http"]["request"]["body"]["body"])
        assert body == as_dict["http"]["request"]["body"]["body"]
        # A card or token object is masked as one unit, as it is in a dict.
        assert body["pg_response"]["sourceOfFunds"]["provided"]["card"] == "[CARD-MASKED]"
        assert body["token"] == "[SECRET-MASKED]"
        # What is not sensitive is still there to debug with.
        assert body["operation"] == "purchase"
        assert body["status"] == "error"
        assert body["pg_response"]["result"] == "FAILURE"
        assert body["reference_number"] == "jade-o45CEG"

    @pytest.mark.parametrize(
        "key,value,expected",
        [
            ("nameOnCard", "Jane Payer", "[NAME-MASKED]"),
            ("name_on_card", "Jane Payer", "[NAME-MASKED]"),
            ("expiry", {"month": "1", "year": "28"}, "[EXPIRY-MASKED]"),
            ("expiry_month", "01", "[EXPIRY-MASKED]"),
            ("expiry_year", "39", "[EXPIRY-MASKED]"),
        ],
    )
    def test_keys_inside_a_json_string_are_masked(self, key, value, expected):
        out = _mask({"payload": json.dumps({"payer_details": {key: value}, "status": "ok"})})
        assert json.loads(out["payload"]) == {"payer_details": {key: expected}, "status": "ok"}

    def test_a_json_message_is_masked_by_key(self):
        out = _mask('{"customer": {"nameOnCard": "Jane Payer"}}')
        assert json.loads(out) == {"customer": {"nameOnCard": "[NAME-MASKED]"}}

    def test_record_skip_keys_do_not_apply_inside_a_json_message(self):
        """``log`` and ``service`` are skipped as ecsctx's own metadata at the
        top of a record, not in a payload that happens to use those names."""
        out = _mask('{"log": {"nameOnCard": "Jane Payer"}}')
        assert json.loads(out) == {"log": {"nameOnCard": "[NAME-MASKED]"}}

    def test_text_with_nothing_to_mask_by_key_is_left_as_written(self):
        sample = '{"status":"ok","count":3}'
        assert _mask(sample) == sample

    def test_content_rules_still_run_on_the_masked_text(self):
        """A card number logged as a JSON number is caught by the content
        rules, as it was when the string was only scanned as text."""
        out = _mask('{"nameOnCard": "Jane Payer", "ref": 4111111111111111}')
        assert out == '{"nameOnCard": "[NAME-MASKED]", "ref": [CARD-MASKED:411111******1111]}'

    def test_text_that_is_not_json_gets_the_content_rules_only(self):
        assert _mask("{not json} a@b.com") == "{not json} [EMAIL-MASKED]"

    def test_a_json_scalar_is_text(self):
        assert _mask('"a@b.com"') == '"[EMAIL-MASKED]"'

    def test_text_over_the_parse_limit_gets_the_content_rules_only(self):
        """Parsing is bounded: every string in every record reaches this path."""
        big = json.dumps({"nameOnCard": "Jane Payer", "pad": "x" * JSON_PARSE_LIMIT})
        assert _mask(big) == big


class TestMaskPIIFilterEngine:
    def test_dict_message_masked(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        flt = MaskPIIFilter()
        out = flt._mask_value({"customer_name": "John Doe", "amount": 5})
        assert re.fullmatch(r"ptok:v1:[\w-]+", out["customer_name"])
        assert out == {"customer_name": out["customer_name"], "amount": 5}

    def test_structural_ecs_keys_skipped_at_top_level_by_default(self):
        flt = MaskPIIFilter()
        out = flt._mask_value({"service": {"name": "app"}, "project": {"name": "connect"}})
        assert out["service"] == {"name": "app"}
        assert out["project"] == {"name": "connect"}

    def test_structural_ecs_keys_only_skipped_when_top_level(self):
        """The skip only applies at path == () — a nested "service" key is
        not special and gets content/key-name masked like anything else."""
        flt = MaskPIIFilter()
        out = flt._mask_value({"wrapper": {"service": "not really structural"}})
        assert out["wrapper"]["service"] == "not really structural"

    def test_custom_skip_keys_empty_masks_everything(self):
        skip_if_safe("name")
        flt = MaskPIIFilter(skip_keys=())
        out = flt._mask_value({"service": {"name": "John Doe should be masked"}})
        assert out["service"]["name"] != "John Doe should be masked"

    def test_default_skip_keys_cover_structural_and_correlation_keys(self):
        assert MaskPIIFilter()._skip_keys == DEFAULT_SKIP_KEYS
        assert STRUCTURAL_ECS_KEYS <= DEFAULT_SKIP_KEYS

    @pytest.mark.parametrize("container", [list, tuple, set])
    def test_iterable_container_type_is_preserved(self, container):
        """A tuple stays a tuple, a set stays a set — masking must not
        silently change the shape of a logged value."""
        out = MaskPIIFilter()._mask_value(container(["a@b.com"]))
        assert type(out) is container
        assert list(out) == ["[EMAIL-MASKED]"]

    @pytest.mark.parametrize("value", [10, 3.5, True, False, None])
    def test_primitives_untouched_at_content_level(self, value):
        assert MaskPIIFilter()._mask_value(value) is value

    def test_nested_containers_are_walked(self):
        out = MaskPIIFilter()._mask_value({"items": [{"notes": ["a@b.com"]}]})
        assert out["items"][0]["notes"][0] == "[EMAIL-MASKED]"


class TestPackageExports:
    """The masking surface is part of ecsctx's public API — a consuming
    project imports it straight from `ecsctx`."""

    @pytest.mark.parametrize(
        "name",
        [
            "MaskPIIFilter",
            "install_maskers",
            "uninstall_maskers",
            "configure_masking",
            "configure_masking_from_env",
            "safe_tokenize",
            "mask_sensitive_data",
        ],
    )
    def test_exported_from_package_root(self, name):
        import ecsctx

        assert hasattr(ecsctx, name)
        assert name in ecsctx.__all__

    def test_root_maskpiifilter_is_the_real_engine(self):
        import ecsctx

        assert ecsctx.MaskPIIFilter is MaskPIIFilter


class TestMaskPIIFilterAsLoggingFilter:
    def _record(self, msg, args=()):
        return logging.LogRecord(
            name="test", level=logging.INFO, pathname=__file__, lineno=1,
            msg=msg, args=args, exc_info=None,
        )

    def test_filter_masks_dict_record_msg(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        record = self._record({"customer_name": "Jane Doe"})
        MaskPIIFilter().filter(record)
        assert re.fullmatch(
            r"ptok:v1:[\w-]+", record.msg["customer_name"]
        )
        assert list(record.msg) == ["customer_name"]

    def test_filter_masks_string_record_msg(self):
        record = self._record("contact a@b.com please")
        MaskPIIFilter().filter(record)
        assert record.msg == "contact [EMAIL-MASKED] please"

    def test_filter_masks_positional_args(self):
        record = self._record("user %s signed in", args=("bob@example.com",))
        MaskPIIFilter().filter(record)
        assert record.args == ("[EMAIL-MASKED]",)

    def test_masked_like_fragment_does_not_suppress_masking(self):
        """Regression: a coincidental -MASKED] fragment (e.g. user-controlled
        text) must not skip content-regex masking for real PII in the same
        string."""
        record = self._record("ha-MASKED] contact me at attacker@evil.com")
        MaskPIIFilter().filter(record)
        assert record.msg == "ha-MASKED] contact me at [EMAIL-MASKED]"

    def test_second_regex_pass_over_masked_markers_is_a_noop(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        record = self._record("contact victim@example.com, card 4111111111111111")
        MaskPIIFilter(packs=ALL_PACKS).filter(record)
        once = record.msg
        assert "victim@example.com" not in once
        assert mask_by_all_patterns(once) == once

    def test_filter_marks_record_and_is_idempotent(self):
        record = self._record({"customer_name": "Jane Doe"})
        flt = MaskPIIFilter()
        assert not is_masked_object(record)
        flt.filter(record)
        assert is_masked_object(record)
        once = record.msg
        flt.filter(record)  # second pass must be a no-op
        assert record.msg is once

    def test_filter_returns_true(self):
        record = self._record("hello")
        assert MaskPIIFilter().filter(record) is True
