"""Tests for the MaskPIIFilter engine: content rules, key-name rules, and
the stdlib logging.Filter itself (ecsctx.masking.filters/patterns/tokens/
fields_rules).

The case tables below are ported from ottu_pg's tests/test_utils/
test_log_filters.py — the filter ecsctx's engine originated from — and
re-verified against ecsctx's actual output. Two deliberate differences from
the original expectations:

* every masked value is a ``[LABEL]`` marker, not ``***`` / bare ``CARD-MASKED``;
* card numbers are ALWAYS fully masked — ecsctx dropped the partial
  BIN/last-4 reveal, so a PAN the original rendered as ``112345******3456``
  is ``[CARD-MASKED]`` here.

These run with PII tokenization unconfigured, so every label is the bare
``[LABEL]`` form. With PII configured the same rules emit
``[LABEL:ptok:v1:…]`` — covered separately in TestMaskByFieldType.
"""

import logging
import re

import pytest

from ecsctx.masking.fields_rules import FIELD_RULES, get_field_rule
from ecsctx.masking.filters import (
    STRUCTURAL_ECS_KEYS,
    MaskPIIFilter,
    is_masked_object,
)
from ecsctx.masking.patterns import SAFE_KEYS, check_if_sensitive_keyword, mask_by_all_patterns
from ecsctx.masking.samples import (
    ACCEPTED_LEAK_CASES,
    CARD_CASES as CARD_NUMBER_CASES,
    CREDENTIAL_CASES as CREDENTIAL_MASKED_CASES,
    CVV_CASES as CVV_KEYWORD_CASES,
    DICT_KEY_CASES as DICT_KEY_VALUE_MASKING_CASES,
    EMAIL_CASES as EMAIL_MASKED_CASES,
    HEX as _HEX,
    IBAN_CASES as IBAN_MASKED_CASES,
    JWT as _JWT,
    JWT_CASES as JWT_MASKED_CASES,
    NOT_MASKED_CASES as NOT_MASKED,
    PAYMENT_ID_CASES as PAYMENT_ID_QUOTE_CASES,
    PEM_CASES as PEM_MASKED_CASES,
    PHONE_CASES as PHONE_MASKED_CASES,
    SSN_CASES as SSN_MASKED_CASES,
    SampleCard as _FakeCard,
    pem as _pem,
)
from ecsctx.masking.tokens import (
    already_masked,
    make_label,
    mask_by_field_type,
    safe_tokenize,
)
from ecsctx.pii import configure_pii


def _mask(msg):
    """Run a message through MaskPIIFilter and return the (mutated) record.msg."""
    record = logging.LogRecord("test", logging.INFO, __file__, 0, msg, None, None)
    MaskPIIFilter().filter(record)
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
    def test_cvv_not_tokenizable_not_exemptable(self):
        rule = get_field_rule("cvv")
        assert rule.tokenizable is False
        assert rule.exemptable is False

    @pytest.mark.parametrize(
        "field_type", ["secret", "payment_id", "card", "pem_key", "iban", "jwt", "ssn"]
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
        assert re.fullmatch(r"\[EMAIL-MASKED:ptok:v1:[\w-]+\]", result)

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


class TestContentRules:
    """Spot checks on mask_by_all_patterns; the exhaustive per-rule tables
    live in the ported case groups further down."""

    def test_email_regex_no_pipe_leak(self):
        """Regression: [A-Z|a-z] would let a literal '|' into the TLD."""
        assert mask_by_all_patterns("a@b.com") == "[EMAIL-MASKED]"

    def test_card_number_separators_dont_matter(self):
        spaced = mask_by_all_patterns("4111 1111 1111 1111")
        dashed = mask_by_all_patterns("4111-1111-1111-1111")
        assert spaced == dashed == "[CARD-MASKED]"

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


# ---------------------------------------------------------------------------
# PEM key blocks. Mask ANY type (PRIVATE / RSA PRIVATE / EC PRIVATE /
# PUBLIC / ...) — enumerating variants is a losing game, so the filter
# matches the whole "-----BEGIN ... KEY----- ... -----END ... KEY-----"
# envelope. Public keys aren't secret, but masking them too is the safe
# direction and future-proofs new key types.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "label,sample,expected", PEM_MASKED_CASES, ids=[c[0] for c in PEM_MASKED_CASES]
)
def test_masks_pem_key_blocks(label, sample, expected):
    assert _mask(sample) == expected


# ---------------------------------------------------------------------------
# Credential keywords (_CRED_KEYWORD): bearer/basic/api_key/token/secret/
# password/*_key compounds/credentials, across all three separator forms
# (quoted key, ":"/"=", bare space) and every realistic shape a header/token
# lands in — bare value, full "Authorization:" line, lowercase scheme,
# interpolated into a message, nested inside a logged `headers` dict, and
# short/single-char/single-digit values. Exact match, not "secret not in
# output" — that weaker check can't tell "masked correctly" from "masked
# into garbage".
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "label,sample,expected",
    CREDENTIAL_MASKED_CASES,
    ids=[c[0] for c in CREDENTIAL_MASKED_CASES],
)
def test_masks_credential_keywords(label, sample, expected):
    assert _mask(sample) == expected


# ---------------------------------------------------------------------------
# CVV/CVC/security-code rules (_CVV_KEYWORD): quoted key, ":"/"=", and mixed
# casing, same 3-rule shape as the credential rules above. Never tokenized —
# PCI forbids storing a CVV in any form, so [CVV-MASKED] is always final.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "label,sample,expected", CVV_KEYWORD_CASES, ids=[c[0] for c in CVV_KEYWORD_CASES]
)
def test_cvv_keyword_masking(label, sample, expected):
    assert _mask(sample) == expected


def test_cvv_never_carries_a_token_even_when_pii_configured(token_keyset_path):
    """The one field type that must never be correlatable."""
    configure_pii(token_keyset_path=token_keyset_path, env="test")
    assert _mask({"cvv": "123"}) == {"cvv": "[CVV-MASKED]"}
    assert _mask("cvv=123") == "cvv=[CVV-MASKED]"


# ---------------------------------------------------------------------------
# Payment/transaction/auth id — bare, quoted-key, and dict forms.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "label,sample,expected",
    PAYMENT_ID_QUOTE_CASES,
    ids=[c[0] for c in PAYMENT_ID_QUOTE_CASES],
)
def test_payment_id_quote_masking(label, sample, expected):
    assert _mask(sample) == expected


# ---------------------------------------------------------------------------
# IBAN (bank account numbers). Must be masked before the card-number rules
# run: several real IBAN formats have a long, letter-free digit run (check
# digits + BBAN) that falls inside the card rules' 12-19-digit body and
# would otherwise get caught as if it were a PAN.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "label,sample,expected", IBAN_MASKED_CASES, ids=[c[0] for c in IBAN_MASKED_CASES]
)
def test_masks_iban(label, sample, expected):
    assert _mask(sample) == expected


# ---------------------------------------------------------------------------
# Phone numbers. Runs before the card rules: a purely numeric value in the
# card rules' 12-19-digit range would otherwise be claimed as a PAN.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "label,sample,expected", PHONE_MASKED_CASES, ids=[c[0] for c in PHONE_MASKED_CASES]
)
def test_masks_phone(label, sample, expected):
    assert _mask(sample) == expected


# ---------------------------------------------------------------------------
# Email addresses. No keyword needed — matched purely by shape
# (local@domain.tld), so it works the same whether it's a bare string, a
# real dict value, or nested inside a quoted/JSON-shaped key:value pair.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "label,sample,expected", EMAIL_MASKED_CASES, ids=[c[0] for c in EMAIL_MASKED_CASES]
)
def test_masks_email(label, sample, expected):
    assert _mask(sample) == expected


def test_email_under_a_sensitive_parent_key_is_blanket_masked():
    """Diverges from the ported source on purpose: "contact" is itself a
    sensitive key in ecsctx (generic PII category), so the whole subtree is
    replaced rather than recursed into and masked leaf-by-leaf. The email
    never survives either way."""
    assert _mask({"contact": {"email": "user@example.com"}}) == {"contact": "[GENERIC-MASKED]"}


# ---------------------------------------------------------------------------
# Bare JWT — standalone secret with no keyword/scheme in front (the
# keyworded forms, e.g. "token:<jwt>" / "Bearer <jwt>", are covered by the
# credential rules above).
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "label,sample,expected", JWT_MASKED_CASES, ids=[c[0] for c in JWT_MASKED_CASES]
)
def test_masks_jwt(label, sample, expected):
    assert _mask(sample) == expected


# ---------------------------------------------------------------------------
# Card numbers (PAN), 12-19 digits, dash/space separators. ecsctx always
# masks the WHOLE number — the leading digit no longer changes the outcome
# and no BIN/last-4 is ever revealed, so every row below collapses to one
# [CARD-MASKED]. (The ported source revealed first-6/last-4 for any leading
# digit other than 9; that partial reveal was deliberately dropped.)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "label,sample,expected", CARD_NUMBER_CASES, ids=[c[0] for c in CARD_NUMBER_CASES]
)
def test_card_number_masking(label, sample, expected):
    assert str(_mask(sample)) == expected


def test_card_number_never_reveals_bin_or_last4():
    """The partial-reveal drop, stated directly rather than only implied by
    the table above."""
    assert _mask("4111111111111111") == "[CARD-MASKED]"


# ---------------------------------------------------------------------------
# SSN. Runs before standalone-CVV (the loosest rule of all — any bare 3-4
# digit group): a space-separated SSN's outer groups ("123" and "6789") are
# each individually CVV-standalone-shaped, so without this order it would
# fragment instead of masking as one SSN.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "label,sample,expected", SSN_MASKED_CASES, ids=[c[0] for c in SSN_MASKED_CASES]
)
def test_masks_ssn(label, sample, expected):
    assert _mask(sample) == expected


# ---------------------------------------------------------------------------
# _mask_dict's key-name check: a dict key that is itself a sensitive keyword
# masks its whole value outright, regardless of type/content — this is what
# makes a bare structlog kwarg (log.info(..., token="abcd1234")) get masked,
# since the content rules never see key and value joined into one string.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "label,sample,expected",
    DICT_KEY_VALUE_MASKING_CASES,
    ids=[c[0] for c in DICT_KEY_VALUE_MASKING_CASES],
)
def test_dict_key_value_masking(label, sample, expected):
    assert _mask(sample) == expected


# ---------------------------------------------------------------------------
# Non-sensitive fields and prose that must NOT be masked — guards the rules
# against over-masking. "key" is only sensitive as a *_key compound, so
# cache_key/sort_key/primary_key are spared; and the space rule's digit
# guard leaves prose like "Basic authentication" untouched.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("label,sample", NOT_MASKED, ids=[g[0] for g in NOT_MASKED])
def test_does_not_over_mask(label, sample):
    assert _mask(sample) == sample


# ---------------------------------------------------------------------------
# Space-cascade bug (open): the standalone-CVV rule — the loosest rule in the
# file, any bare 3-4 digit group — claims the 4-digit groups of a
# space-separated digit run that the card rules correctly ignored for being
# outside the 12-19 range. `expected` is the intended output (untouched),
# not what ships today. Strict xfail, so fixing the cascade turns these into
# XPASS failures and forces promotion into NOT_MASKED.
#
# The in-range 4-4-4-4 rows this list carried in the ported source are no
# longer affected — full-PAN masking claims the whole run before the CVV
# rule can see the groups — and now live in CARD_NUMBER_CASES.
# ---------------------------------------------------------------------------
OVER_MASKED_BECAUSE_OF_CVV = [
    ("card-11d-9-space", "9123 4567 891"),
    ("card-20d-9-space", "9123 4567 8912 34567891"),
    ("card-11d-other-space", "1123 4567 891"),
    ("card-20d-other-space", "1123 4567 8912 34567891"),
]


@pytest.mark.xfail(strict=True, reason="space-cascade bug: bare digit groups get masked as CVV")
@pytest.mark.parametrize(
    "label,sample", OVER_MASKED_BECAUSE_OF_CVV, ids=[g[0] for g in OVER_MASKED_BECAUSE_OF_CVV]
)
def test_over_masked_because_of_cvv(label, sample):
    assert _mask(sample) == sample


# ---------------------------------------------------------------------------
# Accepted leaks: unlike NOT_MASKED above (values that aren't sensitive, or
# don't match a rule's shape at all), every case here is genuinely
# sensitive-looking data (a real PAN, a real token) that a guard deliberately
# lets through unmasked. Each is a settled decision, not an open bug.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "label,sample", ACCEPTED_LEAK_CASES, ids=[g[0] for g in ACCEPTED_LEAK_CASES]
)
def test_accepted_leaks(label, sample):
    assert _mask(sample) == sample


class TestObjectAndPrimitiveHandling:
    def test_masks_sensitive_data_inside_object_repr(self):
        """Structured logging passes objects as kwargs; their repr must not
        leak. The filter stringifies a non-primitive before masking, or the
        embedded PAN would render unmasked downstream."""
        # the PAN is replaced; the already-masked portion of the repr is
        # left as-is
        assert _mask({"event": "decrypted payment data", "card": _FakeCard()}) == {
            "event": "decrypted payment data",
            "card": "<Card(VISA, 512345******0008, [CARD-MASKED])>",
        }

    def test_masks_object_nested_in_list_and_dict(self):
        assert _mask({"data": {"cards": [{"instrument": _FakeCard()}]}}) == {
            "data": {
                "cards": [
                    {"instrument": "<Card(VISA, 512345******0008, [CARD-MASKED])>"}
                ]
            }
        }

    def test_masks_cvv_string_field(self):
        assert _mask({"processed_data": {"cvv": "100"}}) == {
            "processed_data": {"cvv": "[CVV-MASKED]"}
        }

    def test_does_not_mangle_numeric_primitives(self):
        """Numbers/bools/None must survive intact — a 3-digit status code or
        count must not be caught by the CVV pattern."""
        sample = {"status_code": 200, "count": 100, "ok": True, "nothing": None}
        assert _mask(sample) == {"status_code": 200, "count": 100, "ok": True, "nothing": None}

    def test_masks_plain_string_message(self):
        assert _mask("card 5123 4500 0000 0008") == "card [CARD-MASKED]"


class TestMaskPIIFilterEngine:
    def test_dict_message_masked(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        flt = MaskPIIFilter()
        out = flt._mask_value({"customer_name": "John Doe", "amount": 5})
        assert re.fullmatch(r"\[NAME-MASKED:ptok:v1:[\w-]+\]", out["customer_name"])
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
        flt = MaskPIIFilter(skip_keys=())
        out = flt._mask_value({"service": {"name": "John Doe should be masked"}})
        assert out["service"]["name"] != "John Doe should be masked"

    def test_default_skip_keys_is_structural_ecs_keys(self):
        assert MaskPIIFilter()._skip_keys == STRUCTURAL_ECS_KEYS

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
            r"\[NAME-MASKED:ptok:v1:[\w-]+\]", record.msg["customer_name"]
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
