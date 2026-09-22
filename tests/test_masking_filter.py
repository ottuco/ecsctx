"""Tests for the MaskPIIFilter engine: content rules, key-name rules, and
the stdlib logging.Filter itself (ecsctx.masking.filters/patterns/tokens/
fields_rules).

The case tables below are ported from ottu_pg's tests/test_utils/
test_log_filters.py — the filter ecsctx's engine originated from — and
re-verified against ecsctx's actual output. Two deliberate differences from
the original expectations:

* every masked value is a ``[LABEL]`` marker, not ``***`` / bare ``CARD-MASKED``;
* card numbers are truncated to first 6 + last 4 (#159795, PCI DSS 3.4.1),
  so a PAN renders as ``112345******3456`` — no token
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
from ecsctx.masking.tokens import (
    already_masked,
    make_label,
    mask_by_field_type,
    safe_tokenize,
)
from ecsctx.pii import configure_pii


def _mask(msg):
    """Run a message through MaskPIIFilter with every pack on, and return the
    (mutated) record.msg — the case tables below cover all 17 rules."""
    record = logging.LogRecord("test", logging.INFO, __file__, 0, msg, None, None)
    MaskPIIFilter(packs=ALL_PACKS).filter(record)
    return record.msg


class _FakeCard:
    """Stand-in for a model whose ``__repr__`` embeds sensitive data (PAN/token)."""

    def __repr__(self) -> str:
        return "<Card(VISA, 512345******0008, 9584184138614802)>"


def _pem(kind: str, body: str) -> str:
    """Build a PEM block of the given kind, e.g. 'RSA PRIVATE KEY'."""
    return f"-----BEGIN {kind}-----\n{body}\n-----END {kind}-----"


_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.abc123def456ghi"
_HEX = "1a2b3c4d5e6f7a8b9c0d1e2f"


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
    @pytest.mark.parametrize("field_type", ["cvv", "card"])
    def test_cardholder_data_is_neither_tokenized_nor_exemptable(self, field_type):
        """Expiry is not here: it is Cardholder Data rather than Sensitive
        Authentication Data, so it is no longer classified at all."""
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

    def test_already_masked_detects_every_form_masking_produces(self):
        assert already_masked("[CVV-MASKED]")
        assert already_masked("ptok:v1:abc")
        assert already_masked("450875******1019")  # the bare truncated PAN
        # Pre-0.11 documents re-masked by a newer release.
        assert already_masked("[EMAIL-MASKED:ptok:v1:abc]")
        assert already_masked("[CARD-MASKED:450875******1019]")
        assert not already_masked("plain text")

    def test_already_masked_is_anchored_not_a_substring_test(self):
        """A marker-shaped fragment must not vouch for the value around it --
        otherwise attacker-supplied text turns masking off for its neighbours."""
        assert not already_masked("hello 450875******1019 there")
        assert not already_masked("[CVV-MASKED] and 4111111111111111")


class TestMaskByFieldType:
    def test_an_empty_value_stays_empty(self):
        """Nothing was there. A label would read as a value that had been
        hidden -- the same reason a null stays null."""
        assert mask_by_field_type("", "email") == ""
        assert mask_by_field_type("", "address") == ""

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
    configured or failing, or a type that is never tokenized (CVV, a truncated
    card)."""

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
            "expiry": "12/28",  # Cardholder Data, not SAD -- readable
            "card_number": "411111******1111",
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
    live in the ported case groups further down."""

    def test_email_regex_no_pipe_leak(self):
        """Regression: [A-Z|a-z] would let a literal '|' into the TLD."""
        assert mask_by_all_patterns("a@b.com") == "[EMAIL-MASKED]"

    def test_card_number_separators_dont_matter(self):
        spaced = mask_by_all_patterns("4111 1111 1111 1111")
        dashed = mask_by_all_patterns("4111-1111-1111-1111")
        assert spaced == dashed == "411111******1111"

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
PEM_MASKED_CASES = [
    ("pem-private-key", _pem("PRIVATE KEY", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"), "[PEM-KEY-MASKED]"),
    ("pem-rsa-private-key", _pem("RSA PRIVATE KEY", "MIIEpAIBAAKCAQEA0abcDEF"), "[PEM-KEY-MASKED]"),
    ("pem-ec-private-key", _pem("EC PRIVATE KEY", "MHcCAQEEIABxYZec012private"), "[PEM-KEY-MASKED]"),
    ("pem-public-key", _pem("PUBLIC KEY", "MIIBIjANBgkqhkiG9w0pubKEY"), "[PEM-KEY-MASKED]"),
    ("pem-rsa-public-key", _pem("RSA PUBLIC KEY", "MEgCQQCrsaPUBLICkeyXYZ"), "[PEM-KEY-MASKED]"),
]


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
CREDENTIAL_MASKED_CASES = [
    # quotes
    ("cred-single-quoted-colon", "'token': 'abcd1234'", "'token': '[SECRET-MASKED]'"),
    ("cred-single-quoted-colon-tight", "'token':'abcd1234'", "'token':'[SECRET-MASKED]'"),
    ("cred-double-quoted-colon", '"token": "abcd1234"', '"token": "[SECRET-MASKED]"'),
    ("cred-double-quoted-colon-tight", '"token":"abcd1234"', '"token":"[SECRET-MASKED]"'),
    # colons
    ("cred-colon", "token: abcd1234", "token: [SECRET-MASKED]"),
    ("cred-colon-tight", "token:abcd1234", "token:[SECRET-MASKED]"),
    # equals
    ("cred-equals", "token= abcd1234", "token= [SECRET-MASKED]"),
    ("cred-equals-tight", "token=abcd1234", "token=[SECRET-MASKED]"),
    # shorts — no 8-char floor
    ("cred-equals-single-digit", "token=1", "token=[SECRET-MASKED]"),
    ("cred-equals-single-char", "token=a", "token=[SECRET-MASKED]"),
    ("cred-colon-single-digit", "token: 1", "token: [SECRET-MASKED]"),
    ("cred-colon-single-char", "token: a", "token: [SECRET-MASKED]"),
    # HEX & JWT values
    ("cred-colon-hex", f"token:{_HEX}", "token:[SECRET-MASKED]"),
    ("cred-equals-hex", f"token={_HEX}", "token=[SECRET-MASKED]"),
    ("cred-colon-jwt", f"token:{_JWT}", "token:[SECRET-MASKED]"),
    ("cred-equals-jwt", f"token={_JWT}", "token=[SECRET-MASKED]"),
    # bare space (no colon, no equals, no quotes)
    ("cred-space-hex", f"token {_HEX}", "token [SECRET-MASKED]"),
    ("cred-space-jwt", f"token {_JWT}", "token [SECRET-MASKED]"),
    ("cred-space-8chars-4digits", "token abcd1234", "token [SECRET-MASKED]"),
    # in a sentence
    ("cred-short-token-equals-in-sentence", "message token=1", "message token=[SECRET-MASKED]"),
    # (token/secret/password/passwd) prefixes-on-token
    ("cred-token", "token abcd1234", "token [SECRET-MASKED]"),
    ("cred-anyword_token", "anyword_token abcd1234", "anyword_token [SECRET-MASKED]"),
    ("cred-any_word_token", "any_word_token abcd1234", "any_word_token [SECRET-MASKED]"),
    ("cred-any-word_token", "any-word_token abcd1234", "any-word_token [SECRET-MASKED]"),
    ("cred-any-word-token", "any-word-token abcd1234", "any-word-token [SECRET-MASKED]"),
    ("cred-any_1-word_2-token", "any_1-word_2-token abcd1234", "any_1-word_2-token [SECRET-MASKED]"),
    # (token/secret/password/passwd) keywords
    ("cred-secret", "secret abcd1234", "secret [SECRET-MASKED]"),
    ("cred-any_1-word_2-secret", "any_1-word_2-secret abcd1234", "any_1-word_2-secret [SECRET-MASKED]"),
    ("cred-password", "password abcd1234", "password [SECRET-MASKED]"),
    ("cred-any_1-word_2-password", "any_1-word_2-password abcd1234", "any_1-word_2-password [SECRET-MASKED]"),
    ("cred-passwd", "passwd abcd1234", "passwd [SECRET-MASKED]"),
    ("cred-any_1-word_2-passwd", "any_1-word_2-passwd abcd1234", "any_1-word_2-passwd [SECRET-MASKED]"),
    # auth schemes
    ("cred-bearer", "bearer abcd1234", "bearer [SECRET-MASKED]"),
    ("cred-basic", "basic abcd1234", "basic [SECRET-MASKED]"),
    ("cred-digest", "digest abcd1234", "digest [SECRET-MASKED]"),
    ("cred-credential", "credential abcd1234", "credential [SECRET-MASKED]"),
    ("cred-credentials", "credentials abcd1234", "credentials [SECRET-MASKED]"),
    # auth keywords (both spellings, both separators)
    ("cred-authorization", "authorization abcd1234", "authorization [SECRET-MASKED]"),
    ("cred-authorization_header", "authorization_header abcd1234", "authorization_header [SECRET-MASKED]"),
    ("cred-authorization-header", "authorization-header abcd1234", "authorization-header [SECRET-MASKED]"),
    ("cred-authorisation", "authorisation abcd1234", "authorisation [SECRET-MASKED]"),
    ("cred-authorisation_header", "authorisation_header abcd1234", "authorisation_header [SECRET-MASKED]"),
    ("cred-authorisation-header", "authorisation-header abcd1234", "authorisation-header [SECRET-MASKED]"),
    # key examples with api prefix
    ("cred-apikey", "apikey abcd1234", "apikey [SECRET-MASKED]"),
    ("cred-api_key", "api_key abcd1234", "api_key [SECRET-MASKED]"),
    ("cred-api-key", "api-key abcd1234", "api-key [SECRET-MASKED]"),
    # sensitive *_key compounds
    ("cred-secret-key", "secret-key abcd1234", "secret-key [SECRET-MASKED]"),
    ("cred-private-key", "private-key abcd1234", "private-key [SECRET-MASKED]"),
    ("cred-public-key", "public-key abcd1234", "public-key [SECRET-MASKED]"),
    ("cred-encryption-key", "encryption-key abcd1234", "encryption-key [SECRET-MASKED]"),
    ("cred-decryption-key", "decryption-key abcd1234", "decryption-key [SECRET-MASKED]"),
    ("cred-signing-key", "signing-key abcd1234", "signing-key [SECRET-MASKED]"),
    ("cred-access-key", "access-key abcd1234", "access-key [SECRET-MASKED]"),
    ("cred-master-key", "master-key abcd1234", "master-key [SECRET-MASKED]"),
    ("cred-root-key", "root-key abcd1234", "root-key [SECRET-MASKED]"),
    ("cred-session-key", "session-key abcd1234", "session-key [SECRET-MASKED]"),
    # 16-digit numeric secret, inside the card rules' 12-19 digit range —
    # the credential rule must claim it before the card rule sees it.
    ("cred-numeric-secret-in-card-digit-range", "secret_key=1234567890123456", "secret_key=[SECRET-MASKED]"),
    # Authorization header, every realistic shape
    ("auth-header-line-single-quotes", f"'Authorization': 'Bearer {_JWT}'", "'Authorization': '[SECRET-MASKED]'"),
    ("auth-header-line-double-quotes", f'"Authorization": "Bearer {_JWT}"', '"Authorization": "[SECRET-MASKED]"'),
    ("auth-header-line-colon", f"Authorization: Bearer {_JWT}", "Authorization: [SECRET-MASKED] [JWT-MASKED]"),
    ("auth-header-line-equal", f"Authorization= Bearer {_JWT}", "Authorization= [SECRET-MASKED] [JWT-MASKED]"),
    ("auth-header-line-space", f"Authorization Bearer {_JWT}", "Authorization Bearer [SECRET-MASKED]"),
    ("auth-header-quoted-kv", f'{{"Authorization": "{_HEX}"}}', '{"Authorization": "[SECRET-MASKED]"}'),
    ("auth-header-quoted-kv-in-sentence", f'Here is {{"Authorization": "{_HEX}"}}', 'Here is {"Authorization": "[SECRET-MASKED]"}'),
    ("auth-dict-value-with-spaces", f'{{"Authorization": "Bearer {_HEX} more"}}', '{"Authorization": "[SECRET-MASKED]"}'),
    ("authorization-raw-colon", f"Authorization: {_HEX}abcd", "Authorization: [SECRET-MASKED]"),
    ("authorisation-raw-dict", f'{{"Authorisation": "{_HEX}abcd"}}', '{"Authorisation": "[SECRET-MASKED]"}'),
    (
        "auth-inside-headers-dict-apikey",
        {"headers": {"Authorization": f"API-Key {_HEX}"}},
        {"headers": {"Authorization": "[SECRET-MASKED]"}},
    ),
    (
        "auth-inside-headers-dict-bearer",
        {"headers": {"Authorization": f"Bearer {_JWT}"}},
        {"headers": {"Authorization": "[SECRET-MASKED]"}},
    ),
    (
        "auth-inside-headers-dict-token",
        {"headers": {"Authorization": "token abcd 1234 anything"}},
        {"headers": {"Authorization": "[SECRET-MASKED]"}},
    ),
    (
        "auth-interpolated-in-message",
        f"Authentication failed with key 'API-Key {_HEX}'",
        "Authentication failed with key 'API-Key [SECRET-MASKED]'",
    ),
    # common OAuth/API field names
    ("access_token-kv", "access_token=abcd1234efgh5678", "access_token=[SECRET-MASKED]"),
    ("refresh_token-kv", "refresh_token=abcd1234efgh5678", "refresh_token=[SECRET-MASKED]"),
    ("client_secret-kv", "client_secret=sk_live_abcd1234ef", "client_secret=[SECRET-MASKED]"),
    ("private_key-kv", "private_key=abcd1234efgh5678", "private_key=[SECRET-MASKED]"),
    ("secret_key-kv", "secret_key=abcd1234efgh5678", "secret_key=[SECRET-MASKED]"),
    ("auth-basic-equals", f"basic= {_HEX}", "basic= [SECRET-MASKED]"),
    ("auth-api-key-value", f"API-Key {_HEX}", "API-Key [SECRET-MASKED]"),
    ("auth-basic-value", "Basic dXNlcjpwYXNzd29yZA==", "Basic [SECRET-MASKED]"),
    # A quoted key whose value is a bare literal: text that is JSON (or a
    # Python repr) must stay parseable, and a null/boolean holds no secret.
    ("cred-quoted-key-json-null", 'body {"public_key": null, "a": 1}', 'body {"public_key": null, "a": 1}'),
    ("cred-quoted-key-json-bool", 'body {"session_key": true}', 'body {"session_key": true}'),
    ("cred-quoted-key-python-none", "body {'public_key': None}", "body {'public_key': None}"),
    (
        "cred-quoted-key-number-stays-quoted",
        'body {"session_key": 12345}',
        'body {"session_key": "[SECRET-MASKED]"}',
    ),
    (
        "cred-single-quoted-key-number-stays-quoted",
        "body {'api_key': 12345}",
        "body {'api_key': '[SECRET-MASKED]'}",
    ),
]


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
CVV_KEYWORD_CASES = [
    ("cvv-single-quoted-colon", "'cvv': '123'", "'cvv': '[CVV-MASKED]'"),
    ("cvv-single-quoted-colon-tight-mixed-case", "'Cvv':'123'", "'Cvv':'[CVV-MASKED]'"),
    ("cvv-double-quoted-colon-mixed-case", '"cVv": "123"', '"cVv": "[CVV-MASKED]"'),
    ("cvv-double-quoted-colon-tight-mixed-case", '"cvV":"123"', '"cvV":"[CVV-MASKED]"'),
    ("cvv-unquoted-colon-mixed-case", "CVv: 1234", "CVv: [CVV-MASKED]"),
    ("cvv-unquoted-colon-tight-mixed-case", "cVV:1234", "cVV:[CVV-MASKED]"),
    ("cvv-unquoted-equals-mixed-case", "CvV= 1234", "CvV= [CVV-MASKED]"),
    ("cvv-unquoted-equals-tight-mixed-case", "CVV=1234", "CVV=[CVV-MASKED]"),
    ("cvv-in-sentence", "Here cvv=100 is submitted", "Here cvv=[CVV-MASKED] is submitted"),
    ("cvc-single-quoted-colon", "'cvc': '123'", "'cvc': '[CVV-MASKED]'"),
    ("cvc-single-quoted-colon-uppercase", "'CVC': '1234'", "'CVC': '[CVV-MASKED]'"),
    # real dicts, cvv key nested one level deep — not just a string sample.
    ("cvv-dict-obj", {"processed_data": {"cvv": "100"}}, {"processed_data": {"cvv": "[CVV-MASKED]"}}),
    (
        "cvv-dict-obj-long",
        {"processed_data": {"cvv": "not a cvv shape 123456789"}},
        {"processed_data": {"cvv": "[CVV-MASKED]"}},
    ),
    # same shape, but as a JSON string, not a real dict — the quoted-key rule
    # must still find it nested inside the braces.
    (
        "cvv-quoted-inside-json-string",
        '{"processed_data": {"cvv": "100"}}',
        '{"processed_data": {"cvv": "[CVV-MASKED]"}}',
    ),
    # A quoted key with a numeric value: the marker is quoted so JSON text
    # stays parseable.
    ("cvv-quoted-key-number-stays-quoted", 'data {"cvv": 123}', 'data {"cvv": "[CVV-MASKED]"}'),
]


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
PAYMENT_ID_QUOTE_CASES = [
    ("payment_id-bare-colon", "payment_id: abc12345", "payment_id: [PAYMENT-ID-MASKED]"),
    ("payment_id-bare-equals", "payment_id= abc12345", "payment_id= [PAYMENT-ID-MASKED]"),
    ("payment_id-bare-space", "payment_id abc12345", "payment_id [PAYMENT-ID-MASKED]"),
    ("payment-id-bare-colon", "payment-id: abc12345", "payment-id: [PAYMENT-ID-MASKED]"),
    ("payment-id-bare-equals", "payment-id= abc12345", "payment-id= [PAYMENT-ID-MASKED]"),
    ("payment-id-bare-space", "payment-id abc12345", "payment-id [PAYMENT-ID-MASKED]"),
    ("payment_id-single-quoted-colon", "'payment_id': 'abc12345'", "'payment_id': '[PAYMENT-ID-MASKED]'"),
    ("payment-id-single-quoted-colon", "'payment-id': 'abc12345'", "'payment-id': '[PAYMENT-ID-MASKED]'"),
    ("payment_id-single-quoted-colon-tight", "'payment_id':'abc12345'", "'payment_id':'[PAYMENT-ID-MASKED]'"),
    ("payment-id-single-quoted-colon-tight", "'payment-id':'abc12345'", "'payment-id':'[PAYMENT-ID-MASKED]'"),
    ("payment_id-double-quoted-colon", '"payment_id": "abc12345"', '"payment_id": "[PAYMENT-ID-MASKED]"'),
    ("payment-id-double-quoted-colon", '"payment-id": "abc12345"', '"payment-id": "[PAYMENT-ID-MASKED]"'),
    ("payment_id-double-quoted-colon-tight", '"payment_id":"abc12345"', '"payment_id":"[PAYMENT-ID-MASKED]"'),
    ("payment-id-double-quoted-colon-tight", '"payment-id":"abc12345"', '"payment-id":"[PAYMENT-ID-MASKED]"'),
    ("transaction-id-quoted-alnum-value", "'transaction_id': 'jbzzTT577'", "'transaction_id': '[PAYMENT-ID-MASKED]'"),
    ("auth-id-quoted-numeric-value", "'auth_id': '016153570198200'", "'auth_id': '[PAYMENT-ID-MASKED]'"),
    ("payment-id-numeric-in-card-digit-range", "payment_id: 1234567890123456 done", "payment_id: [PAYMENT-ID-MASKED] done"),
    ("payment-id-equals-numeric-in-card-digit-range", "payment_id= 9876543210987654 done", "payment_id= [PAYMENT-ID-MASKED] done"),
    ("transaction_id-bare-colon", "transaction_id: abcd1234", "transaction_id: [PAYMENT-ID-MASKED]"),
    ("transaction-id-bare-colon", "transaction-id: abcd1234", "transaction-id: [PAYMENT-ID-MASKED]"),
    ("auth_id-bare-colon", "auth_id: abcd1234", "auth_id: [PAYMENT-ID-MASKED]"),
    ("auth-id-bare-colon", "auth-id: abcd1234", "auth-id: [PAYMENT-ID-MASKED]"),
    (
        "payment-id-dict-obj",
        {"processed_data": {"payment_id": "abc12345"}},
        {"processed_data": {"payment_id": "[PAYMENT-ID-MASKED]"}},
    ),
    (
        "payment-id-dict-obj-long",
        {"processed_data": {"payment_id": "not a cvv shape abc12345"}},
        {"processed_data": {"payment_id": "[PAYMENT-ID-MASKED]"}},
    ),
    (
        "payment-id-quoted-inside-json-string",
        '{"processed_data": {"payment_id": "abc12345"}}',
        '{"processed_data": {"payment_id": "[PAYMENT-ID-MASKED]"}}',
    ),
]


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
IBAN_MASKED_CASES = [
    ("iban", "account GB33BUKB20201555555555 credited", "account [IBAN-MASKED] credited"),
    # BE/FR: not Gulf-region at all; BH/QA: Gulf-region codes that still
    # collide despite embedded letters elsewhere in the BBAN.
    ("iban-be-digit-run-collision", "acct BE68539007547034 debited", "acct [IBAN-MASKED] debited"),
    ("iban-fr-digit-run-collision", "acct FR1420041010050500013M02606 debited", "acct [IBAN-MASKED] debited"),
    ("iban-bh-digit-run-collision", "acct BH67BMAG00001299123456 debited", "acct [IBAN-MASKED] debited"),
    ("iban-qa-digit-run-collision", "acct QA58DOHB00001234567890ABCDEFG debited", "acct [IBAN-MASKED] debited"),
    # Synthetic IBANs pinned to exact digit-run lengths, covering the card
    # rule's collision window directly (_CARD_BODY matches a 12-19-digit
    # run). 13 (2 check digits + 11 BBAN) is the shortest constructible case.
    ("iban-digit-run-13-just-over-card-floor", "acct GB1212345678901 debited", "acct [IBAN-MASKED] debited"),
    ("iban-digit-run-16-classic-pan-length", "acct GB3412345678901234 debited", "acct [IBAN-MASKED] debited"),
    ("iban-digit-run-19-top-of-card-range", "acct GB5612345678901234567 debited", "acct [IBAN-MASKED] debited"),
    ("iban-digit-run-20-past-card-range", "acct GB78123456789012345678 debited", "acct [IBAN-MASKED] debited"),
]


@pytest.mark.parametrize(
    "label,sample,expected", IBAN_MASKED_CASES, ids=[c[0] for c in IBAN_MASKED_CASES]
)
def test_masks_iban(label, sample, expected):
    assert _mask(sample) == expected


# ---------------------------------------------------------------------------
# Phone numbers. Runs before the card rules: a purely numeric value in the
# card rules' 12-19-digit range would otherwise be claimed as a PAN.
# ---------------------------------------------------------------------------
PHONE_MASKED_CASES = [
    # bare local number, no country code, fixed 3-3-4 grouping.
    ("phone-local-space-separators", "091 234 5678", "[PHONE-MASKED]"),
    ("phone-local-dash-space-mixed", "091-234 5678", "[PHONE-MASKED]"),
    ("phone-local-space-dash-mixed", "091 234-5678", "[PHONE-MASKED]"),
    ("phone-local-dash-separators", "091-234-5678", "[PHONE-MASKED]"),
    # "+" country code, E.164-style, any grouping/separators.
    ("phone-intl-plus-no-separators", "+963912345678", "[PHONE-MASKED]"),
    ("phone-intl-plus-space-after-code", "+963 912345678", "[PHONE-MASKED]"),
    ("phone-intl-plus-dash-after-code", "+963-912345678", "[PHONE-MASKED]"),
    ("phone-intl-country-code-in-card-digit-range", "call +44-555-123-4567 now", "call [PHONE-MASKED] now"),
    ("phone-intl-3digit-country-code-in-card-digit-range", "call +971-555-123-4567 now", "call [PHONE-MASKED] now"),
]


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
EMAIL_MASKED_CASES = [
    ("email-plain", "user@example.com", "[EMAIL-MASKED]"),
    ("email-in-sentence", "contact john.doe@example.com now", "contact [EMAIL-MASKED] now"),
    ("email-mixed-case", "User.Name+tag@Example.CO.UK", "[EMAIL-MASKED]"),
    ("email-subdomain", "first.last@sub.domain.example.com", "[EMAIL-MASKED]"),
    ("email-underscore-local-part", "user_name@example.com", "[EMAIL-MASKED]"),
    ("email-hyphen-local-part", "user-name@example.com", "[EMAIL-MASKED]"),
    ("email-hyphenated-domain", "user@sub-domain.example.co.uk", "[EMAIL-MASKED]"),
    ("email-plus-tag-local-part", "disposable.style.email.with+symbol@example.com", "[EMAIL-MASKED]"),
    # numeric-heavy local part / domain — must mask as one email, not get
    # fragmented by the card/phone/CVV rules that also look for digit runs.
    ("email-numeric-local-part", "123456@example.com", "[EMAIL-MASKED]"),
    ("email-numeric-domain", "notify: john@1234567890.com", "notify: [EMAIL-MASKED]"),
    ("email-single-quoted-colon", "'email': 'user@example.com'", "'email': '[EMAIL-MASKED]'"),
    ("email-double-quoted-colon", '"email": "user@example.com"', '"email": "[EMAIL-MASKED]"'),
    ("email-equals", "email=user@example.com", "email=[EMAIL-MASKED]"),
    (
        "email-quoted-inside-json-string",
        '{"contact": {"email": "user@example.com"}}',
        '{"contact": {"email": "[EMAIL-MASKED]"}}',
    ),
]


@pytest.mark.parametrize(
    "label,sample,expected", EMAIL_MASKED_CASES, ids=[c[0] for c in EMAIL_MASKED_CASES]
)
def test_masks_email(label, sample, expected):
    assert _mask(sample) == expected


def test_email_under_a_sensitive_parent_key_is_masked_as_an_email():
    """"contact" is a PII container (generic category): it keeps its shape and
    each field is masked on its own, so the email gets an email token that
    correlates with the same email anywhere else."""
    assert _mask({"contact": {"email": "user@example.com"}}) == {"contact": {"email": "[EMAIL-MASKED]"}}


# ---------------------------------------------------------------------------
# Bare JWT — standalone secret with no keyword/scheme in front (the
# keyworded forms, e.g. "token:<jwt>" / "Bearer <jwt>", are covered by the
# credential rules above).
# ---------------------------------------------------------------------------
JWT_MASKED_CASES = [
    ("jwt-standalone", _JWT, "[JWT-MASKED]"),
    ("jwt-in-sentence-space-bounded", f"Here it's {_JWT} failed!", "Here it's [JWT-MASKED] failed!"),
    ("jwt-in-sentence-parens-wrapped", f"Here it's ({_JWT}) failed!", "Here it's ([JWT-MASKED]) failed!"),
    ("jwt-in-sentence-colon-prefixed", f"Here it's: {_JWT} failed!", "Here it's: [JWT-MASKED] failed!"),
    # leading "\b" only blocks a letter/digit/underscore glued directly in
    # front — hyphen and dot aren't word characters, so they still match.
    ("jwt-hyphen-prefixed", f"-{_JWT}", "-[JWT-MASKED]"),
    ("jwt-dot-prefixed", f".{_JWT}", ".[JWT-MASKED]"),
    # no boundary check at the end at all — any letter/digit/underscore/
    # hyphen glued directly after gets silently swallowed into the match.
    ("jwt-suffix-letter-swallowed", f"{_JWT}abc", "[JWT-MASKED]"),
    ("jwt-suffix-digit-swallowed", f"{_JWT}123", "[JWT-MASKED]"),
    ("jwt-suffix-underscore-swallowed", f"{_JWT}_more", "[JWT-MASKED]"),
    ("jwt-suffix-hyphen-swallowed", f"{_JWT}-more", "[JWT-MASKED]"),
    ("jwt-suffix-swallowed-in-sentence", f"token was {_JWT}extra and more", "token was [JWT-MASKED] and more"),
]


@pytest.mark.parametrize(
    "label,sample,expected", JWT_MASKED_CASES, ids=[c[0] for c in JWT_MASKED_CASES]
)
def test_masks_jwt(label, sample, expected):
    assert _mask(sample) == expected


# ---------------------------------------------------------------------------
# Card numbers (PAN), 12-19 digits, dash/space separators. ecsctx truncates
# to first 6 + last 4 (#159795, PCI DSS 3.4.1) — the leading digit no longer
# changes the outcome, and every row below IS its own truncated core, bare:
# brackets mean nothing survived, and a truncation carries the BIN and the last
# four. Separators are stripped, so grouped input comes back contiguous.
# ---------------------------------------------------------------------------
CARD_NUMBER_CASES = [
    # continuous, leading 9
    ("card-12d-9-continuous", "912345678912", "********8912"),
    ("card-13d-9-continuous", "9123456789123", "*********9123"),
    ("card-14d-9-continuous", "91234567891234", "**********1234"),
    ("card-15d-9-continuous", "912345678912345", "912345*****2345"),
    ("card-16d-9-continuous", "9123456789123456", "912345******3456"),
    ("card-17d-9-continuous", "91234567891234567", "912345*******4567"),
    ("card-18d-9-continuous", "912345678912345678", "912345********5678"),
    ("card-19d-9-continuous", "9123456789123456789", "912345*********6789"),
    # space-separated, leading 9
    ("card-12d-9-space", "9123 4567 8912", "********8912"),
    ("card-13d-9-space", "9123 4567 8912 3", "*********9123"),
    ("card-14d-9-space", "9123 4567 8912 34", "**********1234"),
    ("card-15d-9-space", "9123 4567 8912 345", "912345*****2345"),
    ("card-16d-9-space", "9123 4567 8912 3456", "912345******3456"),
    ("card-17d-9-space", "9123 4567 8912 34567", "912345*******4567"),
    ("card-18d-9-space", "9123 4567 8912 345678", "912345********5678"),
    ("card-19d-9-space", "9123 4567 8912 3456789", "912345*********6789"),
    # dash-separated, leading 9
    ("card-12d-9-dash", "9123-4567-8912", "********8912"),
    ("card-13d-9-dash", "9123-4567-8912-3", "*********9123"),
    ("card-14d-9-dash", "9123-4567-8912-34", "**********1234"),
    ("card-15d-9-dash", "9123-4567-8912-345", "912345*****2345"),
    ("card-16d-9-dash", "9123-4567-8912-3456", "912345******3456"),
    ("card-17d-9-dash", "9123-4567-8912-34567", "912345*******4567"),
    ("card-18d-9-dash", "9123-4567-8912-345678", "912345********5678"),
    ("card-19d-9-dash", "9123-4567-8912-3456789", "912345*********6789"),
    # continuous, other leading digit — truncated too (BIN + last 4 visible)
    ("card-12d-other-continuous", "112345678912", "********8912"),
    ("card-13d-other-continuous", "1123456789123", "*********9123"),
    ("card-14d-other-continuous", "11234567891234", "**********1234"),
    ("card-15d-other-continuous", "112345678912345", "112345*****2345"),
    ("card-16d-other-continuous", "1123456789123456", "112345******3456"),
    ("card-17d-other-continuous", "11234567891234567", "112345*******4567"),
    ("card-18d-other-continuous", "112345678912345678", "112345********5678"),
    ("card-19d-other-continuous", "1123456789123456789", "112345*********6789"),
    # space-separated, other leading digit
    ("card-12d-other-space", "11234 56 78912", "********8912"),
    ("card-13d-other-space", "11234 56 789123", "*********9123"),
    ("card-14d-other-space", "11234 56 7891234", "**********1234"),
    ("card-15d-other-space", "11234 56 78912345", "112345*****2345"),
    ("card-16d-other-space", "11234 56 789123456", "112345******3456"),
    ("card-17d-other-space", "11234 56 7891234567", "112345*******4567"),
    ("card-18d-other-space", "11234 56 78912345678", "112345********5678"),
    ("card-19d-other-space", "11234 56 789123456789", "112345*********6789"),
    # dash-separated, other leading digit
    ("card-12d-other-dash", "1123-4567-8912", "********8912"),
    ("card-13d-other-dash", "1123-4567-8912-3", "*********9123"),
    ("card-14d-other-dash", "1123-4567-8912-34", "**********1234"),
    ("card-15d-other-dash", "1123-4567-8912-345", "112345*****2345"),
    ("card-16d-other-dash", "1123-4567-8912-3456", "112345******3456"),
    ("card-17d-other-dash", "1123-4567-8912-34567", "112345*******4567"),
    ("card-18d-other-dash", "1123-4567-8912-345678", "112345********5678"),
    ("card-19d-other-dash", "1123-4567-8912-3456789", "112345*********6789"),
    # irregular grouping
    ("card-2groups-9-space", "90345 67812901256", "903456******1256"),
    ("card-2groups-9-dash", "90345-67812901256", "903456******1256"),
    ("card-2groups-other-space", "10345 67812901256", "103456******1256"),
    ("card-2groups-other-dash", "10345-67812901256", "103456******1256"),
    ("card-3groups-9-space", "90345 678129012 90345", "903456*********0345"),
    ("card-3groups-9-dash", "90345-678129012-90345", "903456*********0345"),
    ("card-3groups-other-space", "10345 678129012 10345", "103456*********0345"),
    ("card-3groups-other-dash", "10345-678129012-10345", "103456*********0345"),
    ("card-5groups-9-space", "90345 678 1290 12 56789", "903456*********6789"),
    ("card-5groups-9-dash", "90345-678-1290-12-56789", "903456*********6789"),
    ("card-5groups-other-space", "40345 678 1290 12 56789", "403456*********6789"),
    ("card-5groups-other-dash", "40345-678-1290-12-56789", "403456*********6789"),
    # mixed separators within one number
    ("card-2-mixed-separator-9", "9034-5678 1290", "********1290"),
    ("card-3-mixed-separator-9", "9034-5678 1290-125", "903456*****0125"),
    ("card-4-mixed-separator-9", "9034-5678 1290-1256 125", "903456*********6125"),
    ("card-2-mixed-separator-other", "4034-5678 1290", "********1290"),
    ("card-3-mixed-separator-other", "4034-5678 1290-125", "403456*****0125"),
    ("card-4-mixed-separator-other", "4034-5678 1290-1256 125", "403456*********6125"),
    # trailing chunk is phone-shaped (10 bare digits) — the phone rule runs
    # first, so the card rule needs its guard to still claim the full PAN.
    ("card-17d-space-trailing-chunk-is-phone-shaped", "11234 56 7891234567", "112345*******4567"),
    # every allowed lead-guard prefix, embedded in a sentence
    ("card-19d-9-space-prefixed-in-sentence", "Here is 9123456789123456789 card Number", "Here is 912345*********6789 card Number"),
    ("card-19d-9-paren-prefixed-in-sentence", "Here is (9123456789123456789) card Number", "Here is (912345*********6789) card Number"),
    ("card-19d-9-bracket-prefixed-in-sentence", "Here is [9123456789123456789] card Number", "Here is [912345*********6789] card Number"),
    ("card-19d-9-brace-prefixed-in-sentence", "Here is {9123456789123456789} card Number", "Here is {912345*********6789} card Number"),
    ("card-19d-9-colon-prefixed-in-sentence", "Here num:9123456789123456789 card Number", "Here num:912345*********6789 card Number"),
    ("card-19d-9-equals-prefixed-in-sentence", "Here num=9123456789123456789 card Number", "Here num=912345*********6789 card Number"),
    ("card-19d-9-comma-prefixed-in-sentence", "Here num,9123456789123456789 card Number", "Here num,912345*********6789 card Number"),
    ("card-19d-9-dot-prefixed-in-sentence", "Here num.9123456789123456789 card Number", "Here num.912345*********6789 card Number"),
    # 4-4-4-4 grouping: cascaded into per-group CVV masking in the ported
    # source, but full-PAN masking claims the whole run here.
    ("card-12d-other-space-4x4", "1123 4567 8912", "********8912"),
    ("card-15d-other-space-4x4", "1123 4567 8912 345", "112345*****2345"),
    ("card-16d-other-space-4x4", "1123 4567 8912 3456", "112345******3456"),
    ("card-17d-other-space-4x4", "1123 4567 8912 34567", "112345*******4567"),
    ("card-19d-other-space-4x4", "1123 4567 8912 3456789", "112345*********6789"),
]


@pytest.mark.parametrize(
    "label,sample,expected", CARD_NUMBER_CASES, ids=[c[0] for c in CARD_NUMBER_CASES]
)
def test_card_number_masking(label, sample, expected):
    assert str(_mask(sample)) == expected


def test_card_number_reveals_only_bin_and_last4():
    """The truncation contract (#159795), stated directly rather than only
    implied by the table above: first 6 + last 4 visible, full PAN gone,
    and the labeled output is stable under a second pass."""
    assert _mask("4111111111111111") == "411111******1111"
    assert _mask("411111******1111") == "411111******1111"


# ---------------------------------------------------------------------------
# SSN. Runs before standalone-CVV (the loosest rule of all — any bare 3-4
# digit group): a space-separated SSN's outer groups ("123" and "6789") are
# each individually CVV-standalone-shaped, so without this order it would
# fragment instead of masking as one SSN.
# ---------------------------------------------------------------------------
SSN_MASKED_CASES = [
    ("ssn-space-glued-no-separators", "ssn 123456789 on file", "ssn [SSN-MASKED] on file"),
    ("ssn-space-then-glued-tail", "ssn 123 456789 on file", "ssn [SSN-MASKED] on file"),
    ("ssn-glued-head-then-space", "ssn 12345 6789 on file", "ssn [SSN-MASKED] on file"),
    ("ssn-space-separated-all-groups", "ssn 123 45 6789 on file", "ssn [SSN-MASKED] on file"),
    ("ssn-dash-then-glued-tail", "ssn 123-456789 on file", "ssn [SSN-MASKED] on file"),
    ("ssn-glued-head-then-dash", "ssn 12345-6789 on file", "ssn [SSN-MASKED] on file"),
    ("ssn-dash-separated-all-groups", "ssn 123-45-6789 on file", "ssn [SSN-MASKED] on file"),
    ("ssn-mixed-space-then-dash", "ssn 123 45-6789 on file", "ssn [SSN-MASKED] on file"),
    ("ssn-mixed-dash-then-space", "ssn 123-45 6789 on file", "ssn [SSN-MASKED] on file"),
    ("ssn-equals-prefixed", "ssn=123456789 on file", "ssn=[SSN-MASKED] on file"),
    ("ssn-colon-prefixed", "ssn:123456789 on file", "ssn:[SSN-MASKED] on file"),
    ("ssn-comma-prefixed", "ssn,123456789 on file", "ssn,[SSN-MASKED] on file"),
    ("ssn-dot-prefixed", "ssn.123456789 on file", "ssn.[SSN-MASKED] on file"),
    ("ssn-single-quote-prefixed", "ssn'123456789' on file", "ssn'[SSN-MASKED]' on file"),
    ("ssn-double-quote-prefixed", 'ssn"123456789" on file', 'ssn"[SSN-MASKED]" on file'),
    ("ssn-paren-prefixed", "ssn(123456789) on file", "ssn([SSN-MASKED]) on file"),
    ("ssn-bracket-prefixed", "ssn[123456789] on file", "ssn[[SSN-MASKED]] on file"),
    ("ssn-brace-prefixed", "ssn{123456789} on file", "ssn{[SSN-MASKED]} on file"),
    ("ssn-string-start-no-prefix", "123456789 on file", "[SSN-MASKED] on file"),
]


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
DICT_KEY_VALUE_MASKING_CASES = [
    (
        "key-token-string-value",
        {"event": "create payment", "token": "abcd1234"},
        {"event": "create payment", "token": "[SECRET-MASKED]"},
    ),
    ("key-cvv-int-value", {"cvv": 123}, {"cvv": "[CVV-MASKED]"}),
    ("key-cvv-string-value", {"cvv": "123"}, {"cvv": "[CVV-MASKED]"}),
    ("key-session-key-int-value", {"session_key": 12345}, {"session_key": "[SECRET-MASKED]"}),
    # A null holds nothing to mask: a marker there would read as a value.
    ("key-access-token-none-value", {"access_token": None}, {"access_token": None}),
    (
        "key-sensitive-nulls-stay-null",
        {"public_key": None, "customer_name": None, "card": None, "expiry": None, "cvv": None},
        {"public_key": None, "customer_name": None, "card": None, "expiry": None, "cvv": None},
    ),
    ("key-mixed-case-cvv", {"Cvv": "123"}, {"Cvv": "[CVV-MASKED]"}),
    ("key-camelcase-security-code-int", {"securityCode": 999}, {"securityCode": "[CVV-MASKED]"}),
    (
        "key-nested-under-sensitive-key-blanket-masked",
        {"data": {"token": {"nested": "stuff", "more": 1}}},
        {"data": {"token": "[SECRET-MASKED]"}},
    ),
]


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
NOT_MASKED = [
    # Promoted out of OVER_MASKED_BECAUSE_OF_CVV: an 11-digit run is too short
    # for the card rules AND carries no card context, so the standalone-CVV
    # rule no longer claims its 4-digit groups.
    ("card-11d-9-space", "9123 4567 891"),
    ("card-11d-other-space", "1123 4567 891"),
    ("cache-key", "cache_key=user_profile_v2"),
    ("sort-key", "sort_key=created_at_desc"),
    ("primary-key", "primary_key=customer_00042"),
    ("partition-key", "partition_key=eu_west_1a"),
    ("prose-basic", "Basic authentication required"),
    ("prose-bearer", "the bearer of this message"),
    ("prose-token", "token expired, please retry"),
    ("cred-char-session-id-unaffected", "session_id=abcdefghijklmn"),
    ("cred-both-session-id-unaffected", "session_id=6ea04d6db060f7ce414b6f5faa7119161e2214bc"),
    # IBAN pattern must validate a real uppercase country prefix, not just
    # the "2 letters + 2 digits + alnum" shape — these are not IBANs.
    ("iban-fake-country", "order AB12CDEF3456GH78 shipped"),
    ("iban-non-iban-country", "ref US12INVOICE0000042 paid"),
    ("iban-lowercase", "acct gb33bukb20201555 done"),
    # Card rules only recognize dash/space (the two real-world PAN
    # separators), so dot/comma/underscore are deliberately not chased.
    ("card-dot-separated-not-a-real-pan-format", "4111.1111.1111.1111"),
    # outside the 12-19 digit range entirely
    ("card-11d-9-continuous", "91234567891"),
    ("card-20d-9-continuous", "91234567891234567891"),
    ("card-11d-9-space", "912345 67891"),
    ("card-20d-9-space", "912345 678912 34567891"),
    ("card-11d-9-dash", "9123-4567-891"),
    ("card-20d-9-dash", "9123-4567-8912-34567891"),
    ("card-11d-other-continuous", "11234567891"),
    ("card-20d-other-continuous", "11234567891234567891"),
    ("card-11d-other-space", "112345 67891"),
    ("card-20d-other-space", "112345 678912 34567891"),
    ("card-11d-other-dash", "1123-4567-891"),
    ("card-20d-other-dash", "1123-4567-8912-34567891"),
    # Email rule requires a literal "@", a domain, a dot, and a 2+ letter
    # TLD — anything short of that full shape is left alone.
    ("email-no-tld-dot", "user@localhost"),
    ("email-trailing-dot-no-tld", "user@example."),
    ("email-no-domain-before-dot", "user@.com"),
    ("email-no-local-part", "@example.com"),
    ("email-no-domain", "user@"),
    ("email-single-char-tld", "user@example.c"),
    # not a sensitive key at all, regardless of value.
    ("key-cache-key-unaffected", {"cache_key": "user_profile_v2"}),
]


@pytest.mark.parametrize("label,sample", NOT_MASKED, ids=[g[0] for g in NOT_MASKED])
def test_does_not_over_mask(label, sample):
    assert _mask(sample) == sample


# ---------------------------------------------------------------------------
# Space-cascade bug (narrowed, not closed): the standalone-CVV rule — the
# loosest rule in the file, any bare 3-4 digit group — claims the 4-digit
# groups of a space-separated digit run that the card rules correctly ignored
# for being outside the 12-19 range. `expected` is the intended output
# (untouched), not what ships today. Strict xfail, so fixing it turns these
# into XPASS failures and forces promotion into NOT_MASKED.
#
# The 11-digit rows have been promoted: the rule now needs card context in the
# text, and 11 digits are too few for _CARD_SHAPE to supply it. The 20-digit
# rows stay — their first 12 digits ARE card-shaped, so the text does carry
# card context and the rule is entitled to look at the groups. Closing those
# needs the card rules to claim the whole run first, which is a change to
# rule 15, not to the CVV rule.
#
# The in-range 4-4-4-4 rows this list carried in the ported source are no
# longer affected — truncated-PAN masking claims the whole run before the
# CVV rule can see the groups — and now live in CARD_NUMBER_CASES.
# ---------------------------------------------------------------------------
OVER_MASKED_BECAUSE_OF_CVV = [
    ("card-20d-9-space", "9123 4567 8912 34567891"),
    ("card-20d-other-space", "1123 4567 8912 34567891"),
]


@pytest.mark.xfail(strict=True, reason="space-cascade: card-shaped text lets the CVV rule see its groups")
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
ACCEPTED_LEAK_CASES = [
    # The bare-space credential rule requires a digit in the value, so it can
    # tell a real token from prose — an all-letter value is left unmasked.
    ("cred-space-value-no-digit-unmasked", "Bearer abcdefghij"),
    # Keyword glued directly to its value with no separator at all is never
    # matched — required, since matching it would over-mask ordinary words
    # like "tokenization" that merely start with a keyword.
    ("cred-glued-no-separator-unmasked", "token12345"),
    # All card rules share one lead guard: a match may only start right after
    # a real prefix (quote, ":", "=", space, comma, dot, or start-of-string).
    # A letter isn't in that set, so a digit run glued to a preceding letter
    # matches no card rule at all.
    ("card-glued-to-letters-leading-9-unaffected", "REF9111111111111111 confirmed"),
    ("card-glued-to-letters-leading-other-unaffected", "REF4111111111111111 confirmed"),
    # The lead guard also blocks a match preceded by "<digit><space>", which
    # ordinary text ending in a digit ("point 1", "step 2") triggers.
    ("card-19d-9-preceded-by-digit-space-unaffected", "point 1 9123456789123456789"),
    ("card-19d-other-preceded-by-digit-space-unaffected", "point 1 1234567891234567891"),
    # The JWT rule's leading "\b" blocks a match when "eyJ" is glued directly
    # to a word character.
    ("jwt-glued-to-letter-prefix-unmasked", f"abc{_JWT}"),
    ("jwt-glued-to-digit-prefix-unmasked", f"123{_JWT}"),
    ("jwt-glued-to-underscore-prefix-unmasked", f"_{_JWT}"),
    # Phone shares the card lead guard — "+" glued to a preceding letter
    # doesn't match.
    ("phone-glued-plus-to-letter-unmasked", "call+963912345678"),
]


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
        assert _mask({"event": "decrypted payment data", "source": _FakeCard()}) == {
            "event": "decrypted payment data",
            "source": "<Card(VISA, 512345******0008, 958418******4802)>",
        }

    def test_masks_object_nested_in_list_and_dict(self):
        assert _mask({"data": {"cards": [{"instrument": _FakeCard()}]}}) == {
            "data": {
                "cards": [
                    {"instrument": "<Card(VISA, 512345******0008, 958418******4802)>"}
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
        assert _mask("card 5123 4500 0000 0008") == "card 512345******0008"


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
            # Not expiry: a safe key now, so it reads through even inside a
            # PII container, month and year intact.
            ("expiry", {"month": "1", "year": "28"}, {"month": "1", "year": "28"}),
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
        assert out == '{"nameOnCard": "[NAME-MASKED]", "ref": 411111******1111}'

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
