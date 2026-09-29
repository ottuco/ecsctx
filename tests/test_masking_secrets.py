"""A credential masks alike on every path into a log, and a fixed marker never
stands where a token can.

| Value                                                 | With a keyset       | Without           |
|-------------------------------------------------------|---------------------|-------------------|
| a secret                                              | its `ptok:v1:` token | `[SECRET-MASKED]` |
| a secret shaped like a card number                    | `[SECRET-MASKED]`   | `[SECRET-MASKED]` |
| a placeholder another masker left (`[REDACTED]`, `***`) | `[SECRET-MASKED]`   | `[SECRET-MASKED]` |
| empty                                                 | empty               | empty             |

A secret shaped like a card number -- a saved card's sixteen-digit gateway
token, Luhn-valid or not -- was the label under a credential key only: the
credential text rules and a route parameter hashed it, a keyed hash of what
may be a PAN (PCI DSS FAQ 1117). A placeholder was hashed too, into one token
shared by every record that carried it: a credential that was never there.

Every test runs with a keyset and without one. An expected token is computed
by ecsctx under the same keyset, never written out.
"""

import pytest
from django.test import RequestFactory
from django.urls import path, re_path, resolve

import ecsctx
import ecsctx.masking
from ecsctx.contrib.django.routes import loggable_path
from ecsctx.masking import mask_by_field_type, mask_secret
from ecsctx.masking import patterns as masking_patterns
from ecsctx.masking.patterns import ALL_PACKS, mask_by_patterns, rules_for
from ecsctx.pii import configure_pii, is_configured, tokenize
from ecsctx.processors import mask_sensitive_data

SECRET = "s3cr3t-Hunter2"
LABEL = "[SECRET-MASKED]"
# A saved card's gateway token is sixteen digits: Luhn-valid, and not.
CARD_SHAPED = ["4111111111111111", "9923960000004314"]
PLACEHOLDERS = ["[REDACTED]", "[PII_REDACTED]", "*", "***", "****", "Bearer ****"]


@pytest.fixture(autouse=True, params=["keyset", "no keyset"])
def mode(request, token_keyset_path):
    if request.param == "keyset":
        configure_pii(token_keyset_path=token_keyset_path, env="test")
    return request.param


def token_or_label(value: str) -> str:
    """A plain secret as it must read in the mode in force."""
    return tokenize(value, "secret") if is_configured() else LABEL


def test_the_modes_are_what_they_say(mode):
    assert token_or_label(SECRET).startswith("ptok:v1:") == (mode == "keyset")


class TestMaskByFieldType:
    def test_a_secret_is_its_token_or_the_label(self):
        assert mask_by_field_type(SECRET, "secret") == token_or_label(SECRET)

    @pytest.mark.parametrize("value", CARD_SHAPED)
    def test_a_secret_shaped_like_a_card_number_is_the_label(self, value):
        assert mask_by_field_type(value, "secret") == LABEL

    @pytest.mark.parametrize("value", PLACEHOLDERS)
    def test_a_placeholder_is_the_label(self, value):
        assert mask_by_field_type(value, "secret") == LABEL

    def test_an_empty_value_stays_empty(self):
        assert mask_by_field_type("", "secret") == ""

    def test_a_value_masking_produced_passes_through(self):
        for value in (token_or_label(SECRET), LABEL, "411111******1111"):
            assert mask_by_field_type(value, "secret") == value


class TestMaskSecret:
    """A credential that reaches a log outside a mapping -- a URL, a body a
    service masks itself -- masked as a credential key's value is."""

    def test_a_secret_is_its_token_or_the_label(self):
        assert mask_secret(SECRET) == token_or_label(SECRET)

    @pytest.mark.parametrize("value", CARD_SHAPED)
    def test_a_secret_shaped_like_a_card_number_is_the_label(self, value):
        assert mask_secret(value) == LABEL

    @pytest.mark.parametrize("value", PLACEHOLDERS)
    def test_a_placeholder_is_the_label(self, value):
        assert mask_secret(value) == LABEL

    def test_an_empty_value_stays_empty(self):
        assert mask_secret("") == ""

    @pytest.mark.parametrize("value", [None, True, False])
    def test_a_null_or_a_flag_comes_back_as_it_is(self, value):
        assert mask_secret(value) is value

    def test_anything_else_is_masked_as_its_text(self):
        assert mask_secret(4111111111111111) == LABEL
        assert mask_secret(20260929) == token_or_label("20260929")

    def test_it_masks_as_the_key_walk_does(self):
        for value in (SECRET, *CARD_SHAPED, *PLACEHOLDERS, ""):
            assert mask_secret(value) == _walk({"password": value})["password"]


@pytest.mark.parametrize("name", ["mask_secret", "mask_card_value"])
def test_exported_from_the_masking_package_and_the_root(name):
    assert getattr(ecsctx, name) is getattr(ecsctx.masking, name) is getattr(masking_patterns, name)
    assert name in ecsctx.__all__
    assert name in ecsctx.masking.__all__


def _walk(data: dict) -> dict:
    return mask_sensitive_data(None, "info", dict(data))


class TestTheKeyWalk:
    @pytest.mark.parametrize("value", PLACEHOLDERS)
    def test_a_placeholder_under_a_credential_key_is_the_label(self, value):
        assert _walk({"password": value})["password"] == LABEL

    def test_an_authorization_header_another_masker_starred_is_the_label(self):
        assert _walk({"Authorization": "Bearer ****"})["Authorization"] == LABEL


_TEXT_RULES = rules_for(ALL_PACKS)
# Rule 2 (a quoted key), rule 3 (`key=value`) and rule 8 (an auth scheme).
CREDENTIAL_TEXTS = [
    'sent {"password": "%s"} to the gateway',
    "login with password=%s failed",
    "retried with Bearer %s",
]


class TestTheCredentialTextRules:
    @pytest.mark.parametrize("text", CREDENTIAL_TEXTS)
    def test_a_secret_is_its_token_or_the_label(self, text):
        assert mask_by_patterns(text % SECRET, _TEXT_RULES) == text % token_or_label(SECRET)

    @pytest.mark.parametrize("value", CARD_SHAPED)
    @pytest.mark.parametrize("text", CREDENTIAL_TEXTS)
    def test_a_secret_shaped_like_a_card_number_is_the_label(self, text, value):
        assert mask_by_patterns(text % value, _TEXT_RULES) == text % LABEL

    @pytest.mark.parametrize("value", ["[REDACTED]", "***"])
    def test_a_placeholder_under_a_quoted_key_is_the_label(self, value):
        # Rules 3 and 8 never take one: their value starts with a credential
        # character, which `[` and `*` are not.
        assert mask_by_patterns(CREDENTIAL_TEXTS[0] % value, _TEXT_RULES) == CREDENTIAL_TEXTS[0] % LABEL

    def test_an_empty_value_stays_empty(self):
        text = CREDENTIAL_TEXTS[0] % ""
        assert mask_by_patterns(text, _TEXT_RULES) == text


def _view(request):
    raise AssertionError("resolved, never called")


# `resolve()` below runs against these, as a service's own urlconf would.
urlpatterns = [
    path("v1/cards/<str:token>/", _view),
    re_path(r"^v1/receipts/(?P<token>[^/]*)/$", _view),
]


def _loggable_path(url_path: str) -> str:
    request = RequestFactory().delete(url_path)
    request.resolver_match = resolve(url_path, urlconf=__name__)
    return loggable_path(request)


class TestARouteParameter:
    def test_a_secret_is_its_token_or_the_label(self):
        assert _loggable_path(f"/v1/cards/{SECRET}/") == f"/v1/cards/{token_or_label(SECRET)}/"

    @pytest.mark.parametrize("value", CARD_SHAPED)
    def test_a_card_token_shaped_like_a_card_number_is_the_label(self, value):
        assert _loggable_path(f"/v1/cards/{value}/") == f"/v1/cards/{LABEL}/"

    @pytest.mark.parametrize("value", ["[REDACTED]", "***"])
    def test_a_placeholder_is_the_label(self, value):
        assert _loggable_path(f"/v1/cards/{value}/") == f"/v1/cards/{LABEL}/"

    def test_an_empty_value_stays_empty(self):
        assert _loggable_path("/v1/receipts//") == "/v1/receipts//"
