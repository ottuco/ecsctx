"""A credential masks alike on every path into a log, and a fixed marker never
stands where a token can.

| Value                                        | With a keyset          | Without           |
|----------------------------------------------|------------------------|-------------------|
| a secret                                     | its token (`ptok:v1:`) | `[SECRET-MASKED]` |
| a secret shaped like a card number           | `[SECRET-MASKED]`      | `[SECRET-MASKED]` |
| a placeholder (`[REDACTED]`, `***`)          | `[SECRET-MASKED]`      | `[SECRET-MASKED]` |
| a token's shape with a card number in it     | `[SECRET-MASKED]`      | `[SECRET-MASKED]` |
| a secret holding a card number, `pci` pack   | `[SECRET-MASKED]`      | `[SECRET-MASKED]` |
| a secret holding a card number, without it   | its token              | `[SECRET-MASKED]` |
| empty                                        | empty                  | empty             |

A secret shaped like a card number -- a saved card's sixteen-digit gateway
token, Luhn-valid or not -- was the label under a credential key only: the
credential text rules and a route parameter hashed it, a keyed hash of what
may be a PAN (PCI DSS FAQ 1117). A placeholder another masker left was hashed
too, into one token shared by every record that carried it: a credential that
was never there. And `ecsctx.contrib.net` wrote `[REDACTED]` whatever the
keyset.

Every test runs with a keyset and without one. An expected token is computed
by ecsctx under the same keyset, never written out.
"""

import dataclasses
import json
import logging
import re
from urllib.parse import quote, unquote, urlsplit

import pytest
from django.test import RequestFactory
from django.urls import path, re_path, resolve

import ecsctx
import ecsctx.masking
from ecsctx.contrib.django.routes import loggable_path
from ecsctx.contrib.net import configure_redaction, ecs_url, loggable_body, redact_body, redact_url
from ecsctx.masking import mask_by_field_type, mask_secret
from ecsctx.masking import patterns as masking_patterns
from ecsctx.masking.config import configure_masking_packs
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS, mask_by_patterns, rules_for
from ecsctx.masking.tokens import make_label
from ecsctx.pii import configure_pii, is_configured, tokenize
from ecsctx.pii.crypto import hmac_tokenize
from ecsctx.processors import mask_sensitive_data

SECRET = "s3cr3t-Hunter2"
LABEL = "[SECRET-MASKED]"
# A saved card's gateway token is sixteen digits: Luhn-valid, and not.
CARD_SHAPED = ["4111111111111111", "9923960000004314"]
PLACEHOLDERS = ["[REDACTED]", "[PII_REDACTED]", "*", "***", "****", "Bearer ****"]
# A card truncation after an auth scheme: the card rule's output, or another
# masker's, where a credential stood.
SCHEMED_TRUNCATIONS = ["Bearer 411111******1111", "Basic 411111******1111", "Bearer ********1111", "token 411111******1111"]


@pytest.fixture(autouse=True, params=["keyset", "no-keyset"])
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
        for value in (token_or_label(SECRET), LABEL):
            assert mask_by_field_type(value, "secret") == value

    @pytest.mark.parametrize("value", ["411111******1111", '"411111******1111"', "411111%2A%2A%2A%2A%2A%2A1111"])
    def test_a_truncation_is_the_label(self, value):
        # Ten digits of a saved card's sixteen-digit gateway token: a
        # credential the card rule truncated shows too much of itself.
        assert mask_by_field_type(value, "secret") == LABEL

    @pytest.mark.parametrize("value", SCHEMED_TRUNCATIONS)
    def test_a_truncation_after_a_scheme_is_the_label(self, value):
        # #160054: with a keyset it was hashed whole, a token of the scheme
        # and the truncation.
        assert mask_by_field_type(value, "secret") == LABEL
        assert mask_secret(value) == LABEL


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
# Rule 5 (a quoted key), rule 7 (`key=value`) and rule 13 (an auth scheme).
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
        # Rules 7 and 13 never take `[REDACTED]`: a value never starts with `[`,
        # which opens a label. `***` after `=` is the label too (below).
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


class TestALiteralSecretInAUrl:
    def test_a_secret_is_its_token_or_the_label(self):
        url = redact_url(f"https://h/pbl/card/{SECRET}/", secrets=[SECRET])
        assert url == f"https://h/pbl/card/{token_or_label(SECRET)}/"

    @pytest.mark.parametrize("value", CARD_SHAPED)
    def test_a_secret_shaped_like_a_card_number_is_the_label(self, value):
        assert redact_url(f"https://h/pbl/card/{value}/", secrets=[value]) == f"https://h/pbl/card/{LABEL}/"

    @pytest.mark.parametrize("value", ["[REDACTED]", "***"])
    def test_a_placeholder_is_the_label(self, value):
        assert redact_url(f"https://h/pbl/card/{value}/", secrets=[value]) == f"https://h/pbl/card/{LABEL}/"

    def test_an_empty_secret_masks_nothing(self):
        assert redact_url("https://h/pbl/card/x/", secrets=[""]) == "https://h/pbl/card/x/"

    @pytest.mark.parametrize("short", ["SECRET", "ptok", "v1"])
    def test_a_short_secret_never_matches_inside_what_a_longer_one_became(self, short):
        # Masked one after another, a short secret was found again inside the
        # label or token the longer one had just become, and mangled it.
        url = redact_url(f"https://h/pbl/card/{SECRET}/", secrets=[SECRET, short])
        assert url == f"https://h/pbl/card/{token_or_label(SECRET)}/"


class TestACredentialQueryParam:
    def test_a_secret_is_its_token_or_the_label(self):
        url = redact_url(f"https://h/pay?password={SECRET}&order_id=42")
        assert url == f"https://h/pay?password={token_or_label(SECRET)}&order_id=42"

    @pytest.mark.parametrize("value", CARD_SHAPED)
    def test_a_secret_shaped_like_a_card_number_is_the_label(self, value):
        url = redact_url(f"https://h/pay?card_token={value}&order_id=42")
        assert url == f"https://h/pay?card_token={LABEL}&order_id=42"

    @pytest.mark.parametrize("value", ["[REDACTED]", "%5BREDACTED%5D", "***"])
    def test_a_placeholder_is_the_label(self, value):
        url = redact_url(f"https://h/pay?password={value}&order_id=42")
        assert url == f"https://h/pay?password={LABEL}&order_id=42"

    def test_an_empty_value_stays_empty(self):
        assert redact_url("https://h/pay?password=&order_id=42") == "https://h/pay?password=&order_id=42"

    def test_an_encoded_value_is_masked_as_what_it_decodes_to(self):
        # So it carries the token the same value gets under a key.
        url = redact_url("https://h/pay?password=a%2Bb+c")
        assert url == f"https://h/pay?password={token_or_label('a+b c')}"


def test_an_unparseable_url_is_masked_whole_as_a_secret():
    assert redact_url("http://[::1") == token_or_label("http://[::1")


BODIES = {
    "json": '{"password": "%s", "status": "ok"}',
    "form": "password=%s&grant_type=client_credentials",
}


@pytest.mark.parametrize("body", list(BODIES.values()), ids=list(BODIES))
class TestACredentialInABody:
    def test_a_secret_is_its_token_or_the_label(self, body):
        assert redact_body(body % SECRET) == body % token_or_label(SECRET)

    @pytest.mark.parametrize("value", CARD_SHAPED)
    def test_a_secret_shaped_like_a_card_number_is_the_label(self, body, value):
        assert redact_body(body % value) == body % LABEL

    @pytest.mark.parametrize("value", ["[REDACTED]", "***"])
    def test_a_placeholder_is_the_label(self, body, value):
        assert redact_body(body % value) == body % LABEL

    def test_an_empty_value_stays_empty(self, body):
        assert redact_body(body % "") == body % ""

    def test_a_value_masking_produced_passes_through(self, body):
        for value in (token_or_label(SECRET), LABEL):
            assert redact_body(body % value) == body % value

    def test_a_truncation_is_the_label(self, body):
        assert redact_body(body % "411111******1111") == body % LABEL


class TestABodyValueIsMaskedAsWhatItDecodesTo:
    """So it carries the token the same value gets under a key."""

    def test_a_json_escape(self):
        masked = redact_body('{"password": "a\\"b"}')
        assert json.loads(masked) == {"password": token_or_label('a"b')}

    def test_a_form_encoding(self):
        assert redact_body("password=a%2Bb+c") == f"password={token_or_label('a+b c')}"


def test_every_path_gives_a_secret_the_same_token():
    """The key walk, a credential text rule, a credential query param and a
    body: one secret, one token -- or, without a keyset, one label."""
    expected = token_or_label(SECRET)
    assert _walk({"password": SECRET})["password"] == expected
    assert mask_by_patterns(f"password={SECRET}", _TEXT_RULES) == f"password={expected}"
    assert redact_url(f"https://h/pay?password={SECRET}") == f"https://h/pay?password={expected}"
    assert redact_body(f'{{"password": "{SECRET}"}}') == f'{{"password": "{expected}"}}'


# The tokenizer hashes a value without its surrounding whitespace and one layer
# of matching quotes (ecsctx.pii.normalize), so a card number or a placeholder
# in quotes was hashed bare: the checks must run on what is hashed.
QUOTED_CARDS = [
    *(f'"{card}"' for card in CARD_SHAPED),
    *(f"'{card}'" for card in CARD_SHAPED),
    '" 4111111111111111 "',
]
QUOTED = [*QUOTED_CARDS, '"***"', "'[REDACTED]'", '"[PII_REDACTED]"', "'Bearer ****'"]


# Encoded as a URL or a form encodes it, which redact_url and redact_body
# decode before they mask: decoded, a card number or a placeholder.
ENCODED = ["%224111111111111111%22", "4111+1111+1111+1111", "%5BREDACTED%5D", "Bearer+****"]


@pytest.mark.parametrize("packs", [["default"], sorted(ALL_PACKS)], ids=["default", "every-pack"])
class TestAnEncodedCardNumberOrPlaceholderIsTheLabel:
    @pytest.mark.parametrize("value", ENCODED)
    def test_mask_secret(self, packs, value):
        configure_masking_packs(packs)
        assert mask_secret(value) == LABEL

    @pytest.mark.parametrize("value", ENCODED)
    def test_a_credential_text_rule(self, packs, value):
        configure_masking_packs(packs)
        assert mask_by_patterns(f"password={value}&x=1", _TEXT_RULES) == f"password={LABEL}&x=1"

    def test_a_label_encoded_in_a_url_is_left_as_written(self, packs):
        configure_masking_packs(packs)
        assert mask_secret("%5BSECRET-MASKED%5D") == "%5BSECRET-MASKED%5D"


class TestAQuotedCardNumberOrPlaceholderIsTheLabel:
    @pytest.mark.parametrize("value", QUOTED)
    def test_mask_by_field_type(self, value):
        assert mask_by_field_type(value, "secret") == LABEL

    @pytest.mark.parametrize("value", QUOTED)
    def test_mask_secret(self, value):
        assert mask_secret(value) == LABEL

    @pytest.mark.parametrize("value", QUOTED)
    def test_the_key_walk(self, value):
        assert _walk({"password": value})["password"] == LABEL

    @pytest.mark.parametrize("value", QUOTED_CARDS)
    def test_a_credential_text_rule(self, value):
        # A quoted value runs to its closing quote: the quotes stay, and all
        # that is between them, spaces too, is the value.
        text = f"login with password={value} failed"
        assert mask_by_patterns(text, _TEXT_RULES) == f"login with password={value[0]}{LABEL}{value[0]} failed"

    @pytest.mark.parametrize("value", QUOTED)
    def test_a_route_parameter(self, value):
        assert _loggable_path(f"/v1/cards/{value}/") == f"/v1/cards/{LABEL}/"

    @pytest.mark.parametrize("value", QUOTED)
    def test_a_literal_secret_in_a_url(self, value):
        assert redact_url(f"https://h/pbl/card/{value}/", secrets=[value]) == f"https://h/pbl/card/{LABEL}/"

    @pytest.mark.parametrize("key", ["password", "api_key"])
    @pytest.mark.parametrize("value", QUOTED)
    def test_a_credential_query_param(self, key, value):
        url = redact_url(f"https://h/pay?{key}={quote(value, safe='')}&order_id=42")
        assert url == f"https://h/pay?{key}={LABEL}&order_id=42"
        assert redact_url(url) == url

    @pytest.mark.parametrize("value", QUOTED)
    def test_a_json_body(self, value):
        masked = redact_body(json.dumps({"password": value, "status": "ok"}))
        assert json.loads(masked) == {"password": LABEL, "status": "ok"}
        assert redact_body(masked) == masked

    def test_a_json_body_with_unicode_escapes(self):
        masked = redact_body('{"password": "\\u00224111111111111111\\u0022"}')
        assert masked == f'{{"password": "{LABEL}"}}'

    @pytest.mark.parametrize(
        "value", ["'4111111111111111'", "%224111111111111111%22", "%279923960000004314%27", "'***'"]
    )
    def test_a_form_body(self, value):
        masked = redact_body(f"password={value}&grant_type=x")
        assert masked == f"password={LABEL}&grant_type=x"
        assert redact_body(masked) == masked


class TestAFormValueInQuotes:
    """A form value that starts with a quote -- an XML attribute, `key="value"`
    in an error message -- is masked between its quotes, which stay."""

    def test_a_secret_is_its_token_or_the_label(self):
        assert redact_body(f'password="{SECRET}"&x=1') == f'password="{token_or_label(SECRET)}"&x=1'

    @pytest.mark.parametrize("value", CARD_SHAPED)
    def test_a_secret_shaped_like_a_card_number_is_the_label(self, value):
        assert redact_body(f'password="{value}"&x=1') == f'password="{LABEL}"&x=1'

    @pytest.mark.parametrize(
        "body",
        [
            '<Auth password="s3cr3tVALUE" authkey="k3yVALUE" apikey="ap1VALUE"/>',
            'error: client_secret="s3cr3tVALUE" rejected',
            'status=error&password=ab"cd-TAIL&x=1',
        ],
    )
    def test_every_value_is_masked_once(self, body):
        masked = redact_body(body)
        assert "VALUE" not in masked
        assert "TAIL" not in masked
        assert redact_body(masked) == masked


class TestAJsonValueTheParserRejects:
    """A body json.loads rejects reaches redact_body as text: a value holding
    an escape JSON does not know, or one cut before its closing quote."""

    def test_a_value_that_does_not_decode_is_masked_as_written(self):
        value = "abc-SECRET\\\nmore"
        masked = redact_body(f'{{"password": "{value}"}}')
        assert masked == f'{{"password": {json.dumps(token_or_label(value))}}}'
        assert redact_body(masked) == masked

    def test_a_value_cut_before_its_closing_quote_is_masked_to_the_end(self):
        masked = redact_body(f'{{"id": 1, "password": "{SECRET}')
        assert masked == f'{{"id": 1, "password": "{token_or_label(SECRET)}"'
        assert redact_body(masked) == masked

    @pytest.mark.parametrize("value", CARD_SHAPED)
    def test_a_card_number_cut_before_its_closing_quote_is_the_label(self, value):
        assert redact_body(f'{{"password": "{value}') == f'{{"password": "{LABEL}"'


class TestAdjacentJsonMembers:
    """Malformed JSON with no separator between two members, where one quote
    both closes a value and opens the next key: consumed with the first
    value, it hid the next key, whose value shipped in clear."""

    def test_the_next_value_is_masked_too(self):
        masked = redact_body('{"password": ""password": "hunter2"}')
        assert masked == f'{{"password": ""password": "{token_or_label("hunter2")}"}}'
        assert redact_body(masked) == masked

    def test_masked_twice_it_is_masked_once(self):
        # A randomized check's counterexample: the first pass left the second
        # value in clear, and the second pass, no longer blind to it, masked it.
        body = '#password=#password=[SECRET-MASKED]"password": ""password": "\\ \\\'[REDACTED]}\']}'
        once = redact_body(body)
        assert "[REDACTED]}" not in once
        assert redact_body(once) == once

    def test_a_well_formed_body_keeps_one_closing_quote_per_value(self):
        body = '{"password": "abc", "client_secret": "", "nested": {"api_key": "k-1"}, "status": "ok"}'
        masked = redact_body(body)
        assert masked == (
            f'{{"password": "{token_or_label("abc")}", "client_secret": "", '
            f'"nested": {{"api_key": "{token_or_label("k-1")}"}}, "status": "ok"}}'
        )
        assert json.loads(masked)
        assert redact_body(masked) == masked


# What masking itself wrote, in quotes: the credential text rule keeps a
# value's quotes around its label (`password="[SECRET-MASKED]"`), and a JSON
# string escapes them.
QUOTED_MARKERS = ['"[SECRET-MASKED]"', "'[SECRET-MASKED]'", '" [CARD-MASKED] "']


class TestAMarkerInQuotesIsMaskedAlready:
    """Masked already once its quotes are dropped, a value is left as it is:
    hashed, every one of them would be one token shared by every record."""

    @pytest.mark.parametrize("value", QUOTED_MARKERS)
    def test_mask_secret(self, value):
        assert mask_secret(value) == value

    def test_mask_secret_on_a_quoted_token(self):
        value = f'"{token_or_label(SECRET)}"'
        assert mask_secret(value) == value

    @pytest.mark.parametrize("value", QUOTED_MARKERS)
    def test_the_key_walk(self, value):
        assert _walk({"password": value})["password"] == value

    @pytest.mark.parametrize("value", QUOTED_MARKERS)
    def test_a_json_body(self, value):
        body = json.dumps({"password": value, "status": "ok"})
        assert redact_body(body) == body


def _escaped_form_body(value: str) -> str:
    """A form body inside a JSON string: the value's quotes are escaped."""
    return json.dumps({"note": f'password="{value}"&x=1'})


class _Reply:
    status_code = 200
    headers = {"Content-Type": "application/json"}

    def __init__(self, text: str):
        self.text = text


class TestAFormValueInEscapedQuotes:
    """`password=\\"…\\"` inside a JSON string. The escaped quotes stay as
    structure, and the value between them is unescaped before the checks and
    the hash; a value masking already wrote is left as it is written."""

    @pytest.mark.parametrize("value", [*CARD_SHAPED, "***"])
    def test_a_card_number_or_placeholder_is_the_label(self, value):
        masked = redact_body(_escaped_form_body(value))
        assert json.loads(masked) == {"note": f'password="{LABEL}"&x=1'}
        assert redact_body(masked) == masked

    def test_a_secret_is_its_token_or_the_label(self):
        masked = redact_body(_escaped_form_body(SECRET))
        assert json.loads(masked) == {"note": f'password="{token_or_label(SECRET)}"&x=1'}
        assert redact_body(masked) == masked

    def test_a_truncation_is_the_label(self):
        masked = redact_body(_escaped_form_body("411111******1111"))
        assert json.loads(masked) == {"note": f'password="{LABEL}"&x=1'}

    @pytest.mark.parametrize("value", [LABEL])
    def test_a_masked_value_is_left_as_written(self, value):
        body = _escaped_form_body(value)
        assert redact_body(body) == body

    def test_a_token_is_left_as_written(self):
        body = _escaped_form_body(token_or_label(SECRET))
        assert redact_body(body) == body

    # Through loggable_body the key walk's credential text rule masks the
    # value first, keeping its quotes; redact_body leaves what it wrote.
    @pytest.mark.parametrize("value", CARD_SHAPED)
    def test_through_loggable_body_a_card_number_is_the_label(self, value):
        logged = loggable_body(_Reply(_escaped_form_body(value)))
        assert json.loads(logged) == {"note": f'password="{LABEL}"&x=1'}
        assert loggable_body(_Reply(logged)) == logged

    def test_through_loggable_body_a_placeholder_is_the_label(self):
        logged = loggable_body(_Reply(_escaped_form_body("***")))
        assert json.loads(logged) == {"note": f'password="{LABEL}"&x=1'}
        assert loggable_body(_Reply(logged)) == logged

    def test_through_loggable_body_a_secret_keeps_the_key_walks_token(self):
        logged = loggable_body(_Reply(_escaped_form_body(SECRET)))
        assert json.loads(logged) == {"note": f'password="{token_or_label(SECRET)}"&x=1'}
        assert loggable_body(_Reply(logged)) == logged

    def test_through_loggable_body_a_masked_value_is_left_as_written(self):
        body = _escaped_form_body(LABEL)
        assert loggable_body(_Reply(body)) == body


PAN = "4111111111111111"


class TestAFormValueRunsToItsEnd:
    """A form value is everything up to the next `&` or whitespace, as in
    0.15.3, or an end tag. Only the structure at its two ends -- a quote or
    an escaped one, and `}`, `]`, `,`, `>` or `/>` at the end -- stays outside
    the mask; the rest is the value, however a quote inside it reads."""

    @pytest.mark.parametrize(
        ("body", "masked"),
        [
            ('<Auth password="4111111111111111" x="1"/>', f'<Auth password="{LABEL}" x="1"/>'),
            ('error: client_secret="4111111111111111" rejected', f'error: client_secret="{LABEL}" rejected'),
            ('<Auth apikey="4111111111111111"/>', f'<Auth apikey="{LABEL}"/>'),
            # An end tag ends it: before 0.15.6 the value took `</a` with it.
            ('<a href="/cb?password=4111111111111111">x</a>', f'<a href="/cb?password={LABEL}</a>'),
            ("password=4111111111111111, status=ok", f"password={LABEL}, status=ok"),
            ("password=4111111111111111;", f"password={LABEL}"),
            ("password=4111111111111111'", f"password={LABEL}"),
            ('password=ab",4111111111111111&x=1', f"password={LABEL}&x=1"),
            ('password="***" x', f'password="{LABEL}" x'),
            ('password="[REDACTED]" rejected', f'password="{LABEL}" rejected'),
            # What the credential text rule writes is masked already.
            ('password="[SECRET-MASKED]" rejected', 'password="[SECRET-MASKED]" rejected'),
            ("password=[SECRET-MASKED], status=ok", "password=[SECRET-MASKED], status=ok"),
            # A JSON value cut before its closing quote, run on to the end.
            ('{"password": "4111111111111111}', f'{{"password": "{LABEL}"'),
            ('{"id": 1, "password": "4111111111111111 x', f'{{"id": 1, "password": "{LABEL}"'),
        ],
    )
    def test_a_card_number_or_placeholder_is_the_label(self, body, masked):
        assert redact_body(body) == masked
        assert redact_body(masked) == masked

    def test_every_xml_attribute_is_masked_and_the_element_still_closes(self):
        masked = redact_body('<Auth password="s3cr3tVALUE" authkey="k3yVALUE" apikey="ap1VALUE"/>')
        t = token_or_label
        assert masked == f'<Auth password="{t("s3cr3tVALUE")}" authkey="{t("k3yVALUE")}" apikey="{t("ap1VALUE")}"/>'
        assert redact_body(masked) == masked

    @pytest.mark.parametrize("glue", ['",', '":', '"}', '"]'])
    def test_a_quote_inside_a_value_does_not_end_it(self, glue):
        value = f"ab{glue}cd-TAIL"
        masked = redact_body(f"password={value}&x=1")
        assert masked == f"password={token_or_label(value)}&x=1"
        assert redact_body(masked) == masked

    def test_whitespace_ends_a_value_as_it_did(self):
        # 0.15.3 stopped at the space too: what follows it is not the value.
        assert redact_body('password=ab" cd-TAIL&x=1') == f'password={token_or_label("ab")}" cd-TAIL&x=1'

    def test_a_query_in_a_json_string_keeps_the_strings_close(self):
        masked = redact_body('{"url": "https://x?secret=abc"}')
        assert masked == f'{{"url": "https://x?secret={token_or_label("abc")}"}}'
        assert json.loads(masked)

    def test_quotes_doubled_before_a_form_value_are_structure(self):
        # As the credential text rule reads them: the value after them gets
        # the token it gets there, and what the text rule wrote stays.
        assert redact_body('password=""abc123secret&x=1') == f'password=""{token_or_label("abc123secret")}&x=1'
        assert redact_body('password=""[SECRET-MASKED] x') == 'password=""[SECRET-MASKED] x'
        assert redact_body("password=''abc123&x=1") == f"password=''{token_or_label('abc123')}&x=1"
        assert redact_body("password=\"'abc123&x=1") == f"password=\"'{token_or_label('abc123')}&x=1"

    @pytest.mark.parametrize("text", ['password=""abc123&x=1', "password=''abc123&x=1", "password=\"'abc123&x=1"])
    def test_what_the_text_rule_wrote_after_doubled_quotes_stays(self, text):
        # Read as a value with its quotes, the token was hashed again.
        masked = mask_by_patterns(text, _TEXT_RULES)
        assert redact_body(masked) == masked

    def test_a_field_inside_another_fields_value_is_masked_in_one_pass(self):
        # The JSON rule rewrote the field holding it, uncovering it after the
        # form field pass had gone by: a second call labelled the CVV.
        text = '"password": "password="paymentCvv=cvv=123https://u:p@h/'
        masked = f'"password": "{token_or_label("password=")}"paymentCvv=[CVV-MASKED]'
        assert redact_body(text) == masked
        assert redact_body(masked) == masked

    def test_a_single_quote_before_a_form_value_is_its_own(self):
        # Closed by another, it is a quoted value: normalized, it carries the
        # token the key walk gives the value inside.
        quoted = "'abc123'"
        assert redact_body(f"password={quoted}&x=1") == f"password={mask_secret(quoted)}&x=1"

    def test_a_raw_form_value_is_never_unescaped(self):
        secret = "C:\\new\\tab"
        assert redact_body(f"password={secret}&x=1") == f"password={mask_secret(secret)}&x=1"

    def test_an_unquoted_value_before_a_self_closing_tag_keeps_only_its_gt(self):
        # A `/` right after a token reads to the credential text rule as more
        # of the credential: left outside the mask, the next pass hashed the
        # token again.
        masked = redact_body("<Auth password=s3cr3t/>")
        assert masked == f"<Auth password={token_or_label('s3cr3t/')}>"
        assert redact_body(mask_by_patterns(masked, _TEXT_RULES)) == masked

    def test_a_value_shaped_like_a_token_that_holds_a_card_number_is_the_label(self):
        # The card-number check comes before the pass-through for masked values.
        crafted = f"ptok:v1:{PAN}{'A' * 27}"
        assert redact_body(f"password={crafted}&x=1") == f"password={LABEL}&x=1"
        assert redact_body(f'{{"password": "{crafted}') == f'{{"password": "{LABEL}"'

    @pytest.mark.parametrize("value", [f"{PAN}*", f"ptok:v1:{PAN}{'A' * 27}"])
    def test_a_closed_json_value_that_holds_a_card_number_is_the_label(self, value):
        # Closed or not: a keyed hash of it was a keyed hash of a card number,
        # and a value shaped like a token passed through with one in it.
        masked = redact_body(f'{{"password": "{value}", "status": "ok"}}')
        assert masked == f'{{"password": "{LABEL}", "status": "ok"}}'
        assert redact_body(masked) == masked

    def test_escaped_xml_in_a_json_field_keeps_what_the_key_walk_wrote(self):
        logged = loggable_body(_Reply(json.dumps({"xml": f'<Auth apikey="{PAN}"/>'})))
        assert json.loads(logged) == {"xml": f'<Auth apikey="{LABEL}"/>'}
        assert loggable_body(_Reply(logged)) == logged


# Every shape a card number was hashed in, or left beside, by some capture.
PAN_SHAPES = [
    f'<Auth password="{PAN}" x="1"/>',
    f'error: client_secret="{PAN}" rejected',
    f'<Auth apikey="{PAN}"/>',
    f'<a href="/cb?password={PAN}">x</a>',
    f'{{"password": "{PAN}}}',
    f'{{"id": 1, "password": "{PAN} x',
    f"password={PAN}, status=ok",
    f"password={PAN};",
    f"password={PAN}'",
    f'password=ab",{PAN}&x=1',
    f'password={PAN}":cd&x=1',
    f'password="{PAN}"&x=1',
    f"password=%22{PAN}%22&x=1",
    json.dumps({"xml": f'<Auth apikey="{PAN}"/>'}),
    json.dumps({"note": f'password="{PAN}"&x=1'}),
    json.dumps({"note": f"password={PAN}&x=1"}),
    json.dumps({"password": f'"{PAN}"'}),
    json.dumps({"url": f"https://x?secret={PAN}"}),
    # Not `{"password": "<card number>*"}`: redact_body gives it the label
    # (test above), but without `pci` the key walk and the credential text
    # rules hash it first -- the accepted residual for a default-pack service,
    # which receives no card numbers (TestACredentialThatHoldsACardNumber).
    json.dumps({"password": f"ptok:v1:{PAN}{'A' * 27}"}),
]


def _pan_candidates(text: str) -> set[str]:
    """The token of every stretch of ``text``, or of a JSON string in it, that
    holds the card number: none of them may ever reach a log."""
    texts = [text]
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        texts += [value for value in parsed.values() if isinstance(value, str)]
    return {
        tokenize(t[start:end], "secret")
        for t in texts
        for start in range(len(t))
        for end in range(start + len(PAN), len(t) + 1)
        if PAN in t[start:end]
    }


def _outputs(text: str) -> list[str]:
    once = redact_body(text)
    return [
        once,
        redact_body(once),
        redact_body(mask_by_patterns(text, _TEXT_RULES)),
        mask_sensitive_data(None, "info", {"event": once})["event"],
        loggable_body(_Reply(text)),
    ]


@pytest.mark.parametrize("packs", [["default"], sorted(ALL_PACKS)], ids=["default", "every-pack"])
@pytest.mark.parametrize("shape", PAN_SHAPES)
def test_no_output_holds_the_card_number_or_a_hash_of_anything_holding_it(mode, packs, shape):
    configure_masking_packs(packs)
    # Tokens exist only with a keyset; without one, the label stands in.
    candidates = _pan_candidates(shape) if mode == "keyset" else set()
    for output in _outputs(shape):
        assert PAN not in output
        assert not candidates & set(re.findall(r"ptok:v1:[A-Za-z0-9_-]{43}", output))


@pytest.mark.parametrize(
    "shape",
    [
        *PAN_SHAPES,
        'password="s3cr3tVALUE" rejected',
        'password=ab",cd-TAIL&x=1',
        "<Auth password=s3cr3t/>",
        "password=:/>",
        # A form value redact_body labels, which the next text pass must not cut.
        "Basic CVV2=)card code<",
        # Doubled quotes before a value, then more after it.
        'password=""s3cr3t code""x',
        'password=""paymentCvv%2Bu:p@card code""(payment_id',
        "password=''abc123",
        "password=''s3cr3t code''x",
        # After a scheme word redact_body masks a form value the text rules
        # left (a label with more after it, a lone quote), and the scheme
        # word's bare-space rule read `password=<token>` as its credential and
        # hashed it again: a token of a token, a strict xfail until 0.15.6.
        'Bearer password=[SECRET-MASKED]"x',
        '123Authorization: Bearer password=[SECRET-MASKED]"note=#',
        "x Bearer note=password=[CVV-MASKED]'",
        "Bearer password='",
    ],
)
def test_the_text_rule_then_redact_body_twice_is_once(shape):
    def mask(text):
        return redact_body(mask_by_patterns(text, _TEXT_RULES))

    once = mask(shape)
    assert mask(once) == once


def test_a_credential_glued_to_a_key_name_after_a_scheme_is_still_hashed():
    # Why the scheme word's rule still reads `key=<token>`: here the digits
    # before the key name are a credential of their own.
    token = hmac_tokenize("x", bytes(32), "secret", "test")
    text = f"Token abc123abc123api_key={token}"
    masked = mask_by_patterns(text, _TEXT_RULES)
    assert "abc123abc123" not in masked
    assert masked == f"Token {token_or_label(f'abc123abc123api_key={token}')}"


# A value that holds a card number among other text, and `ptok:v1:` typed
# before one in a token's exact shape.
HOLDS_A_PAN = "abc4111111111111111xyz"
CRAFTED_TOKEN = f"ptok:v1:{PAN}{'A' * 27}"
A_UUID = "26888535-1296-4273-8ba1-c634e90bf52f"


def _every_path(value: str) -> dict[str, str]:
    """What ``value`` becomes as a credential on every path into a log, each
    reduced to the value it was masked to."""
    return {
        "key walk": _walk({"password": value})["password"],
        "mask_secret": mask_secret(value),
        **{text: mask_by_patterns(text % value, _TEXT_RULES) for text in CREDENTIAL_TEXTS},
        "query param": redact_url(f"https://h/pay?password={value}&order_id=42"),
        "route param": _loggable_path(f"/v1/cards/{value}/"),
    }


def _as_masked(masked: str) -> dict[str, str]:
    """What every path gives when the value is masked to ``masked``."""
    return {
        "key walk": masked,
        "mask_secret": masked,
        **{text: text % masked for text in CREDENTIAL_TEXTS},
        "query param": f"https://h/pay?password={masked}&order_id=42",
        "route param": f"/v1/cards/{masked}/",
    }


class TestACredentialThatHoldsACardNumber:
    """With `pci` among the call's packs, a credential holding a card-number
    run is its label on every path -- as the key walk's own `pci` branch
    already made it under a key -- since its hash is a keyed hash of a card
    number. Without `pci` among them it keeps its token: a default-pack
    service receives no card numbers, and labelling such values would label
    7% of 64-hex signatures."""

    def test_with_pci_it_is_the_label_on_every_path(self):
        configure_masking_packs(["pci"])
        assert _every_path(HOLDS_A_PAN) == _as_masked(LABEL)

    def test_without_pci_it_keeps_its_token(self):
        assert _every_path(HOLDS_A_PAN) == _as_masked(token_or_label(HOLDS_A_PAN))

    def test_with_pci_a_uuid_keeps_its_token(self):
        configure_masking_packs(["pci"])
        assert _every_path(A_UUID) == _as_masked(token_or_label(A_UUID))

    @pytest.mark.parametrize("packs", [["default"], ["pci"]])
    def test_a_percent_encoded_one_in_text_is_the_label_in_every_pack(self, packs):
        # A value runs to its delimiter, `%22` and all; decoded, as a URL or
        # form encoding reads it, it is a card number in quotes.
        configure_masking_packs(packs)
        text = "password=%224111111111111111%22&x=1"
        assert mask_by_patterns(text, _TEXT_RULES) == f"password={LABEL}&x=1"

    def test_masked_twice_it_is_masked_once(self):
        configure_masking_packs(["pci"])
        for text in CREDENTIAL_TEXTS:
            once = mask_by_patterns(text % HOLDS_A_PAN, _TEXT_RULES)
            assert mask_by_patterns(once, _TEXT_RULES) == once


def _payment_id(value: str) -> str:
    return tokenize(value, "payment_id") if is_configured() else "[PAYMENT-ID-MASKED]"


PAYMENT_ID_TEXTS = ["payment_id=%s", "transaction_id: %s done", "'auth_id': '%s'", "auth_id %s"]


class TestAPaymentIdThatHoldsACardNumber:
    """A payment id was `tokenize(<card number>, "payment_id")`: a keyed hash
    of the bare card number. With `pci` it is the label, as a credential is."""

    @pytest.mark.parametrize("value", [PAN, HOLDS_A_PAN])
    @pytest.mark.parametrize("text", PAYMENT_ID_TEXTS)
    def test_with_pci_it_is_the_label(self, text, value):
        configure_masking_packs(["pci", "financial_ids"])
        masked = mask_by_patterns(text % value, rules_for(ALL_PACKS))
        assert masked == text % "[PAYMENT-ID-MASKED]"
        assert mask_by_patterns(masked, rules_for(ALL_PACKS)) == masked

    @pytest.mark.parametrize("text", PAYMENT_ID_TEXTS)
    def test_without_pci_it_keeps_its_token(self, text):
        configure_masking_packs(["financial_ids"])
        rules = rules_for(frozenset({"default", "financial_ids"}))
        assert mask_by_patterns(text % PAN, rules) == text % _payment_id(PAN)

    def test_under_its_key_with_pci_it_is_the_label_too(self):
        configure_masking_packs(["pci", "financial_ids"])
        assert _walk({"payment_id": HOLDS_A_PAN}) == {"payment_id": "[PAYMENT-ID-MASKED]"}

    @pytest.mark.parametrize("text", PAYMENT_ID_TEXTS)
    def test_with_pci_a_uuid_keeps_its_token(self, text):
        configure_masking_packs(["pci", "financial_ids"])
        assert mask_by_patterns(text % A_UUID, rules_for(ALL_PACKS)) == text % _payment_id(A_UUID)


@pytest.mark.parametrize("packs", [["default"], sorted(ALL_PACKS)], ids=["default", "every-pack"])
class TestATokenShapedValueThatHoldsACardNumber:
    """`ptok:v1:` typed before a card number, in a token's exact shape, passed
    every check for masking's own output: in clear, card number and all, in
    every pack. It is the label, in every pack."""

    def test_on_every_path_it_is_the_label(self, packs):
        configure_masking_packs(packs)
        assert _every_path(CRAFTED_TOKEN) == _as_masked(LABEL)

    @pytest.mark.parametrize("field_type", ["secret", "payment_id", "email", "name", "generic"])
    def test_under_any_type_it_is_the_types_label(self, packs, field_type):
        configure_masking_packs(packs)
        assert mask_by_field_type(CRAFTED_TOKEN, field_type) == f"[{make_label(field_type)}]"

    def test_in_quotes_or_a_legacy_marker_it_is_the_label(self, packs):
        configure_masking_packs(packs)
        assert mask_secret(f'"{CRAFTED_TOKEN}"') == LABEL
        assert mask_by_field_type(f"[EMAIL-MASKED:{CRAFTED_TOKEN}]", "email") == "[EMAIL-MASKED]"

    def test_under_a_pii_key_it_is_the_label(self, packs):
        configure_masking_packs(packs)
        assert _walk({"customer_email": CRAFTED_TOKEN}) == {"customer_email": "[EMAIL-MASKED]"}

    def test_a_real_token_still_passes_through(self, packs):
        configure_masking_packs(packs)
        real = tokenize(SECRET, "secret") if is_configured() else LABEL
        assert _every_path(real) == _as_masked(real)


_DEFAULT_RULES = rules_for(frozenset({"default"}))
# Where each tail shipped: past a character the old value class did not know
# (a backslash, `@`, an apostrophe), or a key the old rules could not read
# (a JSON-escaped one). (text, the text around the value, the value masked.)
TAILS = [
    ("password=ab\\cd-TAIL1", "password=%s", "ab\\cd-TAIL1"),
    # A JSON string: masked as what it decodes to, `ab\cd-TAIL2`.
    ('password: "ab\\\\cd-TAIL2"', 'password: "%s"', "ab\\cd-TAIL2"),
    ('password=abc\\"def-TAIL4', "password=%s", 'abc\\"def-TAIL4'),
    ('{"password": "ab\\"cd-TAIL5"}', '{"password": "%s"}', 'ab"cd-TAIL5'),
    ('{\\"password\\": \\"hunter2-TAIL3\\"}', '{\\"password\\": \\"%s\\"}', "hunter2-TAIL3"),
    ("Bearer abc123\\def456-TAIL9", "Bearer %s", "abc123\\def456-TAIL9"),
    ('{"password": "it\'s-a-secret-TAIL"}', '{"password": "%s"}', "it's-a-secret-TAIL"),
    ("password=p@ss-TAIL", "password=%s", "p@ss-TAIL"),
    # Doubled quotes, as CSV and SQL escape one: no empty quoted value.
    ('password=""abc123secret', 'password=""%s', "abc123secret"),
    ('7,"password=""s3cret-X9"""', '7,"password=""%s"""', "s3cret-X9"),
]
# Where an unquoted value ends, and what stays inside one.
DELIMITED = [
    ("password=abc&x=1", "password=%s&x=1", "abc"),
    ("password=abc;x=1", "password=%s;x=1", "abc"),
    ("password=abc, x=1", "password=%s, x=1", "abc"),
    ("password=abc\tx=1", "password=%s\tx=1", "abc"),
    ("(password=abc)", "(password=%s)", "abc"),
    ("[password=abc]", "[password=%s]", "abc"),
    ("{password=abc}", "{password=%s}", "abc"),
    ("<password=abc>", "<password=%s>", "abc"),
    ('{"note": "password=abc"}', '{"note": "password=%s"}', "abc"),
    ("password=abc' x", "password=%s' x", "abc"),
    ("password=abc#frag~!$*", "password=%s", "abc#frag~!$*"),
    ('password=ab"cd-TAIL', "password=%s", 'ab"cd-TAIL'),
    ("password=ab''cd-TAIL", "password=%s", "ab''cd-TAIL"),
    ("password=ptok:v1:hunter2", "password=%s", "ptok:v1:hunter2"),
    ('{\\"api_key\\": 12345}', '{\\"api_key\\": \\"%s\\"}', "12345"),
]
# A quoted value runs to its unescaped closing quote, spaces and all.
QUOTED_VALUES = [
    ('password="a b&c" x', 'password="%s" x', "a b&c"),
    ("password='it\\'s' x", "password='%s' x", "it\\'s"),
    ("{'password': 'it\\'s'}", "{'password': '%s'}", "it\\'s"),
    ("{'password': \"it's here\"}", "{'password': \"%s\"}", "it's here"),
    ('Authorization: "Bearer abc123"', 'Authorization: "%s"', "Bearer abc123"),
    # JSON in a JSON string: a value between escaped quotes runs to its
    # matching one, masked as what it decodes to, twice.
    ('{\\"password\\": \\"correct horse battery staple\\"}', '{\\"password\\": \\"%s\\"}', "correct horse battery staple"),
    ('{\\"password\\": \\"a\\\\\\"b c\\"}', '{\\"password\\": \\"%s\\"}', 'a"b c'),
    ('note=password=\\"s3cr3t value\\"&x=1', 'note=password=\\"%s\\"&x=1', "s3cr3t value"),
]


@pytest.mark.parametrize("rules", [_DEFAULT_RULES, _TEXT_RULES], ids=["default", "every-pack"])
class TestACredentialValueRunsToItsDelimiter:
    """A credential value in text is everything up to its delimiter, as a
    form value in `redact_body` is: an unquoted one ends at whitespace, `&`,
    `;`, `,`, a closing quote or bracket; a quoted one at its unescaped
    closing quote. A fixed class of value characters left the rest of a
    value in clear after a character outside it."""

    @pytest.mark.parametrize(("text", "around", "value"), TAILS + DELIMITED + QUOTED_VALUES)
    def test_the_value_is_masked_whole_and_once(self, rules, text, around, value):
        masked = mask_by_patterns(text, rules)
        assert masked == around % token_or_label(value)
        assert mask_by_patterns(masked, rules) == masked

    @pytest.mark.parametrize(
        ("text", "around", "value"),
        [
            ("Basic CVV2=[CVV-MASKED] code", "Basic CVV2=[CVV-MASKED] code", None),
            ("password=abc[SECRET-MASKED] x", "password=%s[SECRET-MASKED] x", "abc"),
            ('password=abc"[SECRET-MASKED]', 'password=%s"[SECRET-MASKED]', "abc"),
        ],
    )
    def test_a_value_never_runs_into_a_label(self, rules, text, around, value):
        # A `]` ends a value: run into a label another path wrote, it cut the
        # label (`Basic [SECRET-MASKED]] code`).
        masked = mask_by_patterns(text, rules)
        assert masked == (around if value is None else around % token_or_label(value))
        assert mask_by_patterns(masked, rules) == masked

    def test_a_placeholder_after_a_separator_is_the_label(self, rules):
        # A star is a value character now; a placeholder is still the label.
        assert mask_by_patterns("password=*** x", rules) == f"password={LABEL} x"

    def test_a_json_escaped_value_gets_the_token_it_gets_under_its_key(self, rules):
        masked = mask_by_patterns('{"password": "ab\\"cd-TAIL5"}', rules)
        assert json.loads(masked) == _walk({"password": 'ab"cd-TAIL5'})

    @pytest.mark.parametrize(
        "text", ['password=""', "password=''", 'password=\\"\\"', "password=", 'password: "" x', '{"password": ""}']
    )
    def test_an_empty_value_stays_empty(self, rules, text):
        assert mask_by_patterns(text, rules) == text

    def test_a_token_in_doubled_quotes_is_left_as_it_is(self, rules):
        text = f'password=""{token_or_label(SECRET)}""'
        assert mask_by_patterns(text, rules) == text

    @pytest.mark.parametrize("text", ['password="abc', 'password: "abc def', "password='abc x"])
    def test_a_quote_nothing_closes_is_read_as_an_unquoted_value(self, rules, text):
        masked = mask_by_patterns(text, rules)
        assert "abc" not in masked
        assert mask_by_patterns(masked, rules) == masked


AUTHORIZATIONS = [
    "Bearer abc123def456ghi789",
    "Basic dXNlcjpwYXNzd29yZA==",
    "Digest dXNlcjpwYXNz",
    "Token abc123def456",
    "Negotiate YIIBhwYGKwYBBQUC",
    "Api-Key 1a2b3c4d5e6f",
]


class TestAnAuthorizationHeaderInText:
    """`Authorization: <scheme> <credential>` is one value, as the header is
    under its key: the text rule took the scheme for the value, so without a
    keyset the credential after it shipped in clear unless another rule
    caught it (`Basic dXNlcjpwYXNz` has no digit for the bare-space rule), and
    with one every record shared the scheme's token."""

    @pytest.mark.parametrize("header", AUTHORIZATIONS)
    @pytest.mark.parametrize(
        "text", ["Authorization: %s", "Proxy-Authorization: %s", "authorization=%s", "Authorization= %s", "authorisation_header: %s"]
    )
    def test_scheme_and_credential_are_one_token(self, text, header):
        masked = mask_by_patterns(text % header, _TEXT_RULES)
        assert masked == text % mask_secret(header)
        assert mask_by_patterns(masked, _TEXT_RULES) == masked

    def test_every_path_gives_the_header_the_same_token(self):
        header = "Bearer abc123def456ghi789"
        expected = mask_secret(header)
        configure_redaction(extra_secret_keys=["authorization"])
        assert _walk({"Authorization": header})["Authorization"] == expected
        assert mask_by_patterns(f"Authorization: {header}", _TEXT_RULES) == f"Authorization: {expected}"
        assert redact_url(f"https://h/pay?authorization={quote(header)}") == f"https://h/pay?authorization={expected}"
        assert redact_body(f'{{"Authorization": "{header}"}}') == f'{{"Authorization": "{expected}"}}'

    @pytest.mark.parametrize("text", ["Authorization: Bearer [REDACTED]", "Authorization: Bearer"])
    def test_a_scheme_alone_is_never_the_value_beside_a_placeholder(self, text):
        # `Bearer [REDACTED]` holds nothing to mask; the scheme alone, when
        # nothing follows it, is the header's whole value, as under its key.
        expected = text if text.endswith("]") else f"Authorization: {mask_secret('Bearer')}"
        assert mask_by_patterns(text, _TEXT_RULES) == expected

    @pytest.mark.parametrize(
        "text", ["Authorization: Bearer %s", "Authorization=Basic %s", "Proxy-Authorization: Token %s"]
    )
    def test_a_token_after_the_scheme_is_left_as_it_is(self, text):
        # What masked the credential alone left: hashed with its scheme, it
        # was a second token for the same credential.
        text = text % token_or_label(SECRET)
        assert mask_by_patterns(text, _TEXT_RULES) == text

    def test_a_starred_credential_is_the_label(self):
        assert mask_by_patterns("Authorization: Bearer ****", _TEXT_RULES) == f"Authorization: {LABEL}"

    def test_only_an_authorization_key_takes_a_scheme(self):
        # `password=basic more words` is a password, `basic`, and prose.
        masked = mask_by_patterns("password=basic more words", _TEXT_RULES)
        assert masked == f"password={token_or_label('basic')} more words"


def _part(value: str) -> str:
    """A userinfo part as it must read in text: empty stays empty."""
    return token_or_label(value) if value else value


def _url_part(value: str) -> str:
    """...and in a URL redact_url rebuilt, where a label's brackets are
    percent-encoded: a netloc holding them does not parse."""
    return _part(value).replace("[", "%5B").replace("]", "%5D")


class TestAUrlsUserinfoAndFragmentInRedactUrl:
    """`redact_url` masked credential query params only: a password in the
    userinfo (`https://user:pass@host`) or an OAuth implicit-grant token in
    the fragment (`#access_token=…`) reached `url.full` in clear."""

    def test_the_user_and_password_are_masked_and_the_host_kept(self):
        url = redact_url("https://user:pa55word@api.host.example:8443/v1/pay?order_id=42")
        assert url == f"https://{_url_part('user')}:{_url_part('pa55word')}@api.host.example:8443/v1/pay?order_id=42"
        assert urlsplit(url).hostname == "api.host.example"

    @pytest.mark.parametrize(
        ("url", "user", "password", "rest"),
        [
            ("https://key:@api.host/", "key", "", "api.host/"),
            ("redis://:s3cret@cache:6379/0", "", "s3cret", "cache:6379/0"),
            ("https://u%40corp:p%3Ass@host/", "u@corp", "p:ss", "host/"),
            ("https://u:p@ss@host/", "u", "p@ss", "host/"),
        ],
    )
    def test_each_part_is_masked_as_it_decodes_and_an_empty_one_stays_empty(self, url, user, password, rest):
        scheme = url.split("://")[0]
        assert redact_url(url) == f"{scheme}://{_url_part(user)}:{_url_part(password)}@{rest}"

    def test_a_user_alone_is_masked(self):
        assert redact_url("https://ghp_abc123@github.example/o/r") == f"https://{_url_part('ghp_abc123')}@github.example/o/r"

    def test_the_fragment_params_are_masked_as_the_query_params_are(self):
        url = redact_url("https://h/cb#access_token=abc123&state=xyz&scope=read")
        assert url == f"https://h/cb#access_token={_part('abc123')}&state=xyz&scope=read"

    def test_a_url_with_neither_is_left_as_written(self):
        for url in ("https://h/a?x=1#section-2", "https://h/a#", "https://h/a?"):
            assert redact_url(url) == url

    def test_a_token_shaped_user_that_holds_a_card_number_is_the_label(self):
        assert redact_url(f"https://{CRAFTED_TOKEN}@host.example/") == "https://%5BSECRET-MASKED%5D@host.example/"

    @pytest.mark.parametrize(
        "url",
        [
            "https://user:pa55word@api.host.example/v1/pay",
            "https://user@api.host.example/v1/pay",
            "https://key:@api.host/",
            "https://h/cb#access_token=abc123&state=xyz",
            # A token before a fragment: a whole token, not one run on into it.
            "https://h/cb?password=x1#access_token=abc123",
            "https://h/cb?password=x1#section",
        ],
    )
    def test_masked_twice_or_by_the_text_rules_it_is_masked_once(self, url):
        once = redact_url(url)
        assert redact_url(once) == once
        assert mask_by_patterns(once, _TEXT_RULES) == once
        assert "ptok:v1:ptok:v1:" not in once

    def test_ecs_url_masks_them_and_keeps_the_domain(self):
        shaped = ecs_url("https://user:pa55word@api.host.example/v1/pay#access_token=abc123")
        assert shaped == {
            "full": f"https://{_url_part('user')}:{_url_part('pa55word')}@api.host.example/v1/pay"
            f"#access_token={_part('abc123')}",
            "domain": "api.host.example",
            "path": "/v1/pay",
        }


# A URL's userinfo in free text -- a DSN in an exception message. (text, the
# text around the masked user and password, user, password.)
USERINFO_TEXTS = [
    ("could not connect postgresql://u:p@localhost:5432/db", "could not connect postgresql://%s:%s@localhost:5432/db", "u", "p"),
    ("amqp://u:p@10.0.0.5//", "amqp://%s:%s@10.0.0.5//", "u", "p"),
    ("GET https://key:@api.host/ failed", "GET https://%s:%s@api.host/ failed", "key", ""),
    ("redis://:s3cret@cache:6379/0 refused", "redis://%s:%s@cache:6379/0 refused", "", "s3cret"),
    ('{"dsn": "mongodb+srv://admin:s3cr3t@cluster0.example.net/app"}', '{"dsn": "mongodb+srv://%s:%s@cluster0.example.net/app"}', "admin", "s3cr3t"),
    ("fetch https://user:pa55word@api.host.example/v1/pay", "fetch https://%s:%s@api.host.example/v1/pay", "user", "pa55word"),
    ("amqp://u%40corp:p%3Ass@mq:5672/", "amqp://%s:%s@mq:5672/", "u@corp", "p:ss"),
    ("amqp://guest:5551234567@mq:5672/", "amqp://%s:%s@mq:5672/", "guest", "5551234567"),
]


class TestAUrlsUserinfoInText:
    """A URL's userinfo in free text is masked part by part, as redact_url
    masks it, keeping the scheme, host and port. Before, a DSN in exception
    text shipped whole, and `user:pw@host.tld` was masked, if at all, as an
    email -- the host with it."""

    @pytest.mark.parametrize(("text", "around", "user", "password"), USERINFO_TEXTS)
    def test_the_parts_are_masked_and_the_host_kept(self, text, around, user, password):
        masked = mask_by_patterns(text, _TEXT_RULES)
        assert masked == around % (_part(user), _part(password))
        assert mask_by_patterns(masked, _TEXT_RULES) == masked
        assert "ptok:v1:ptok:v1:" not in masked

    def test_it_gives_the_parts_the_tokens_redact_url_does(self):
        url = "https://user:pa55word@api.host.example/v1/pay"
        assert mask_by_patterns(url, _TEXT_RULES) == unquote(redact_url(url))

    def test_a_user_alone_is_left_to_the_other_rules(self):
        # No password, no credential: `ssh://git@host` names an account.
        text = "clone ssh://git@10.0.0.5/repo.git"
        assert mask_by_patterns(text, _TEXT_RULES) == text

    def test_without_a_scheme_the_email_rule_still_masks_what_it_did(self):
        text = "login user:pw@host.tld failed"
        email = tokenize("pw@host.tld", "email") if is_configured() else "[EMAIL-MASKED]"
        assert mask_by_patterns(text, _TEXT_RULES) == f"login user:{email} failed"

    def test_the_email_rule_never_starts_inside_a_token(self):
        # What redact_url leaves for a user alone: the host after it is no
        # email, and the token is kept whole.
        token = token_or_label("user")
        text = f"GET https://{token}@api.host.example/v1/pay"
        assert mask_by_patterns(text, _TEXT_RULES) == text

    def test_an_email_glued_after_a_token_is_still_masked(self):
        token = hmac_tokenize("user", bytes(32), "secret", "test")
        email = tokenize("jane@example.com", "email") if is_configured() else "[EMAIL-MASKED]"
        assert mask_by_patterns(f"x {token}jane@example.com y", _TEXT_RULES) == f"x {token}{email} y"

    def test_a_user_alone_before_a_host_is_still_masked_as_an_email(self):
        # No password: the userinfo rule leaves it, and the email rule masks
        # `john@example.com` as it did -- the host with it.
        email = tokenize("john@example.com", "email") if is_configured() else "[EMAIL-MASKED]"
        assert mask_by_patterns("GET https://john@example.com/v1", _TEXT_RULES) == f"GET https://{email}/v1"

    @pytest.mark.parametrize("rules", [_DEFAULT_RULES, _TEXT_RULES], ids=["default", "every-pack"])
    @pytest.mark.parametrize(
        "user",
        [
            # A saved card's gateway token, Luhn-valid and not, as redact_url
            # masks it: the label.
            *CARD_SHAPED,
            "4111-1111-1111-1111",
            # A user holding a card-number run.
            "abc4111111111111111xyz",
            "4111111111111111%40corp",
        ],
    )
    def test_a_user_alone_shaped_like_or_holding_a_card_number_is_the_label(self, rules, user):
        # #160054: in free text it shipped whole, while redact_url masked it.
        text = f"GET https://{user}@api.host.example/v1 failed"
        masked = mask_by_patterns(text, rules)
        assert masked == f"GET https://{LABEL}@api.host.example/v1 failed"
        assert mask_by_patterns(masked, rules) == masked

    def test_a_card_shaped_user_reads_as_redact_url_writes_it(self):
        url = f"https://{CARD_SHAPED[1]}@host.example/v1"
        assert mask_by_patterns(url, _TEXT_RULES) == unquote(redact_url(url))

    @pytest.mark.parametrize("text", ["clone ssh://git@10.0.0.5/repo.git", "GET https://u12345@gateway/x"])
    def test_any_other_user_alone_is_still_left_to_the_other_rules(self, text):
        assert mask_by_patterns(text, _TEXT_RULES) == text


# Values whose card number R4 now reads as part of the credential: 0.15.4's
# value class stopped at `@`, `\` or `%`, and the card rule truncated it.
CARD_IN_A_CREDENTIAL = [
    ("password=p@ss4111111111111111", "password=[SECRET-MASKED]"),
    ("password=ab\\cd4111111111111111", "password=[SECRET-MASKED]"),
    ("password=%224111111111111111%22&x=1", "password=[SECRET-MASKED]&x=1"),
    ("payment_id=4111111111111111", "payment_id=[PAYMENT-ID-MASKED]"),
]


def _record(msg, args) -> str:
    record = logging.LogRecord("t", logging.INFO, __file__, 0, msg, args, None)
    MaskPIIFilter().filter(record)
    return record.getMessage()


@dataclasses.dataclass
class _Login:
    user: str
    password: list


class TestABareApiKeyScheme:
    """Ottu PG sends `Authorization: API-Key <merchant key>` into Connect. Its
    own filter masked a bare `API-Key <key>` in text; ecsctx hashed the key
    alone and left the scheme word beside it -- another token than the
    header's. The scheme and the key are one value, as after Authorization:
    they carry the header's token, or the label."""

    @pytest.mark.parametrize(
        ("text", "value"),
        [
            ("sending API-Key abc123XYZ to core", "API-Key abc123XYZ"),
            ("headers={'X': 'API-Key abc123XYZ'}", "API-Key abc123XYZ"),
            ("retry with Api-Key abc123XYZ", "Api-Key abc123XYZ"),
            ("api-key abc123XYZ done", "api-key abc123XYZ"),
        ],
    )
    def test_the_scheme_and_the_key_are_one_value(self, text, value):
        masked = mask_by_patterns(text, _DEFAULT_RULES)
        assert masked == text.replace(value, mask_secret(value))
        assert mask_by_patterns(masked, _DEFAULT_RULES) == masked

    def test_it_carries_the_token_the_authorization_header_carries(self):
        header = mask_by_patterns("Authorization: API-Key abc123XYZ", _DEFAULT_RULES)
        bare = mask_by_patterns("sending API-Key abc123XYZ to core", _DEFAULT_RULES)
        assert header == f"Authorization: {mask_secret('API-Key abc123XYZ')}"
        assert bare == f"sending {mask_secret('API-Key abc123XYZ')} to core"
        assert _walk({"Authorization": "API-Key abc123XYZ"})["Authorization"] == mask_secret("API-Key abc123XYZ")

    @pytest.mark.parametrize(
        "key",
        [
            # A 44-character Fernet key with no digit (about 1 in 1,550 of Ottu
            # PG's), a short key, a two-character one: the scheme word is the
            # evidence, not the key's shape.
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR",
            "ab1cd2",
            "Zx",
        ],
    )
    @pytest.mark.parametrize("scheme", ["API-Key", "api-key"])
    def test_any_key_after_the_scheme_is_masked_whole(self, scheme, key):
        value = f"{scheme} {key}"
        masked = mask_by_patterns(f"calling core with {value} now", _DEFAULT_RULES)
        assert masked == f"calling core with {mask_secret(value)} now"
        assert mask_by_patterns(masked, _DEFAULT_RULES) == masked
        header = mask_by_patterns(f"Authorization: {value}", _DEFAULT_RULES)
        assert header == f"Authorization: {mask_secret(value)}"
        assert _walk({"Authorization": value})["Authorization"] == mask_secret(value)

    def test_a_field_inside_the_value_does_not_change_its_token(self):
        # The key=value rule runs after the scheme, as it does after
        # `Authorization:`: both forms carry one token for the whole value.
        value = "API-Key password=s3cr3tVALUE"
        assert mask_by_patterns(f"sending {value} now", _DEFAULT_RULES) == f"sending {mask_secret(value)} now"
        assert mask_by_patterns(f"Authorization: {value}", _DEFAULT_RULES) == f"Authorization: {mask_secret(value)}"

    def test_a_field_masking_wrote_after_the_scheme_is_not_hashed_again(self):
        # What redact_body leaves after the scheme word: its token stands.
        token = hmac_tokenize("s3cr3t", bytes(32), "secret", "test")
        text = f"API-Key password={token}"
        assert mask_by_patterns(text, _DEFAULT_RULES) == text

    @pytest.mark.parametrize("text", ["Bearer of bad news", "basic auth enabled", "Bearer abcdefghij"])
    def test_the_other_schemes_keep_their_guards(self, text):
        assert mask_by_patterns(text, _DEFAULT_RULES) == text

    def test_a_header_name_ending_in_the_word_is_no_scheme(self):
        # Only the scheme word itself: `X-API-Key <key>` names a header, and
        # its key alone is masked, as before.
        assert mask_by_patterns("X-API-Key abc123XYZ", _DEFAULT_RULES) == f"X-API-Key {token_or_label('abc123XYZ')}"


class TestAnAuthorizationHoldingATruncation:
    """`Authorization: Bearer <truncation>` is the label on every path, as a
    bare truncation is: a token of the scheme and the truncation stood where
    no token can."""

    @pytest.mark.parametrize("value", SCHEMED_TRUNCATIONS)
    def test_every_path(self, value):
        assert _walk({"Authorization": value})["Authorization"] == LABEL
        assert mask_by_patterns(f"Authorization: {value}", _TEXT_RULES) == f"Authorization: {LABEL}"
        assert mask_by_patterns(f"<Authorization>{value}</Authorization>", _TEXT_RULES) == (
            f"<Authorization>{LABEL}</Authorization>"
        )


class TestACredentialWordBeforeAContainer:
    """#160054: `password=%(pw)s` rendered with a list or dict printed
    `password=['a', 'b']` -- the credential rules never start a value at an
    opening bracket, and the key `pw` names nothing. The whole container is
    the credential's value now: its token, or the label."""

    @pytest.mark.parametrize(
        ("msg", "args", "value"),
        [
            ("password=%(pw)s", ({"pw": ["a", "b"]},), "['a', 'b']"),
            ("login password=%s rejected", (["s3cret", "x"],), "['s3cret', 'x']"),
            ("password: %s", ({"user": "bob", "code": "x1"},), "{'user': 'bob', 'code': 'x1'}"),
            ("api_key=%s", (("k1", "k2"),), "('k1', 'k2')"),
        ],
    )
    def test_a_rendered_container_is_masked_whole(self, msg, args, value):
        rendered = msg % (args[0] if isinstance(args[0], dict) and "%(" in msg else args)
        assert _record(msg, args) == rendered.replace(value, token_or_label(value))

    @pytest.mark.parametrize(
        ("text", "value"),
        [
            ("password=['a', 'b'] rejected", "['a', 'b']"),
            ("secret = {'k': [1, 2]} x", "{'k': [1, 2]}"),
            ("token: (1, 'x')", "(1, 'x')"),
            ("password=[unclosed, 'rest of the line", "[unclosed, 'rest of the line"),
        ],
    )
    def test_in_text(self, text, value):
        masked = mask_by_patterns(text, _TEXT_RULES)
        assert masked == text.replace(value, token_or_label(value))
        assert mask_by_patterns(masked, _TEXT_RULES) == masked

    def test_a_repr_keeps_its_value_a_string(self):
        text = "{'user': 'bob', 'password': ['s3cret']}"
        masked = token_or_label("['s3cret']")
        assert mask_by_patterns(text, _TEXT_RULES) == "{'user': 'bob', 'password': '" + masked + "'}"

    @pytest.mark.parametrize(
        "text",
        [
            # What masking wrote: a label, a container of tokens and labels.
            "password=[SECRET-MASKED] rejected",
            f"password=['{hmac_tokenize('a', bytes(32), 'secret', 'test')}', '[SECRET-MASKED]', None]",
            # Nothing in it.
            "password=[] and token={}",
            # JSON: the key walk masked it by its keys before it was written,
            # the saved card under `token` its own number, brand and expiry.
            '{"token": {"brand": "VISA", "number": "411111******1111", "expiry_month": "01"}}',
            '{"password": ["a"]}',
        ],
    )
    def test_what_is_masked_already_or_json_is_left_as_it_is(self, text):
        assert mask_by_patterns(text, _TEXT_RULES) == text

    def test_a_record_rendering_a_credential_field_is_masked_once(self):
        masked = MaskPIIFilter()._mask_value(_Login(user="bob", password=["s3cret"]))
        assert masked == f"_Login(user='bob', password=['{token_or_label('s3cret')}'])"
        assert "ptok:v1:ptok" not in masked


class TestTheCallsPacksDecide:
    """"`pci` in force" is the masking call's packs -- a filter built with its
    own `packs=`, as a PCI handler beside a default one is -- and the
    process's, together. Read from the process alone, a pci filter in a
    default-configured process hashed a credential holding a card number;
    read from the call alone, a default handler ahead of a pci one masked the
    record in place with a hash, and the pci handler logged it."""

    @pytest.mark.parametrize(("text", "masked"), CARD_IN_A_CREDENTIAL)
    def test_a_pci_filter_labels_it_in_a_default_process(self, text, masked):
        assert MaskPIIFilter(packs=ALL_PACKS)._mask_string(text) == masked

    def test_a_pci_filters_key_walk_labels_it_too(self):
        text = "password=p@ss4111111111111111"
        out = MaskPIIFilter(packs=ALL_PACKS)._mask_dict({"password": HOLDS_A_PAN, "note": text})
        assert out == {"password": LABEL, "note": "password=[SECRET-MASKED]"}

    def test_outside_the_call_the_process_packs_decide_again(self):
        MaskPIIFilter(packs=ALL_PACKS)._mask_string("password=p@ss4111111111111111")
        assert mask_secret(HOLDS_A_PAN) == token_or_label(HOLDS_A_PAN)

    def test_a_default_filter_in_a_pci_process_masks_a_card_number_in_any_field(self):
        # The key walk's pci branch and a bare int read the filter's packs
        # alone: a card number typed into the name box was hashed.
        configure_masking_packs(["pci"])
        masked = MaskPIIFilter(packs=("default",))._mask_dict(
            {"customer_name": PAN, "customer_email": HOLDS_A_PAN, "ref": int(PAN)}
        )
        assert masked == {"customer_name": "411111******1111", "customer_email": "[EMAIL-MASKED]", "ref": "411111******1111"}

    def test_a_default_filter_in_a_pci_process_labels_it_too(self):
        configure_masking_packs(["pci"])
        text = f"password={HOLDS_A_PAN}"
        assert MaskPIIFilter(packs=("default",))._mask_string(text) == f"password={LABEL}"

    @pytest.mark.parametrize("template", ["password=%s ref%s", "password=%s card %s"])
    def test_a_default_handler_ahead_of_a_pci_one_renders_no_card_number(self, template, logging_state):
        # The default handler renders `password=%s`, and the record keeps
        # what it rendered: its arguments masked with its own packs only, the
        # pci handler got `ref4111111111111111` whole, glued to a word.
        import io
        import logging

        configure_masking_packs(["pci", "financial_ids"])
        logger = logging.getLogger("handlers.render." + template.split()[1][:3])
        logger.propagate = False
        streams = []
        for packs in (("default",), ALL_PACKS):
            stream = io.StringIO()
            handler = logging.StreamHandler(stream)
            handler.addFilter(MaskPIIFilter(packs=packs))
            logger.addHandler(handler)
            streams.append(stream)
        logger.warning(template, "pw-1", PAN)
        assert [PAN in stream.getvalue() for stream in streams] == [False, False]

    @pytest.mark.parametrize("template", ["password=%s ref%s", "password=%s card %s"])
    def test_in_a_default_process_too(self, template, logging_state):
        # A pci filter built explicitly behind a default handler: the process
        # has no pci for the union to add.
        import io
        import logging

        logger = logging.getLogger("handlers.default.process." + template.split()[1][:3])
        logger.propagate = False
        streams = []
        for packs in (("default",), ALL_PACKS):
            stream = io.StringIO()
            handler = logging.StreamHandler(stream)
            handler.addFilter(MaskPIIFilter(packs=packs))
            logger.addHandler(handler)
            streams.append(stream)
        logger.warning(template, "pw-1", PAN)
        assert [PAN in stream.getvalue() for stream in streams] == [False, False]

    def test_a_default_handler_ahead_of_a_pci_one_leaves_it_the_label(self, logging_state):
        import io
        import logging

        configure_masking_packs(["pci", "financial_ids"])
        logger = logging.getLogger("handlers.in.order")
        logger.propagate = False
        streams = []
        for packs in (("default",), ALL_PACKS):
            stream = io.StringIO()
            handler = logging.StreamHandler(stream)
            handler.addFilter(MaskPIIFilter(packs=packs))
            logger.addHandler(handler)
            streams.append(stream)
        logger.warning("login password=%s", HOLDS_A_PAN)
        assert [stream.getvalue() for stream in streams] == [f"login password={LABEL}\n"] * 2


JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop"
# %-style templates a service logs, the credential after its word passed as an
# argument (the second is pg.cs.flow's own). Masking read the placeholder as
# the credential and rewrote the template, so getMessage() raised: the handler
# dropped the line and printed the arguments to stderr, in clear.
TEMPLATES = [
    ("login password=%s", ("hunter2-s3cret",), "hunter2-s3cret"),
    ("on_challenge_start: step_up_url=%s, has_token=%s", (f"https://centinel.example/stepup?JWT={JWT}", True), JWT),
    ("Authorization: %s", ("Basic dXNlcjpwYXNz",), "dXNlcjpwYXNz"),
    ("api_key=%r", ("k-123abc",), "k-123abc"),
    ("secret: %s", ("s3cr3t-9",), "s3cr3t-9"),
    ("gateway replied token=%s for %s", ("tok_live_abc123", "order-42"), "tok_live_abc123"),
    ("client_secret=%-10s|", ("abc123",), "abc123"),
    ("db postgresql://%s:%s@%s/app", ("u", "pw-9", "db"), "pw-9"),
    ("cvv=%s", ("123",), "123"),
    ("payment_id=%s", ("4111111111111111",), "4111111111111111"),
    # Its value in quotes, a mapping's, a number's.
    ('payload {"password": "%s"}', ("hunter2",), "hunter2"),
    ("password=%(pw)s", ({"pw": "hunter2"},), "hunter2"),
    ("api_key=%d", (12345,), "12345"),
]


class TestATemplateHoldingACredentialWord:
    """Through get_logging_config(), as a service runs it, with every pack."""

    @pytest.mark.parametrize(("template", "args", "secret"), TEMPLATES)
    def test_it_is_one_masked_line_and_nothing_reaches_stderr(self, template, args, secret, capsys, logging_state):
        import io
        import logging
        import logging.config

        from ecsctx.contrib.django import get_logging_config

        out = io.StringIO()
        cfg = get_logging_config(use_cid_filter=False, masking_packs=("pci", "financial_ids"))
        cfg["handlers"]["console"]["stream"] = out
        logging.config.dictConfig(cfg)
        logging.getLogger("app.pay").info(template, *args)
        lines = [json.loads(line) for line in out.getvalue().splitlines()]
        assert len(lines) == 1
        message = lines[0]["message"]
        assert secret not in message
        assert "MASKING-FAILED" not in message
        assert message.split("=")[0].split(":")[0] == template.split("=")[0].split(":")[0]
        assert capsys.readouterr().err == ""

    def test_a_template_masking_leaves_as_it_is_keeps_its_args(self):
        import logging

        record = logging.LogRecord("t", logging.INFO, __file__, 0, "user %s logged in", ("bob",), None)
        MaskPIIFilter().filter(record)
        assert (record.msg, record.args) == ("user %s logged in", ("bob",))

    def test_a_rendered_template_is_masked_whole(self):
        import logging

        record = logging.LogRecord("t", logging.INFO, __file__, 0, "login password=%s", ("hunter2-s3cret",), None)
        MaskPIIFilter().filter(record)
        assert (record.msg, record.args) == (f"login password={token_or_label('hunter2-s3cret')}", ())
        assert record.getMessage() == record.msg

    def test_arguments_that_do_not_fit_the_template_are_the_marker(self):
        import logging

        record = logging.LogRecord("t", logging.INFO, __file__, 0, "password=%s %s", ("only-one",), None)
        MaskPIIFilter().filter(record)
        assert (record.msg, record.args) == ("[MASKING-FAILED: TypeError]", ())

    def test_a_mapping_template_is_rendered_whole(self):
        import logging

        record = logging.LogRecord("t", logging.INFO, __file__, 0, "password=%(pw)s", ({"pw": "hunter2"},), None)
        MaskPIIFilter().filter(record)
        assert (record.msg, record.args) == (f"password={token_or_label('hunter2')}", ())

    def test_a_dicts_keys_still_mask_it_when_rendered(self):
        # Rendered from the masked arguments: from the raw ones, a card number
        # under a card key reached the text rules alone, and the default pack
        # has no card rule.
        import logging

        body = {"card_number": "4111111111111111"}
        record = logging.LogRecord("t", logging.INFO, __file__, 0, "password=%s body=%s", ("hunter2", body), None)
        MaskPIIFilter().filter(record)
        masked = f"password={token_or_label('hunter2')} body={{'card_number': '411111******1111'}}"
        assert (record.msg, record.args) == (masked, ())


class _Lazy:
    """Stands in for Django's gettext_lazy proxy: formats as text, is not a str."""

    def __init__(self, text):
        self.text = text

    def __str__(self):
        return self.text


# Records getMessage() could not render once masked: a template that is not a
# str, a number masking turned into text under a numeric conversion, arguments
# that do not fit. Each was dropped, its arguments printed to stderr.
UNRENDERED = [
    ("lazy", _Lazy("login password=%s"), ("hunter2-s3cret",), "hunter2-s3cret", ("default", "pci")),
    ("exception", ValueError("bad password=%s"), ("hunter2-exc",), "hunter2-exc", ("default", "pci")),
    ("epoch-second", "expires_at %d", (1727712345,), "1727712345", ("default", "pci")),
    ("13-digit-number", "order %d", (1727712345678,), "1727712345678", ("pci",)),
    ("str-format", "password={}", ("fmt-secret-1",), "fmt-secret-1", ("default", "pci")),
    ("count-mismatch", "password=%s %s", ("only-one",), "only-one", ("default", "pci")),
    # Rendered from the masked arguments: from the raw ones, a card number
    # glued to a word in the template is left whole by the card rule.
    ("glued-number", "password=%s ref%d", ("pw-1", 4111111111111111), "4111111111111111", ("pci",)),
]


class TestARecordThatWouldNotRender:
    """Through get_logging_config(), as a service runs it: one line, nothing on stderr."""

    @pytest.mark.parametrize(
        ("msg", "args", "secret", "packs"),
        [(*case[1:4], packs) for case in UNRENDERED for packs in case[4]],
        ids=[f"{case[0]}-{packs}" for case in UNRENDERED for packs in case[4]],
    )
    def test_it_is_one_line_without_the_secret(self, msg, args, secret, packs, capsys, logging_state):
        import io
        import logging
        import logging.config

        from ecsctx.contrib.django import get_logging_config

        out = io.StringIO()
        cfg = get_logging_config(use_cid_filter=False, masking_packs=() if packs == "default" else ("pci", "financial_ids"))
        cfg["handlers"]["console"]["stream"] = out
        logging.config.dictConfig(cfg)
        logging.getLogger("app.render").info(msg, *args)
        lines = [json.loads(line) for line in out.getvalue().splitlines()]
        assert len(lines) == 1
        assert secret not in lines[0]["message"]
        assert capsys.readouterr().err == ""

    def test_a_number_masking_turned_into_text_is_rendered_as_it(self):
        import logging

        masked = MaskPIIFilter()._mask_string("1727712345")
        assert "1727712345" not in masked
        record = logging.LogRecord("t", logging.INFO, __file__, 0, "expires_at %d ok", (1727712345,), None)
        MaskPIIFilter().filter(record)
        assert (record.msg, record.args) == (f"expires_at {masked} ok", ())

    def test_a_bytes_template_that_renders_keeps_its_args(self):
        # Read as the text masking decodes it: as str(bytes) it never matched
        # the decoded template, so every bytes record lost its arguments.
        import logging

        record = logging.LogRecord("t", logging.INFO, __file__, 0, b"user %s ok", ("bob",), None)
        MaskPIIFilter().filter(record)
        assert (record.msg, record.args, record.getMessage()) == ("user %s ok", ("bob",), "user bob ok")

    def test_a_bytes_template_holding_a_credential_word_is_rendered_whole(self):
        import logging

        record = logging.LogRecord("t", logging.INFO, __file__, 0, b"password=%s", ("hunter2-b",), None)
        MaskPIIFilter().filter(record)
        assert (record.msg, record.args) == (f"password={token_or_label('hunter2-b')}", ())

    def test_a_lazy_template_is_rendered_whole(self):
        import logging

        record = logging.LogRecord("t", logging.INFO, __file__, 0, _Lazy("login password=%s"), ("hunter2",), None)
        MaskPIIFilter().filter(record)
        assert (record.msg, record.args) == (f"login password={token_or_label('hunter2')}", ())


class TestACredentialThatIsATruncation:
    """A saved card's gateway token passed as an argument: the pci card rule
    truncated it before the credential rule read it, and ten of its digits
    showed where the key walk and the same text written out give the label."""

    @pytest.mark.parametrize("packs", ["default", "pci"])
    def test_rendered_from_its_argument_it_is_the_label(self, packs, capsys, logging_state):
        import io
        import logging
        import logging.config

        from ecsctx.contrib.django import get_logging_config

        out = io.StringIO()
        cfg = get_logging_config(use_cid_filter=False, masking_packs=() if packs == "default" else ("pci", "financial_ids"))
        cfg["handlers"]["console"]["stream"] = out
        logging.config.dictConfig(cfg)
        logging.getLogger("app.token").info("token=%s", "9923960000004314")
        assert [json.loads(line)["message"] for line in out.getvalue().splitlines()] == [f"token={LABEL}"]
        assert capsys.readouterr().err == ""

    @pytest.mark.parametrize("text", ["password=411111******1111", 'token: "411111******1111"'])
    def test_in_text_it_is_the_label(self, text):
        assert "******" not in mask_by_patterns(text, _TEXT_RULES)


class TestABareTokenKeyInABody:
    """redact_body masks a bare `token` key as the key walk does."""

    @pytest.mark.parametrize(
        ("body", "masked"),
        [
            ('{"token": "pay_abc123"}', '{"token": "%s"}'),
            ("token=pay_abc123&x=1", "token=%s&x=1"),
        ],
    )
    def test_its_value_is_its_token_or_the_label(self, body, masked):
        assert redact_body(body) == masked % token_or_label("pay_abc123")

    @pytest.mark.parametrize(
        ("body", "masked"),
        [
            ('{"token": "9923960000004314"}', '{"token": "[SECRET-MASKED]"}'),
            ("token=9923960000004314&x=1", "token=[SECRET-MASKED]&x=1"),
        ],
    )
    def test_a_card_shaped_one_is_the_label(self, body, masked):
        assert redact_body(body) == masked

    def test_as_the_key_walk_masks_it(self):
        assert _walk({"token": "pay_abc123"})["token"] == token_or_label("pay_abc123")
