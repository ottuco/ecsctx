"""A credential masks alike on every path into a log, and a fixed marker never
stands where a token can.

| Value                               | With a keyset          | Without           |
|-------------------------------------|------------------------|-------------------|
| a secret                            | its token (`ptok:v1:`) | `[SECRET-MASKED]` |
| a secret shaped like a card number  | `[SECRET-MASKED]`      | `[SECRET-MASKED]` |
| a placeholder (`[REDACTED]`, `***`) | `[SECRET-MASKED]`      | `[SECRET-MASKED]` |
| empty                               | empty                  | empty             |

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

import json
from urllib.parse import quote

import pytest
from django.test import RequestFactory
from django.urls import path, re_path, resolve

import ecsctx
import ecsctx.masking
from ecsctx.contrib.django.routes import loggable_path
from ecsctx.contrib.net import loggable_body, redact_body, redact_url
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
        for value in (token_or_label(SECRET), LABEL, "411111******1111"):
            assert redact_body(body % value) == body % value


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
        # The rule's value takes no quote -- they stay in its prefix -- so it
        # never hashed them.
        text = f"login with password={value} failed"
        assert mask_by_patterns(text, _TEXT_RULES) == text.replace(value.strip("\"' "), LABEL)

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
    in an error message -- is masked with its quotes and hashed without them."""

    def test_a_secret_is_its_token_or_the_label(self):
        assert redact_body(f'password="{SECRET}"&x=1') == f"password={token_or_label(SECRET)}&x=1"

    @pytest.mark.parametrize("value", CARD_SHAPED)
    def test_a_secret_shaped_like_a_card_number_is_the_label(self, value):
        assert redact_body(f'password="{value}"&x=1') == f"password={LABEL}&x=1"

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
QUOTED_MARKERS = ['"[SECRET-MASKED]"', "'[SECRET-MASKED]'", '"411111******1111"', '" [CARD-MASKED] "']


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
    """`password=\\"…\\"` inside a JSON string. Unescaped, the value's quotes
    are dropped before the checks and the hash, as plain quotes are; a value
    masking already wrote is left as it is written."""

    @pytest.mark.parametrize("value", [*CARD_SHAPED, "***"])
    def test_a_card_number_or_placeholder_is_the_label(self, value):
        masked = redact_body(_escaped_form_body(value))
        assert json.loads(masked) == {"note": f"password={LABEL}&x=1"}
        assert redact_body(masked) == masked

    def test_a_secret_is_its_token_or_the_label(self):
        masked = redact_body(_escaped_form_body(SECRET))
        assert json.loads(masked) == {"note": f"password={token_or_label(SECRET)}&x=1"}
        assert redact_body(masked) == masked

    @pytest.mark.parametrize("value", [LABEL, "411111******1111"])
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
        assert json.loads(logged) == {"note": f"password={LABEL}&x=1"}
        assert loggable_body(_Reply(logged)) == logged

    def test_through_loggable_body_a_secret_keeps_the_key_walks_token(self):
        logged = loggable_body(_Reply(_escaped_form_body(SECRET)))
        assert json.loads(logged) == {"note": f'password="{token_or_label(SECRET)}"&x=1'}
        assert loggable_body(_Reply(logged)) == logged

    def test_through_loggable_body_a_masked_value_is_left_as_written(self):
        body = _escaped_form_body(LABEL)
        assert loggable_body(_Reply(body)) == body
