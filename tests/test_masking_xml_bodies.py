"""An XML body masks as a JSON or form body does (#160054).

KNET's KPay gateway takes XML: Connect's outbound caller logs every request
body through `redact_body` into `http.request.body.content`, and on 0.15.5
both `redact_body` and `mask_sensitive_data` left `<password>…</password>` in
clear -- neither the body rules nor the credential text rules read an element.

`redact_body` classifies an element's local name as it classifies a query,
form or JSON key: a credential name masks its text as `mask_secret` masks a
credential, and a card, CVV or other SAD name by that type. The text rules
gain both element forms, for a string that never went through
`redact_body`. Every test runs with a keyset and without one.
"""

import json
import logging
import time

import pytest

from ecsctx.contrib.net import configure_redaction, redact_body, redact_url
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS, mask_by_patterns, mask_secret, rules_for
from ecsctx.pii import configure_pii, is_configured, tokenize
from ecsctx.pii.crypto import hmac_tokenize
from ecsctx.processors import mask_sensitive_data

LABEL = "[SECRET-MASKED]"
PASSWORD = "S3cretPassw0rd"

# KPay's bodies, with fake values. 1 pays with an Apple Pay token in udf9, 8
# is the inquiry action, 2 the refund action.
APPLE_PAY_TOKEN = (
    '{"paymentData":{"data":"ZGF0YWJsb2JkYXRhYmxvYg==","signature":"c2ln","header":{"publicKeyHash":"cGtoYXNo",'
    '"ephemeralPublicKey":"ZXBr","transactionId":"abc123"},"version":"EC_v1"}}'
)
KPAY_PAY = (
    "<request><id>TRANPORTAL123</id><password>{password}</password><action>1</action><amt>10.000</amt>"
    "<trackid>TRK1</trackid><udf9>{udf9}</udf9></request>"
)
KPAY_INQUIRY = (
    "<id>TRANPORTAL123</id><password>{password}</password><action>8</action><amt>10.000</amt>"
    "<transid>202612345</transid><trackid>TRK1</trackid><udf5>TrackID</udf5>"
)
KPAY_REFUND = (
    "<id>TRANPORTAL123</id><password>{password}</password><action>2</action><amt>5.000</amt>"
    "<transid>202612345</transid><trackid>TRK1</trackid><udf5>TrackID</udf5>"
)
KPAY_BODIES = {
    "pay": KPAY_PAY.replace("{udf9}", APPLE_PAY_TOKEN),
    "inquiry": KPAY_INQUIRY,
    "refund": KPAY_REFUND,
}
READABLE = ["<id>TRANPORTAL123</id>", "<amt>10.000</amt>", "<trackid>TRK1</trackid>", "<transid>202612345</transid>"]


@pytest.fixture(autouse=True, params=["keyset", "no-keyset"])
def mode(request, token_keyset_path):
    if request.param == "keyset":
        configure_pii(token_keyset_path=token_keyset_path, env="test")
    return request.param


def secret(value: str) -> str:
    """A credential as it must read in the mode in force."""
    return tokenize(value, "secret") if is_configured() else LABEL


def _processor(content: str) -> str:
    event = mask_sensitive_data(None, "info", {"http": {"request": {"body": {"content": content}}}})
    return event["http"]["request"]["body"]["content"]


def _text(content: str) -> str:
    return mask_by_patterns(content, rules_for(ALL_PACKS))


def _default_text(content: str) -> str:
    return mask_by_patterns(content, rules_for(frozenset({"default"})))


def _message(text: str, packs: tuple[str, ...]) -> str:
    """``text`` as a record's message, masked by a filter with ``packs``."""
    record = logging.LogRecord("t", logging.INFO, __file__, 0, text, None, None)
    MaskPIIFilter(packs=packs).filter(record)
    return record.getMessage()


PACKS = [pytest.param(("default",), id="default"), pytest.param(("default", "pci"), id="pci")]


def _body(name: str, password: str) -> str:
    return KPAY_BODIES[name].replace("{password}", password)


def _outside_udf9(body: str) -> str:
    """The body without udf9's text: the wallet token is Ottu's value rule's
    (test_contrib_ottu_wallets.py)."""
    head, _, rest = body.partition("<udf9>")
    return head + rest.partition("</udf9>")[2]


class TestKPayBodies:
    @pytest.mark.parametrize("name", sorted(KPAY_BODIES))
    def test_redact_body_masks_the_password_and_keeps_the_rest(self, name):
        body = _body(name, PASSWORD)
        expected = _body(name, secret(PASSWORD))
        assert _outside_udf9(redact_body(body)) == _outside_udf9(expected)

    @pytest.mark.parametrize("name", sorted(KPAY_BODIES))
    def test_the_processor_masks_a_raw_xml_body(self, name):
        body = _body(name, PASSWORD)
        expected = _body(name, secret(PASSWORD))
        masked = _processor(body)
        assert PASSWORD not in masked
        assert _outside_udf9(masked) == _outside_udf9(expected)
        for element in READABLE:
            assert element in masked or element not in body

    @pytest.mark.parametrize("name", sorted(KPAY_BODIES))
    def test_each_path_gives_the_token_the_key_walk_gives(self, name):
        walked = mask_sensitive_data(None, "info", {"password": PASSWORD})["password"]
        body = _body(name, PASSWORD)
        for masked in (redact_body(body), _processor(body), _text(body), MaskPIIFilter()._mask_value(body)):
            assert f"<password>{walked}</password>" in masked

    @pytest.mark.parametrize("name", sorted(KPAY_BODIES))
    def test_masking_twice_masks_once(self, name):
        body = _body(name, PASSWORD)
        once = redact_body(body)
        assert redact_body(once) == once
        assert _default_text(once) == once
        assert _processor(once) == once
        texts = _text(body)
        assert _text(texts) == texts
        assert redact_body(texts) == texts
        assert _outside_udf9(_text(once)) == _outside_udf9(texts)
        assert "ptok:v1:ptok:v1:" not in once


class TestRedactBodyReadsAnElementsName:
    @pytest.mark.parametrize(
        "element",
        [
            "<password>{}</password>",
            "<PASSWORD>{}</PASSWORD>",
            "<Password>{}</Password>",
            '<password type="text">{}</password>',
            '<wsse:Password Type="PasswordText">{}</wsse:Password>',
            "<ns1:passwd>{}</ns1:passwd>",
            "<access_token>{}</access_token>",
            "<client_secret>{}</client_secret>",
            "<apiKey>{}</apiKey>",
            "<pwd>{}</pwd>",
        ],
    )
    def test_a_credential_names_text_is_masked_as_a_credential(self, element):
        assert redact_body(element.format(PASSWORD)) == element.format(secret(PASSWORD))

    @pytest.mark.parametrize("name", ["author", "design", "monkey", "userType", "keyword"])
    def test_a_name_holding_a_credential_hint_is_a_credential_as_a_query_param_is(self, name):
        # Matched by substring, as redact_url matches a param's name (`auth`,
        # `sign`, `key`, `user`): one reading across a URL and a body, and a
        # cost of failing closed that is accepted.
        assert redact_body(f"<{name}>Jane</{name}>") == f"<{name}>{secret('Jane')}</{name}>"
        assert redact_url(f"https://x.example/?{name}=Jane") == f"https://x.example/?{name}={secret('Jane')}"

    def test_a_key_the_service_listed_is_a_credential_too(self):
        configure_redaction(extra_secret_keys=["merchant_code"])
        assert redact_body(f"<merchant_code>{PASSWORD}</merchant_code>") == (
            f"<merchant_code>{secret(PASSWORD)}</merchant_code>"
        )

    @pytest.mark.parametrize(
        ("element", "masked"),
        [
            ("<cardNumber>4111111111111111</cardNumber>", "<cardNumber>411111******1111</cardNumber>"),
            ("<card_number>4508750000001019</card_number>", "<card_number>450875******1019</card_number>"),
            ("<cvv>123</cvv>", "<cvv>[CVV-MASKED]</cvv>"),
            ("<vpc_CardSecurityCode>1234</vpc_CardSecurityCode>", "<vpc_CardSecurityCode>[CVV-MASKED]</vpc_CardSecurityCode>"),
            ("<pin>1234</pin>", "<pin>[SAD-MASKED]</pin>"),
            ("<cvv_token>123</cvv_token>", "<cvv_token>[CVV-MASKED]</cvv_token>"),
        ],
    )
    def test_a_card_cvv_or_sad_names_text_is_masked_by_that_type(self, element, masked):
        assert redact_body(element) == masked

    @pytest.mark.parametrize(
        "element",
        [
            "<expiry>2712</expiry>",
            "<id>TRANPORTAL123</id>",
            "<action>8</action>",
            "<amt>10.000</amt>",
            "<trackid>TRK1</trackid>",
            "<transid>202612345</transid>",
            "<udf5>TrackID</udf5>",
            "<currencycode>414</currencycode>",
        ],
    )
    def test_an_element_no_key_rule_names_is_left_as_it_is(self, element):
        assert redact_body(element) == element

    @pytest.mark.parametrize(
        ("element", "masked"),
        [
            ('<password hint="a>b">{}</password>', '<password hint="a>b">{}</password>'),
            ("<password hint='a>b' lang=\"en\">{}</password>", "<password hint='a>b' lang=\"en\">{}</password>"),
            # A quote nothing closes before the next tag: the first `>` ends
            # the start tag, as before, and the rest is the credential's.
            ('<password hint="a>{}</password>', '<password hint="a>{}</password>'),
        ],
    )
    def test_a_close_angle_in_a_quoted_attribute_is_the_attributes(self, element, masked):
        body = element.format(PASSWORD)
        assert redact_body(body) == masked.format(secret(PASSWORD))
        assert _default_text(body) == masked.format(secret(PASSWORD))

    @pytest.mark.parametrize(
        ("element", "masked"),
        [
            ('<cvv note="a>b">123</cvv>', '<cvv note="a>b">[CVV-MASKED]</cvv>'),
            ('<cardNumber type="a>b">4111111111111111</cardNumber>', '<cardNumber type="a>b">411111******1111</cardNumber>'),
            (
                '<card><number type="a>b">4111111111111111</number></card>',
                '<card><number type="a>b">411111******1111</number></card>',
            ),
        ],
    )
    def test_a_card_elements_quoted_attribute_is_kept_whole_too(self, element, masked):
        assert redact_body(element) == masked
        assert _default_text(element) == masked

    def test_a_credential_holding_a_card_number_run_is_the_label(self):
        # As a JSON or form value is, in every pack.
        assert redact_body("<password>abc4111111111111111xyz</password>") == f"<password>{LABEL}</password>"

    def test_an_entity_in_a_credential_is_masked_as_it_decodes(self):
        assert redact_body("<password>a&amp;b&lt;c</password>") == f"<password>{mask_secret('a&b<c')}</password>"

    def test_a_cdata_credential_is_masked_as_its_content(self):
        assert redact_body(f"<password><![CDATA[{PASSWORD}]]></password>") == f"<password>{secret(PASSWORD)}</password>"

    def test_a_credential_with_children_is_masked_whole(self):
        masked = redact_body("<token><value>abc123</value><type>x</type></token><id>1</id>")
        assert masked == f"<token>{mask_secret('<value>abc123</value><type>x</type>')}</token><id>1</id>"

    @pytest.mark.parametrize(
        "body",
        [
            # No end tag, no element: a route is a start tag's shape.
            '{"route": "/v1/cards/<str:token>/"}',
            "<password>cut short",
        ],
    )
    def test_a_start_tag_no_end_tag_closes_is_left_as_it_is(self, body):
        assert redact_body(body) == body

    @pytest.mark.parametrize("body", ["<password/>", "<password />", "<password></password>", "<id>1</id><password/>"])
    def test_an_empty_credential_is_left_as_it_is(self, body):
        assert redact_body(body) == body

    def test_masked_twice_it_is_masked_once(self):
        for element in ("<password>{}</password>", "<cvv>{}</cvv>", "<cardNumber>{}</cardNumber>"):
            once = redact_body(element.format("4111111111111111"))
            assert redact_body(once) == once


class TestTextInAnElement:
    def test_json_in_an_element_goes_through_the_body_rules(self):
        body = '<udf9>{"password": "s3cr3t", "amount": "1.000"}</udf9><id>1</id>'
        assert redact_body(body) == f'<udf9>{{"password": "{secret("s3cr3t")}", "amount": "1.000"}}</udf9><id>1</id>'

    def test_encoded_json_in_an_element_goes_through_them_as_it_decodes(self):
        body = "<udf9>{&quot;password&quot;: &quot;s3cr3t&quot;}</udf9>"
        assert redact_body(body) == f'<udf9>{{"password": "{secret("s3cr3t")}"}}</udf9>'

    def test_a_form_body_in_an_element_keeps_its_closing_tag(self):
        body = "<udf1>password=s3cr3t&amp;cvv=123</udf1><id>1</id>"
        masked = redact_body(body)
        assert masked == f"<udf1>password={secret('s3cr3t')}&amp;cvv=[CVV-MASKED]</udf1><id>1</id>"
        assert redact_body(masked) == masked

    def test_a_form_value_in_an_element_keeps_its_closing_tag_in_the_text_rules_too(self):
        text = "<note>password=s3cr3t</note><id>1</id>"
        assert _text(text) == f"<note>password={secret('s3cr3t')}</note><id>1</id>"
        assert redact_body(text) == _text(text)


class TestTheCredentialTextRule:
    """For a string that never went through `redact_body`: every pack."""

    @pytest.mark.parametrize(
        "element",
        [
            "<password>{}</password>",
            '<wsse:Password Type="PasswordText">{}</wsse:Password>',
            "<access_token>{}</access_token>",
            "<client-secret>{}</client-secret>",
            "<api_key>{}</api_key>",
        ],
    )
    def test_an_element_is_masked_in_the_default_pack(self, element):
        assert _default_text(f"sent {element.format(PASSWORD)} ok") == f"sent {element.format(secret(PASSWORD))} ok"

    def test_the_value_runs_to_the_closing_tag(self):
        value = "correct horse & 'battery'"
        assert _text(f"<password>{value}</password>") == f"<password>{mask_secret(value)}</password>"

    def test_an_authorization_element_is_the_scheme_and_the_credential(self):
        walked = mask_sensitive_data(None, "info", {"Authorization": "Bearer abc123def456"})["Authorization"]
        assert _text("<Authorization>Bearer abc123def456</Authorization>") == f"<Authorization>{walked}</Authorization>"

    def test_a_token_after_the_scheme_is_not_hashed_again(self):
        # What masking the credential alone leaves, as rule 7 reads it.
        text = f"<Authorization>Bearer {hmac_tokenize('abc', bytes(32), 'secret', 'test')}</Authorization>"
        assert _text(text) == text

    @pytest.mark.parametrize(
        "text",
        [
            # A route in a message is a start tag's shape; no end tag closes it.
            "api request received: DELETE /v1/cards/<str:token>/",
            "api response sent: DELETE /v1/cards/<str:token>/ (204)",
            "enter <password> here",
            "<password/>",
            "<password></password>",
            "<passwordHint>blue</passwordHint>",
            "<tokenization>on</tokenization>",
        ],
    )
    def test_prose_and_other_names_are_left_as_they_are(self, text):
        assert _text(text) == text

    def test_a_value_masking_produced_passes_through(self):
        for value in (secret(PASSWORD), LABEL, "[CVV-MASKED]"):
            text = f"<password>{value}</password>"
            assert _text(text) == text

    def test_the_processor_masks_a_json_string_holding_xml(self):
        masked = _processor(json.dumps({"xml": f"<password>{PASSWORD}</password>"}))
        assert PASSWORD not in masked
        assert secret(PASSWORD) in masked


class TestAnElementsEndTagIsFoundOnce:
    """No end tag, no element -- and a text's end tags are found once: looked
    for again from each start tag, a text holding many that nothing closes
    took quadratic time, 160 KB of `<password>` twelve seconds in the text
    rule."""

    @pytest.mark.parametrize(
        "text",
        [
            "<password>" * 16000 + "</x>",
            "".join(f"<p{i}_password>" for i in range(8000)) + "</x>",
            "<cvv>" * 16000 + "</x>",
            # redact_body's credential names, `key` among them, and a body is
            # redacted before it is capped (loggable_body): every byte a
            # gateway sends reaches it.
            "<key>" * 16000 + "</x>",
            "<token>" * 16000 + "</x>",
            "".join(f"<k{i}_key><t{i}_token>" for i in range(2000)) + "</x>",
        ],
        ids=["one_name", "distinct_names", "cvv", "key", "token", "distinct_keys_and_tokens"],
    )
    def test_many_start_tags_nothing_closes_take_linear_time(self, text):
        for mask in (_default_text, _text, redact_body):
            started = time.perf_counter()
            assert mask(text) == text
            assert time.perf_counter() - started < 0.25, mask.__name__


# An element named as the key walk names a card, a CVV or other SAD, and its
# text as the key walk masks that key's value.
CARD_ELEMENTS = [
    ("<cvv>123</cvv>", "<cvv>[CVV-MASKED]</cvv>"),
    ("<pin>1234</pin>", "<pin>[SAD-MASKED]</pin>"),
    # A test card that fails Luhn, which the `pci` card rule leaves in text,
    # is a card number under its name all the same.
    ("<cardNumber>5123450000000007</cardNumber>", "<cardNumber>512345******0007</cardNumber>"),
    ("<cardNumber>5123450000000008</cardNumber>", "<cardNumber>512345******0008</cardNumber>"),
    ("<cardNumber>4111111111111112</cardNumber>", "<cardNumber>411111******1112</cardNumber>"),
    ("<pan>4111 1111 1111 1111</pan>", "<pan>411111******1111</pan>"),
    # What a card key refuses to show: a run longer than a card number.
    ("<cardNumber>4111111111111111111111</cardNumber>", "<cardNumber>[CARD-MASKED]</cardNumber>"),
    (
        '<ns2:CardSecurityCode type="x">1234</ns2:CardSecurityCode>',
        '<ns2:CardSecurityCode type="x">[CVV-MASKED]</ns2:CardSecurityCode>',
    ),
    ("<securityCode>123</securityCode>", "<securityCode>[CVV-MASKED]</securityCode>"),
    ("<CVC2>123</CVC2>", "<CVC2>[CVV-MASKED]</CVC2>"),
    ("<track2>4111111111111111=27121010000012300</track2>", "<track2>[SAD-MASKED]</track2>"),
    (
        "<onlinePaymentCryptogram>AgAAAAAABk4DWZ4C28yUQAAAAAA=</onlinePaymentCryptogram>",
        "<onlinePaymentCryptogram>[SAD-MASKED]</onlinePaymentCryptogram>",
    ),
    ("<cavv>AAABBEg0VhI0VniQEjRWAAAAAAA=</cavv>", "<cavv>[SAD-MASKED]</cavv>"),
    ("<cvv><![CDATA[123]]></cvv>", "<cvv>[CVV-MASKED]</cvv>"),
    ("<cardNumber>&#52;111111111111111</cardNumber>", "<cardNumber>411111******1111</cardNumber>"),
]

READABLE_ELEMENTS = [
    "<amount>100.000</amount>",
    "<amt>10.000</amt>",
    "<expiry>2712</expiry>",
    "<cardType>001</cardType>",
    "<cvvResult>M</cvvResult>",
    "<trackid>TRK1</trackid>",
    "<currencycode>414</currencycode>",
]


class TestTheCardCvvAndSadTextRule:
    """For a string that never went through `redact_body` -- a message, an
    exception -- in every pack, as the key walk reads a key: an element named
    as a card, a CVV or other SAD masks its text by that type. A test card
    that fails Luhn under `<cardNumber>` is truncated, `pci` or not."""

    @pytest.mark.parametrize("packs", PACKS)
    @pytest.mark.parametrize(("element", "masked"), CARD_ELEMENTS)
    def test_an_element_in_a_message_is_masked_by_its_name(self, element, masked, packs):
        assert _message(f"sent {element} ok", packs) == f"sent {masked} ok"

    @pytest.mark.parametrize(("element", "masked"), CARD_ELEMENTS)
    def test_every_path_masks_it_alike(self, element, masked):
        assert _default_text(element) == masked
        assert _text(element) == masked
        assert _processor(element) == masked
        assert redact_body(element) == masked

    @pytest.mark.parametrize("packs", PACKS)
    @pytest.mark.parametrize("element", READABLE_ELEMENTS)
    def test_an_element_no_card_key_names_stays_readable(self, element, packs):
        text = f"sent {element} ok"
        assert _message(text, packs) == text
        assert redact_body(text) == text

    @pytest.mark.parametrize("packs", PACKS)
    def test_masking_twice_masks_once(self, packs):
        text = " ".join(element for element, _ in CARD_ELEMENTS)
        once = _message(text, packs)
        assert _message(once, packs) == once
        assert redact_body(once) == once

    @pytest.mark.parametrize(
        "element",
        [
            "<cvv>[CVV-MASKED]</cvv>",
            "<pin>[SAD-MASKED]</pin>",
            "<cardNumber>411111******1111</cardNumber>",
            "<cardNumber>********0002</cardNumber>",
            "<cardNumber>[CARD-MASKED]</cardNumber>",
            "<cvv></cvv>",
            "<cvv/>",
        ],
    )
    @pytest.mark.parametrize("packs", PACKS)
    def test_masking_output_passes_through(self, element, packs):
        assert _message(element, packs) == element
        assert redact_body(element) == element

    @pytest.mark.parametrize("text", ["enter the <cvv> here", "<cvv>123", "GET /v1/cards/<str:pan>/"])
    def test_a_start_tag_no_end_tag_closes_is_left_as_it_is(self, text):
        assert _default_text(text) == text


class TestACardElementHoldingElements:
    """A card object written as XML (CyberSource's `<card>`) is read field by
    field, as the key walk reads a card object's keys: a CVV or SAD field is
    its label, a credential a credential, and any other field's text a card
    value -- a card number under `<accountNumber>` truncated in every pack,
    an expiry or a type read through."""

    CARD = (
        "<card><accountNumber>4111111111111111</accountNumber><expirationMonth>12</expirationMonth>"
        "<expirationYear>2027</expirationYear><cvNumber>123</cvNumber><cardType>001</cardType></card>"
    )
    MASKED = (
        "<card><accountNumber>411111******1111</accountNumber><expirationMonth>12</expirationMonth>"
        "<expirationYear>2027</expirationYear><cvNumber>[CVV-MASKED]</cvNumber><cardType>001</cardType></card>"
    )

    @pytest.mark.parametrize("packs", PACKS)
    def test_each_field_is_masked_by_its_name(self, packs):
        assert _message(self.CARD, packs) == self.MASKED
        assert redact_body(self.CARD) == self.MASKED
        assert _default_text(self.CARD) == self.MASKED

    def test_a_cvv_beside_the_card_number_is_its_label(self):
        text = "<card><number>4111111111111111</number><cvv>123</cvv></card>"
        masked = "<card><number>411111******1111</number><cvv>[CVV-MASKED]</cvv></card>"
        assert redact_body(text) == masked
        assert _default_text(text) == masked

    def test_a_card_number_that_fails_luhn_is_truncated(self):
        card = "<card>\n  <number>4111111111111112</number>\n</card>"
        masked = "<card>\n  <number>411111******1112</number>\n</card>"
        assert _default_text(card) == masked
        assert redact_body(card) == masked

    def test_a_cvv_in_an_element_no_key_rule_names_is_masked(self):
        text = "<cardInfo><cvv>123</cvv><brand>VISA</brand></cardInfo>"
        masked = "<cardInfo><cvv>[CVV-MASKED]</cvv><brand>VISA</brand></cardInfo>"
        assert _default_text(text) == masked
        assert redact_body(text) == masked

    @pytest.mark.parametrize(
        ("text", "masked"),
        [
            ("<cvv><value>123</value></cvv>", "<cvv>[CVV-MASKED]</cvv>"),
            ("<pinBlock><format>0</format><data>041234FFFFFFFFFF</data></pinBlock>", "<pinBlock>[SAD-MASKED]</pinBlock>"),
        ],
    )
    def test_a_cvv_or_sad_element_holding_elements_is_its_label_whole(self, text, masked):
        assert _default_text(text) == masked
        assert redact_body(text) == masked

    def test_a_credential_in_a_card_object_is_still_a_credential(self):
        text = "<card><token>tok_live_abc123</token></card>"
        masked = f"<card><token>{secret('tok_live_abc123')}</token></card>"
        assert _default_text(text) == masked
        assert redact_body(text) == masked

    @pytest.mark.parametrize("name", ["password", "token"])
    def test_a_cvv_in_a_credential_is_its_label_before_the_credential_is_masked(self, name):
        # As the key walk gives a CVV under a credential key its label: masked
        # with the credential, it was part of the text the credential's token
        # was a keyed hash of. The credential's token is taken over the
        # masked text.
        text = f"<{name}><cvv>123</cvv></{name}>"
        masked = f"<{name}>{mask_secret('<cvv>[CVV-MASKED]</cvv>')}</{name}>"
        assert _default_text(text) == masked
        assert redact_body(text) == masked
