"""A CVV in text is masked in every service, as its key is.

The keyed CVV text rules (`cvv=123`, `"securityCode": "123"`, `CVV 123`) were
the opt-in `pci` pack's, so a service on the default pack -- Connect, which
receives the CVV a saved-card payment sends -- logged them in clear, though
the same CVV under a key was `[CVV-MASKED]` everywhere. They knew three
spellings (`cvv`, `cvc`, `security code`) where the key rule knows the rest
(`CVV2`, `csc`, `cardCode`, `vpc_CardSecurityCode`, ...), and stopped at four
digits: `cvv=482912` left `12`. `redact_url` and `redact_body` masked
credential params only, so `vpc_CardSecurityCode=123` and a card number in a
query or form body went out whole.

The keyed rules now run in every pack; the bare 3-4 digit rule, which needs
card context to fire, stays `pci`. A CVV is never tokenized: it is always
`[CVV-MASKED]`, with a keyset or without one.
"""

import pytest

from ecsctx.contrib.net import loggable_request_body, redact_body, redact_url
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS, mask_by_patterns, rules_for
from ecsctx.pii import configure_pii

LABEL = "[CVV-MASKED]"
DEFAULT = rules_for(frozenset({"default"}))


@pytest.fixture(autouse=True, params=["keyset", "no-keyset"])
def mode(request, token_keyset_path):
    if request.param == "keyset":
        configure_pii(token_keyset_path=token_keyset_path, env="test")
    return request.param


# (text, as it must read)
KEYED = [
    ("cvv=4829", "cvv=[CVV-MASKED]"),
    ("cvc: 123", "cvc: [CVV-MASKED]"),
    ("CVV2=123", "CVV2=[CVV-MASKED]"),
    ("security_code=987", "security_code=[CVV-MASKED]"),
    ("vpc_CardSecurityCode=123&vpc_Amount=100", "vpc_CardSecurityCode=[CVV-MASKED]&vpc_Amount=100"),
    ("card_cvv=123", "card_cvv=[CVV-MASKED]"),
    ("cardCvv: 123", "cardCvv: [CVV-MASKED]"),
    ("x-cvv=123", "x-cvv=[CVV-MASKED]"),
    ("csc=123", "csc=[CVV-MASKED]"),
    ("cvn2=123", "cvn2=[CVV-MASKED]"),
    ("card_code=1234", "card_code=[CVV-MASKED]"),
    ("cardCode: 123", "cardCode: [CVV-MASKED]"),
    ("verification_value=123", "verification_value=[CVV-MASKED]"),
    ("cv_number=123", "cv_number=[CVV-MASKED]"),
    ('{"cvv2": "123"}', '{"cvv2": "[CVV-MASKED]"}'),
    ('{"securityCode": 123, "x": 1}', '{"securityCode": "[CVV-MASKED]", "x": 1}'),
    ('{\\"cvv\\": 123}', '{\\"cvv\\": \\"[CVV-MASKED]\\"}'),
    ("paid with CVV 123 ok", "paid with CVV [CVV-MASKED] ok"),
    ("Security Code 1234", "Security Code [CVV-MASKED]"),
    # A value runs to its delimiter: none of it is left after four digits.
    ("cvv=482912", "cvv=[CVV-MASKED]"),
    ("cvv=123abc&x=1", "cvv=[CVV-MASKED]&x=1"),
    ('{"cvv": "4829 12"}', '{"cvv": "[CVV-MASKED]"}'),
]
# Named about a CVV, not one: or not a CVV's value.
LEFT_ALONE = [
    "cvv_required=true",
    "shipping=1234",
    "cvvResult=M",
    "cardSecurityCodeError=1234",
    "security_code_length=3",
    "cvv: required",
    "cvv=12",
    "discard code=1234",
]


@pytest.mark.parametrize("rules", [DEFAULT, rules_for(ALL_PACKS)], ids=["default", "every-pack"])
class TestAKeyedCvvInText:
    @pytest.mark.parametrize(("text", "masked"), KEYED)
    def test_it_is_the_label_in_every_pack(self, rules, text, masked):
        once = mask_by_patterns(text, rules)
        assert once == masked
        assert mask_by_patterns(once, rules) == once

    @pytest.mark.parametrize("text", LEFT_ALONE)
    def test_what_is_not_a_cvv_is_left_as_it_is(self, rules, text):
        assert mask_by_patterns(text, rules) == text


def test_the_filter_masks_it_without_the_pci_pack():
    record_text = "retry payment cvv=482 for token tok_9f8e7d"
    masked = MaskPIIFilter()._mask_string(record_text)
    assert masked.startswith("retry payment cvv=[CVV-MASKED] ")


def test_a_bare_group_still_needs_the_pci_pack():
    # "call 123 now" beside a card: the loose rule stays opt-in.
    text = "card 4111111111111111 call 123 now"
    assert mask_by_patterns(text, DEFAULT) == text


class TestCardAndCvvParamsInAUrl:
    def test_each_is_masked_by_its_keys_type(self):
        url = redact_url(
            "https://gw.example/pay?vpc_CardSecurityCode=123&card_number=4111111111111111&pin=1234&order_id=42"
        )
        assert url == (
            "https://gw.example/pay?vpc_CardSecurityCode=[CVV-MASKED]"
            "&card_number=411111******1111&pin=[SAD-MASKED]&order_id=42"
        )
        assert redact_url(url) == url

    def test_the_fragment_is_read_as_the_query(self):
        assert redact_url("https://h/cb#cvv=123&x=1") == "https://h/cb#cvv=[CVV-MASKED]&x=1"

    @pytest.mark.parametrize(
        "url",
        [
            "https://h/pay?cvv_required=true&shipping=1234",
            "https://h/pay?card_number=n%2Fa&card=visa",
            "https://h/pay?cvv=&pin=",
        ],
    )
    def test_a_value_its_key_does_not_hide_is_left_as_written(self, url):
        assert redact_url(url) == url


class TestCardAndCvvFieldsInAFormBody:
    BODY = "cvv=456&card_number=4111111111111111&pin=1234&shipping=1234&cvv_required=true"
    MASKED = "cvv=[CVV-MASKED]&card_number=411111******1111&pin=[SAD-MASKED]&shipping=1234&cvv_required=true"

    def test_redact_body_masks_each_by_its_keys_type(self):
        assert redact_body(self.BODY) == self.MASKED
        assert redact_body(self.MASKED) == self.MASKED

    def test_a_form_body_logged_as_text_is_masked(self):
        assert loggable_request_body(self.BODY, None) == self.MASKED

    def test_in_a_json_string_the_strings_structure_stays(self):
        assert redact_body('{"note": "cvv=456"}') == '{"note": "cvv=[CVV-MASKED]"}'
