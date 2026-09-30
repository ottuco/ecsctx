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
from ecsctx.masking.patterns import ALL_PACKS, mask_by_patterns, mask_card_value, rules_for
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
    # camelCase, glued to a word other than "card", as the key rule reads it.
    ("paymentCvv=123", "paymentCvv=[CVV-MASKED]"),
    ("savedCardCvv: 123", "savedCardCvv: [CVV-MASKED]"),
    ("paymentSecurityCode=123", "paymentSecurityCode=[CVV-MASKED]"),
    ("newCvv=123", "newCvv=[CVV-MASKED]"),
    ('{"newCvv2": "123"}', '{"newCvv2": "[CVV-MASKED]"}'),
    ("storedCardCode 1234", "storedCardCode [CVV-MASKED]"),
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
    "paymentCvvResult=1234",
    "newCvvRequired=123",
    "RECVV=123",
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

    def test_migs_card_number_is_truncated(self):
        url = "https://migs.example/vpcpay?vpc_CardNum=4111111111111111&vpc_CardSecurityCode=123&vpc_Amount=100"
        assert redact_url(url) == (
            "https://migs.example/vpcpay?vpc_CardNum=411111******1111&vpc_CardSecurityCode=[CVV-MASKED]&vpc_Amount=100"
        )

    def test_a_card_num_key_is_a_card_key_in_the_key_walk(self):
        assert MaskPIIFilter()._mask_dict({"card_num": "4111111111111111", "card_id": "42"}) == {
            "card_num": "411111******1111",
            "card_id": "42",
        }

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


# A credential keyword whose name the key rule reads as a CVV or other SAD.
CARD_SECRET_KEYWORDS = [
    ("cvv_token=123", "cvv_token=[CVV-MASKED]"),
    ('{"cvv_token": "123"}', '{"cvv_token": "[CVV-MASKED]"}'),
    ("card_cvv_secret: 4829", "card_cvv_secret: [CVV-MASKED]"),
    ("cvv_token 12345678", "cvv_token [CVV-MASKED]"),
    ("pin_password=1234", "pin_password=[SAD-MASKED]"),
    ("track2_token=4111111111111111=2512", "track2_token=[SAD-MASKED]"),
]


class TestACredentialKeywordThatNamesACvv:
    """`cvv_token=123` matched the credential rule, which tokenized it: a
    keyed hash of a CVV. Under its key, and in a URL, it was `[CVV-MASKED]`."""

    @pytest.mark.parametrize(("text", "masked"), CARD_SECRET_KEYWORDS)
    def test_it_is_the_label_its_key_gives(self, text, masked):
        rules = rules_for(ALL_PACKS)
        once = mask_by_patterns(text, rules)
        assert once == masked
        assert mask_by_patterns(once, rules) == once

    def test_the_key_walk_and_a_url_agree(self):
        assert MaskPIIFilter()._mask_dict({"cvv_token": "123"}) == {"cvv_token": LABEL}
        assert redact_url("https://h/p?cvv_token=123") == f"https://h/p?cvv_token={LABEL}"


# What mask_card_value truncates and shows: a card number with digits around it
# that make no other card number.
CARD_VALUES = [
    "26888535-1296-4273-8ba1-c634e90bf52fvpc",
    "ref 4111111111111111 99 88 77",
    # Stars that show no more than a truncation it writes: another masker's
    # last four.
    "************1111 4111111111111111",
]
CARD_LABEL = "[CARD-MASKED]"
# A truncation's first six or last four with the bare digits beside them,
# however joined, twelve or more: they can spell a whole card number. The
# last fours of truncations with nothing but separators and stars between
# them count together. 0.15.4 refused each of these.
REFUSED_BESIDE_A_TRUNCATIONS_DIGITS = [
    "4111111111  111111******1111",
    "4111111111, 111111******1111",
    "4111111111,111111******1111",
    "4111111111 | 111111******1111",
    "6011090364  901962******1111",
    "********3782  82246310005",
    "411111******3782 82246310005",
    "************5018  00000009",
    "********4111 ********1111 ********1111 ********1111",
    # The same, masked from the card numbers they come from.
    "4111111111  1111111111111111",
    "4111111111113782 82246310005",
    # Once shown, now refused: the last four and an eleven-digit number after
    # them make fifteen.
    "4111111111111111 12345678901",
    "512345000000000812-12345678901",
    "**** 4111111111111111 12345678901",
    # Digits shown in a row across truncations, however many: a last four,
    # a short group and the next first six (`5018 00 000009` is a Maestro);
    # last fours with a bare group; bare digits before a last four.
    "4000010000005018  00  0000090000000001",
    "400001******5018  00  000009******0001",
    "500001064111  500001021111  1111",
    "********4111  ********1111  1111",
    "02313379 ********1262",
    # A run of X's joins digits as stars do: another masker writes it.
    "411111******3782XX82246310005",
]
# What stays: a short group beside a truncation, under twelve digits with it.
KEPT_BESIDE_A_TRUNCATION = [
    "**** 1111 12 25",
    "411111******1111 12/25",
    "450875******1019 000",
]
# Digits and stars another masker left, showing digits a truncation of their
# length hides -- more than the first six and last four -- with no run the scan
# could truncate: refused, as 0.15.4 refused them.
REFUSED_WITH_STARS = [
    "4508750**0001019",
    "4508750****001019",
    "450875****0001019",
    "4508750000****1019",
    "1234567****1234567",
    "450875****1019****1234",
    "****1111 1234 5670",
    # Beside a card number the scan truncates.
    "4508750****001019 x 4111111111111111",
]


# Twelve digits or more left showing beside the truncations, joined in ways the
# checks do not read as one number: a card number in double-spaced or comma
# groups, another masker's `X`s. 354f70f and 0.15.4 refused these.
REFUSED_BESIDE_A_TRUNCATION = [
    "411111******1111 6011  0903  6490  1962",
    "411111******1111, 4111,1111,1111,1111",
    "4508750XXX001019 ************1111",
    # And on the first pass, where 0.15.4 already showed it.
    "4111111111111111 6011  0903  6490  1962",
]


class TestACardKeysValueIsMaskedOnce:
    """mask_card_value refused its own output: a value holding a truncation
    beside other digits, twelve in all, was `[CARD-MASKED]` on the next pass
    -- the formatter's, or redact_body's over a card param -- though the pass
    before had judged the same digits safe to show."""

    @pytest.mark.parametrize("value", CARD_VALUES)
    def test_mask_card_value_is_a_fixed_point(self, value):
        once = mask_card_value(value)
        assert "*" in once
        assert mask_card_value(once) == once

    @pytest.mark.parametrize("value", CARD_VALUES)
    def test_the_key_walk_twice_is_once(self, value):
        once = MaskPIIFilter()._mask_dict({"card_number": value})
        assert MaskPIIFilter()._mask_dict(once) == once

    def test_a_card_param_in_a_body_twice_is_once(self):
        once = redact_body(f"vpc_CardNum={CARD_VALUES[0]} x")
        assert redact_body(once) == once

    @pytest.mark.parametrize("value", REFUSED_WITH_STARS)
    def test_digits_and_stars_another_masker_left_are_refused(self, value):
        assert mask_card_value(value) == CARD_LABEL
        assert MaskPIIFilter()._mask_dict({"card_number": value}) == {"card_number": CARD_LABEL}

    @pytest.mark.parametrize("value", REFUSED_BESIDE_A_TRUNCATION)
    def test_a_card_numbers_digits_beside_a_truncation_are_refused(self, value):
        assert mask_card_value(value) == CARD_LABEL
        assert MaskPIIFilter()._mask_dict({"card_number": value}) == {"card_number": CARD_LABEL}

    @pytest.mark.parametrize("value", REFUSED_BESIDE_A_TRUNCATIONS_DIGITS)
    def test_a_truncations_digits_with_those_beside_it_are_refused(self, value):
        assert mask_card_value(value) == CARD_LABEL
        assert MaskPIIFilter()._mask_dict({"card_number": value}) == {"card_number": CARD_LABEL}

    @pytest.mark.parametrize("value", KEPT_BESIDE_A_TRUNCATION)
    def test_a_short_group_beside_a_truncation_is_kept(self, value):
        assert mask_card_value(value) == value
        assert MaskPIIFilter()._mask_dict({"card_number": value}) == {"card_number": value}


# Below twelve digits a value cannot be a card number as written, but its stars
# can stand for the rest of one: a group of digits and stars long enough to be
# a card number is shown only in a truncation's shape -- the first six digits
# at most, four stars or more, the last four at most. Groups of four to six,
# one card separator apart, as a card number is written (4-4-4-4, Amex 4-6-5,
# Diners 4-6-4), are read as one group.
STARRED_REFUSED = [
    # The last six of fifteen.
    "45087****001019",
    # Seven leading digits, read as one group: `4508750*****1019`, whatever
    # separates the groups.
    "4508 750* **** 1019",
    "4508-750*-****-1019",
    "4508\u2013750*\u2013****\u20131019",
    "4508\u200b750*\u200b****\u200b1019",
    # Amex 4-6-5 and Diners 4-6-4: seven leading digits and the last four.
    "3782 822*** *0005",
    "3056 930*** 5904",
    # The last eight of sixteen.
    "**** **** 1111 1111",
]
STARRED_KEPT = [
    "411111******1111",
    "**********1234",
    "[CARD-MASKED:411111******1111]",
    # An upstream system's truncation, as test_masking_bare_pan pins it, and
    # masks keeping the first four: fewer digits than a truncation keeps.
    "411111****1111",
    "4508****1019 12",
    "4111********1111",
    "4111****1111",
    # The card rule's own output, read again.
    "411111******1111 x5",
    "****623691**********1234",
    # Groups read as one: the first six and last four, or the last four.
    "4111 11** **** 1111",
    "**** **** **** 1111",
    "3782 82**** *0005",
    "3056 93**** 5904",
    # Short groups stop a run: `****1111` beside an expiry is too short to be
    # a card number, and a date beside a truncation is no part of it.
    "**** 1111 12 25",
    "**** **** **** 1111 12/25",
    "411111******1111 12/25",
    "****1234",
    "12**34",
]
PLAIN_SHORT = ["12345678901", "4111"]


class TestAStarredValueBelowTwelveDigits:
    """Below twelve digits mask_card_value read a value through unscanned, so
    another masker's `45087****001019` -- eleven digits of fifteen -- was shown
    as written."""

    @pytest.mark.parametrize("value", STARRED_REFUSED)
    def test_one_whose_stars_could_hide_a_card_number_is_refused(self, value):
        assert mask_card_value(value) == CARD_LABEL
        assert MaskPIIFilter()._mask_dict({"card_number": value}) == {"card_number": CARD_LABEL}

    @pytest.mark.parametrize("value", STARRED_KEPT + PLAIN_SHORT)
    def test_one_in_a_truncations_shape_or_too_short_is_kept(self, value):
        assert mask_card_value(value) == value
        assert MaskPIIFilter()._mask_dict({"card_number": value}) == {"card_number": value}
