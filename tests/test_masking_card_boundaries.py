"""Where a card number ends, and where the next one starts.

The card rule truncates a PAN found inside a string value. Its guards keep it
from chopping a longer number -- a 20-digit id, a number written in groups, an
IBAN -- and they did it by refusing any candidate that touched other digits: a
PAN followed by a space and more digits, two PANs side by side, a PAN after a
phone number's country code or an invoice number, a PAN glued to the word
before it. Under an unclassified key each of those shipped the full card number
in clear, and a short number after a PAN was merged into its truncation,
showing a last four that was not the card's.

The rule reads each run of digits joined by separators as a whole. Where the
digits around a separator admit more than one reading -- one card, or a card
and another number -- Luhn decides, and no output shows more than the first six
and last four of any Luhn-valid reading of 12-19 digits. An unbroken run of
12-19 digits is a card number wherever it stands. A card number written in
groups may start after digits that belong to something else: a word
("INV-2026"), a "+" (a phone number), a truncation's stars. Before a number
written in groups, digits that stand free, or an IBAN's country code and check
digits, still make one longer number, which is left whole unless a Luhn-valid
reading lies inside it.
"""

import time

import pytest

from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import pan_shaped
from ecsctx.pii import configure_pii

PCI = frozenset({"default", "pci"})


@pytest.fixture
def mask():
    """A value under a key nothing classifies, so only the content rules see it."""
    engine = MaskPIIFilter(packs=PCI)
    return lambda value: engine._mask_value({"ref": value})["ref"]


def _card(value: str) -> str:
    return MaskPIIFilter(packs=PCI)._mask_value({"card_number": value})["card_number"]


def _visible(value: str, out: str, card_start: int, card_end: int) -> list[int]:
    """Positions within the card number at value[card_start:card_end] whose
    digit survives in ``out``. Truncation keeps one output character per digit
    it hides (a star) or keeps, so digits and stars align one to one."""
    digits_in = [i for i, c in enumerate(value) if c.isdigit()]
    marks_out = [c for c in out if c.isdigit() or c == "*"]
    assert len(digits_in) == len(marks_out), (value, out)
    card = [k for k, i in enumerate(digits_in) if card_start <= i < card_end]
    return [pos for pos, k in enumerate(card) if marks_out[k].isdigit()]


class TestACardNumberFollowedByMoreDigits:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("5123450000000008 1234", "512345******0008 1234"),
            ("5123450000000008-1234", "512345******0008-1234"),
            ("4111111111111111 4111111111111111", "411111******1111 411111******1111"),
            # Connect's card summary, with the card number typed as the holder.
            (
                "Mastercard 5123450000000008 512345******0008 01/39",
                "Mastercard 512345******0008 512345******0008 01/39",
            ),
        ],
    )
    def test_the_card_number_is_truncated_and_what_follows_kept(self, mask, value, expected):
        assert mask(value) == expected

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            # Merged, this showed "0812": a last four built from the card's
            # digits and the number after it.
            ("5123450000000008 12", "512345******0008 12"),
            ("Mastercard 5123450000000008 01/39", "Mastercard 512345******0008 01/39"),
        ],
    )
    def test_a_short_number_after_it_is_not_merged_into_the_truncation(self, mask, value, expected):
        assert mask(value) == expected

    def test_card_numbers_side_by_side_are_all_truncated_in_one_pass(self):
        """Each is read on its own, not freed by the one before it being
        truncated: masking stops after four passes."""
        assert MaskPIIFilter(packs=PCI)._mask_string(" ".join(["4111111111111111"] * 5)) == (
            " ".join(["411111******1111"] * 5)
        )

    def test_under_a_card_key_the_rest_of_the_value_is_shown(self):
        """The card key scans with the same rule, so it no longer refuses the
        whole value for want of a card number it could find."""
        assert _card("5123450000000008 1234") == "512345******0008 1234"

    def test_under_a_card_key_nothing_is_merged_either(self):
        """A card key read "5123450000000008 12" as one clean PAN."""
        assert _card("5123450000000008 12") == "512345******0008 12"

    def test_under_a_name_key_it_is_a_card_number_amid_other_text(self, token_keyset_path):
        """Not one clean PAN, so not truncated as one: the label, as for a
        card number beside a name."""
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        out = MaskPIIFilter(packs=PCI)._mask_value({"customer_name": "5123450000000008 12"})
        assert out == {"customer_name": "[NAME-MASKED]"}


class TestACardKeyRefusesWhatStillHoldsACardNumber:
    """A card key shows what is not a card number. It showed a scan's result
    whenever the scan truncated anything, so a second card number in a shape
    the rule never reads went out with it; now a value that still holds a run
    of card-number length, beside the truncations, is refused whole."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            # Truncated by the card rule itself: nothing is left over.
            ("4111 1111 1111 1111 5123450000000008", "411111******1111 512345******0008"),
            ("5123 4500 0000 0008 12 25 5123450000000008", "512345******0008 12 25 512345******0008"),
            ("5123450000000008 4111 1111 1111 1111 1234", "512345******0008 411111******1111 1234"),
            # A card number the rule leaves: glued to a word, or to more digits.
            ("REF5123450000000008 5123450000000008", "[CARD-MASKED]"),
            ("4111 1111 1111 11111234 5123450000000008", "[CARD-MASKED]"),
        ],
    )
    def test_the_value(self, value, expected):
        assert _card(value) == expected

    def test_a_card_number_dressed_as_a_token(self):
        """The exact token shape, holding a card number: not passed as a token."""
        assert _card("ptok:v1:4111111111111111" + "A" * 27) == "ptok:v1:411111******1111" + "A" * 27


class TestLuhnDecidesBetweenReadings:
    """Digits around a separator are one card or a card and another number.
    The long group alone is the card only when it is Luhn-valid and the whole
    run is not; otherwise the whole run is truncated as one card, which never
    shows more than the first six and last four of either reading."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            # The short group is the head of the same card: split, it showed
            # more of the card than its first six.
            ("4 111111111111111", "411111******1111"),
            ("6011 000000000000001", "601100*********0001"),
            ("601 1000000000000001", "601100*********0001"),
            ("6 011000000000000001", "601100*********0001"),
            # The digits after the separator belong to the same card.
            ("6011000000000000 001", "601100*********0001"),
            ("411111111111 1111", "411111******1111"),
            ("411111111111111 1", "411111******1111"),
        ],
    )
    def test_a_luhn_valid_whole_is_one_card(self, mask, value, expected):
        assert mask(value) == expected
        assert _card(value) == expected

    @pytest.mark.parametrize(
        "value", ["4 111111111111111", "6011000000000000 001", "411111111111 1111", "4111 1111 1111 1111"]
    )
    def test_a_card_key_and_the_content_rule_agree_on_one_card(self, value):
        assert pan_shaped(value)

    def test_a_card_and_another_number_read_the_same_everywhere(self, mask, token_keyset_path):
        """Only the long group is Luhn-valid: a card and a number, under an
        unclassified key and a card key alike. Under a name key it is a card
        number amid other text, so the label."""
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        assert not pan_shaped("1 9682010000000005")
        assert mask("1 9682010000000005") == "1 968201******0005"
        assert _card("1 9682010000000005") == "1 968201******0005"
        out = MaskPIIFilter(packs=PCI)._mask_value({"customer_name": "1 9682010000000005"})
        assert out == {"customer_name": "[NAME-MASKED]"}

    def test_the_residual_a_card_that_fails_luhn(self, mask):
        """Accepted: a card that is not Luhn-valid itself (some 19-digit
        UnionPay cards), written as a Luhn-valid long group and a short tail,
        is read as a card and another number."""
        assert mask("4111111111111111 123") == "411111******1111 123"

    def test_leading_zeros_never_change_luhn(self, mask):
        """"00" before a card makes a Luhn-valid 18-digit reading whenever the
        card is valid, so the time of day's last field is read with it. It
        shows the card's first four and last four."""
        assert mask("10:00:00 4111111111111111") == "10:00:004111********1111"


class TestACardNumberAfterANumberThatStandsFree:
    """The card rule refused every match after "<digit><space>", to keep a
    longer number whole, so "point 1 <PAN>" shipped the card number; and a
    shorter card number was merged into the number before it. An unbroken run
    is a card number wherever it stands (CARD_NUMBER_CASES in
    test_masking_filter has the prose forms)."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("qty 2 4111111111111111", "qty 2 411111******1111"),
            ("qty 2 9123456789123456789", "qty 2 912345*********6789"),
            ("12345678 123456789012", "12345678 ********9012"),
            # "78 123456789012" is a Luhn-valid reading: truncated as one.
            ("x 123456 78 123456789012", "x 123456 **********9012"),
        ],
    )
    def test_the_card_number_is_truncated_and_the_number_before_it_kept(self, mask, value, expected):
        assert mask(value) == expected

    def test_a_card_number_written_in_groups_after_one_that_is_not(self, mask):
        """The digits before it are a card number of their own, so it is not a
        chunk of one longer number."""
        assert mask("4111111111111111 4111 1111 1111 1111") == "411111******1111 411111******1111"


class TestTheSecondPassLeavesATruncationAlone:
    """The second pass read "<free digits> <BIN>" -- the digits before a
    truncation and its first six -- as a new card. A reading never ends on
    digits running into a truncation's stars."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            # "26 4111111111111111" is itself a Luhn-valid reading.
            ("2026-09-26 4111111111111111", "2026-09-264111********1111"),
            ("order 123456 4111111111111111", "order 123456 411111******1111"),
            ("1234 5678 4111111111111111", "1234 5678 411111******1111"),
            ("ref 20260926 378282246310005", "ref 20260926 378282*****0005"),
        ],
    )
    def test_a_number_before_a_card_is_kept(self, mask, value, expected):
        assert mask(value) == expected
        assert mask(expected) == expected

    def test_a_star_after_a_card_number_is_not_a_truncation(self, mask):
        assert mask("4111111111111111*") == "411111******1111*"


class TestGroupedRunsOverNineteenDigits:
    """A run written in groups, longer than any card: every Luhn-valid reading
    of 12-19 digits that follows its groups is truncated, overlapping ones as
    one span."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("5123 4500 0000 0008 1234", "512345******0008 1234"),
            ("4111 1111 1111 1111 5123 4500 0000 0008", "411111******1111 512345******0008"),
            ("2026 4111 1111 1111 1111", "2026 411111******1111"),
            ("5123 4500 0000 0008 12 25", "512345******0008 12 25"),
        ],
    )
    def test_the_card_numbers_are_truncated(self, mask, value, expected):
        assert mask(value) == expected

    @pytest.mark.parametrize("lead", ["2026", "0002", "0006"])
    def test_whichever_readings_are_valid_the_card_shows_its_first_six_and_last_four_at_most(self, mask, lead):
        """2026: only the card reads valid. 0002 and 0006: a reading through
        the lead does too, so the two overlap and are truncated as one."""
        value = f"{lead} 4111 1111 1111 1111"
        out = mask(value)
        assert set(_visible(value, out, 5, len(value))) <= {0, 1, 2, 3, 4, 5, 12, 13, 14, 15}

    @pytest.mark.parametrize(
        "value",
        [
            # No reading of 12-19 digits along the groups is Luhn-valid.
            "3141 5926 5358 9793 2384",
            "3141-5926-5358-9793-2384",
            "3141-5926 5358 9793 2384 6264",
            "223307 924402 68599528",
        ],
    )
    def test_a_longer_number_with_no_valid_reading_is_left_whole(self, mask, value):
        assert mask(value) == value

    @pytest.mark.parametrize(
        "text",
        ["1 " * 20000, "1234 " * 8000, "1-2\u20133 " * 8000, "0\u2013" * 20000, "a1 " * 13000, "DE89 " * 8000],
        ids=["digit-space", "groups-of-four", "mixed-dashes", "en-dash-runs", "letter-glued", "iban-heads"],
    )
    def test_it_stays_linear(self, mask, text):
        started = time.perf_counter()
        mask(text)
        assert time.perf_counter() - started < 0.5


class TestInvisibleSeparators:
    """A copy or an editor leaves invisible characters between the groups."""

    @pytest.mark.parametrize("sep", ["\u00ad", "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"])
    def test_they_join_the_groups(self, mask, sep):
        value = sep.join(["4111", "1111", "1111", "1111"])
        assert mask(value) == "411111******1111"
        assert _card(value) == "411111******1111"

    def test_amid_a_name_it_is_the_label(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        out = MaskPIIFilter(packs=PCI)._mask_value({"customer_name": "Jane 4111\u200b1111\u200b1111\u200b1111"})
        assert out == {"customer_name": "[NAME-MASKED]"}


class TestACardNumberAfterDigitsThatBelongToSomethingElse:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            # A phone number's country code.
            ("+965 5123450000000008", "+965 512345******0008"),
            # A number that is part of a word.
            ("INV-2026 4508 7500 0000 1019 ref", "INV-2026 450875******1019 ref"),
            # A phone number, then the card number.
            ("x +966501234567 4508-7500-0000-1019", "x +966501234567 450875******1019"),
            # Written in card-style groups, the first glued to the word before it.
            ("Payer4508 7500 0000 1019", "Payer450875******1019"),
        ],
    )
    def test_the_card_number_is_truncated_and_the_rest_kept(self, mask, value, expected):
        assert mask(value) == expected

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("+9655123450000000008", "+965512*********0008"),
            ("tel: +9655123450000000008", "tel: +965512*********0008"),
        ],
    )
    def test_a_country_code_glued_to_the_card_number(self, mask, value, expected):
        """Nothing tells the country code from the card number, so the whole
        run is truncated. Its first six and last four show no more of the card
        number than the card's own first six and last four."""
        assert mask(value) == expected

    def test_a_truncation_after_a_country_code_is_not_read_as_a_phone_number(self, mask):
        """The phone rule took "+965 512345" -- the country code and the BIN --
        for a phone number, which is what the second pass over the card
        above would do."""
        assert mask("+965 512345******0008") == "+965 512345******0008"

    @pytest.mark.parametrize(
        ("value", "expected"),
        [("call +96550123456* now", "call [PHONE-MASKED]* now"), ("+96550123456*", "[PHONE-MASKED]*")],
    )
    def test_a_phone_number_before_a_lone_star_is_still_a_phone_number(self, mask, value, expected):
        assert mask(value) == expected


# The common Unicode dashes: hyphen, non-breaking hyphen, figure dash, en dash,
# em dash, horizontal bar, minus sign.
_DASHES = ["\u2010", "\u2011", "\u2012", "\u2013", "\u2014", "\u2015", "\u2212"]
_EN_DASHED = "5123\u20134500\u20130000\u20130008"


class TestUnicodeDashesGroupACardNumber:
    """An editor turns "-" into an en dash; the card number is the same. Only
    between card-style groups (fours, or Amex's 4-6-5): elsewhere a dash joins a
    range, which is two numbers."""

    @pytest.mark.parametrize("dash", _DASHES)
    def test_under_an_unclassified_key(self, mask, dash):
        assert mask(dash.join(["5123", "4500", "0000", "0008"])) == "512345******0008"

    def test_amex_grouping(self, mask):
        assert mask("3782\u2013822463\u201310005") == "378282*****0005"

    def test_under_a_card_key(self):
        assert _card(_EN_DASHED) == "512345******0008"

    def test_under_a_name_key_it_is_truncated_not_tokenized(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        out = MaskPIIFilter(packs=PCI)._mask_value({"customer_name": _EN_DASHED})
        assert out == {"customer_name": "512345******0008"}

    def test_amid_a_name_it_is_the_label(self, token_keyset_path):
        """`holds_pan_run` joins the same dashes."""
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        out = MaskPIIFilter(packs=PCI)._mask_value({"customer_name": f"Jane {_EN_DASHED}"})
        assert out == {"customer_name": "[NAME-MASKED]"}

    @pytest.mark.parametrize(
        "value",
        ["2026-09-01\u20132026-09-30", "20260901\u201320260930", "1000000\u20132000000", "ids 123456\u2013123999",
         "12\u2212345678901234"],
    )
    def test_a_range_is_two_numbers(self, mask, value):
        assert mask(value) == value


class TestWhatTheGuardsStillProtect:
    """The cases the guards exist for, beside the ones in test_masking_filter's
    NOT_MASKED and ACCEPTED_LEAK_CASES tables and the Track 2 case in
    test_masking_review."""

    @pytest.mark.parametrize(
        "value",
        [
            # An unbroken run longer than a PAN is an id, with digits around it
            # or not.
            "12345678901234567890 1234",
            "1234 12345678901234567890",
            # An IBAN written in groups: its country code and check digits, and
            # the four-character groups after them, are one number.
            "DE89 3704 0044 0532 0130 00",
            "BE68 5390 0754 7034",
            "SA03 8000 0000 6080 1016 7519",
            "GB33 BUKB 2020 1555 5555 55",
            "KW81 CBKU 0000 0000 0000 1234 5601 01",
            # A run glued to a word is part of an id, whatever follows it.
            "REF4111111111111111 1234",
            "123e4567-e89b-12d3-a456-426614174000",
            # A "+" glued to a word does not start a number.
            "call+963912345678",
        ],
    )
    def test_left_whole(self, mask, value):
        assert mask(value) == value

    @pytest.mark.parametrize(
        "value",
        ["worker12 1695012345", "pod17 1727340000", "req42 1695000000 123", "COVID19 2020 2021 2022",
         "ISO8601 2026 09 26", "HTTP2 200 123456789", "KWD100 000 000 000"],
    )
    def test_digits_after_a_word_are_a_card_only_in_card_style_groups(self, mask, value):
        """A word glued to digits starts a card number only in card-style
        groups ("Payer4508 7500 0000 1019"), and the digits glued to a word are
        its own, not the head of a number after them."""
        assert mask(value) == value

    def test_a_phone_number_is_still_a_phone_number(self, mask):
        """The phone rule runs before the card rule, as before."""
        assert mask("+965 5123 4567") == "[PHONE-MASKED]"

    def test_a_masked_value_is_a_fixed_point(self, mask):
        once = mask("INV-2026 4508 7500 0000 1019 ref 5123450000000008 12")
        assert once == "INV-2026 450875******1019 ref 512345******0008 12"
        assert mask(once) == once
