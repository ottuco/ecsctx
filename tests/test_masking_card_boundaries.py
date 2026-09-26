"""Where a card number ends, and where the next one starts.

The card rule truncates a PAN found inside a string value. Its guards keep it
from chopping a longer number -- a 20-digit id, a number written in groups, an
IBAN -- and they did it by refusing any candidate that touched other digits: a
PAN followed by a space and more digits, two PANs side by side, a PAN after a
phone number's country code or an invoice number, a PAN glued to the word
before it. Under an unclassified key each of those shipped the full card number
in clear, and a short number after a PAN was merged into its truncation,
showing a last four that was not the card's.

An unbroken run of 12-19 digits is now a card number on its own, whatever
follows it across a separator. A card number may start after digits that
belong to something else: a word ("INV-2026"), a "+" (a phone number), a
truncation's stars. Digits that stand free before it, or an IBAN's country code
and check digits, still make one longer number, which is left whole.
"""

import pytest

from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.pii import configure_pii

PCI = frozenset({"default", "pci"})


@pytest.fixture
def mask():
    """A value under a key nothing classifies, so only the content rules see it."""
    engine = MaskPIIFilter(packs=PCI)
    return lambda value: engine._mask_value({"ref": value})["ref"]


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
        out = MaskPIIFilter(packs=PCI)._mask_value({"card_number": "5123450000000008 1234"})
        assert out == {"card_number": "512345******0008 1234"}

    def test_under_a_card_key_nothing_is_merged_either(self):
        """A card key read "5123450000000008 12" as one clean PAN."""
        out = MaskPIIFilter(packs=PCI)._mask_value({"card_number": "5123450000000008 12"})
        assert out == {"card_number": "512345******0008 12"}

    def test_under_a_name_key_it_is_a_card_number_amid_other_text(self, token_keyset_path):
        """Not one clean PAN, so not truncated as one: the label, as for a
        card number beside a name."""
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        out = MaskPIIFilter(packs=PCI)._mask_value({"customer_name": "5123450000000008 12"})
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
            # Written in groups, the first glued to the word before it.
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


# The common Unicode dashes: hyphen, non-breaking hyphen, figure dash, en dash,
# em dash, horizontal bar, minus sign.
_DASHES = ["\u2010", "\u2011", "\u2012", "\u2013", "\u2014", "\u2015", "\u2212"]
_EN_DASHED = "5123\u20134500\u20130000\u20130008"


class TestUnicodeDashesGroupACardNumber:
    """An editor turns "-" into an en dash; the card number is the same."""

    @pytest.mark.parametrize("dash", _DASHES)
    def test_under_an_unclassified_key(self, mask, dash):
        assert mask(dash.join(["5123", "4500", "0000", "0008"])) == "512345******0008"

    def test_under_a_card_key(self):
        out = MaskPIIFilter(packs=PCI)._mask_value({"card_number": _EN_DASHED})
        assert out == {"card_number": "512345******0008"}

    def test_under_a_name_key_it_is_truncated_not_tokenized(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        out = MaskPIIFilter(packs=PCI)._mask_value({"customer_name": _EN_DASHED})
        assert out == {"customer_name": "512345******0008"}

    def test_amid_a_name_it_is_the_label(self, token_keyset_path):
        """`holds_pan_run` joins the same dashes."""
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        out = MaskPIIFilter(packs=PCI)._mask_value({"customer_name": f"Jane {_EN_DASHED}"})
        assert out == {"customer_name": "[NAME-MASKED]"}


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
            # A number written in groups, longer than a PAN: no chunk of it is
            # a card number of its own.
            "1234 5678 9012 3456 7890",
            "1234-5678-9012-3456-7890",
            "1234-5678 9012 3456 7890 1234",
            "1234\u20135678\u20139012\u20133456\u20137890",
            # An IBAN written in groups: its country code and check digits start
            # the one number.
            "DE89 3704 0044 0532 0130 00",
            "BE68 5390 0754 7034",
            "SA03 8000 0000 6080 1016 7519",
            # A run glued to a word is part of an id, whatever follows it.
            "REF4111111111111111 1234",
            "123e4567-e89b-12d3-a456-426614174000",
            # A "+" glued to a word does not start a number.
            "call+963912345678",
        ],
    )
    def test_left_whole(self, mask, value):
        assert mask(value) == value

    def test_a_phone_number_is_still_a_phone_number(self, mask):
        """The phone rule runs before the card rule, as before."""
        assert mask("+965 5123 4567") == "[PHONE-MASKED]"

    def test_a_masked_value_is_a_fixed_point(self, mask):
        once = mask("INV-2026 4508 7500 0000 1019 ref 5123450000000008 12")
        assert once == "INV-2026 450875******1019 ref 512345******0008 12"
        assert mask(once) == once
