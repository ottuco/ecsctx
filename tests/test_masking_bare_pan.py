"""A truncated PAN renders bare: `450875******1019`, not `[CARD-MASKED:…]`.

The convention, from here on: **brackets mean nothing survived**. `[CVV-MASKED]`
and `[EXPIRY-MASKED]` stand where a value was destroyed, and `[EMAIL-MASKED]`
where no token could be made. Where something real is carried — a token, or a
PAN's BIN and last four — it is carried bare, with nothing wrapped around it.

Dropping the wrapper is not cosmetic. The marker's own text was doing three
jobs, and each one needs a replacement that does not depend on it:

1. `already_masked()` recognised a masked value by the literal `-MASKED:` /
   `-MASKED]`, keeping a re-passed value from being masked a second time;
2. `mask_card_value` recognised its own output via `_SINGLE_MARKER`;
3. `_text_has_card_context` — added in this same release to stop the
   standalone-CVV rule eating response codes — read the word "CARD" out of the
   marker. Once the card rule fires the digit run is gone, so the marker was the
   only card context left in the text. Miss this one and a CVV beside a masked
   PAN silently stops being masked, which is a PCI leak, not a regression in
   formatting.
"""

import pytest

from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS, mask_by_all_patterns, mask_card_value

PAN = "4508750000001019"
TRUNCATED = "450875******1019"


@pytest.fixture
def mask():
    f = MaskPIIFilter(packs=ALL_PACKS)
    return f._mask_value


class TestTheTruncationIsCarriedBare:
    def test_a_pan_under_a_card_key(self, mask):
        assert mask({"card_number": PAN}) == {"card_number": TRUNCATED}

    def test_a_pan_bare_in_a_field_value(self, mask):
        assert mask({"note": PAN}) == {"note": TRUNCATED}

    def test_a_pan_in_prose(self):
        assert mask_by_all_patterns(f"charged card {PAN} today") == (
            f"charged card {TRUNCATED} today"
        )

    def test_the_bin_and_last_four_are_all_that_survive(self, mask):
        out = mask({"card_number": PAN})["card_number"]
        assert out.startswith("450875")
        assert out.endswith("1019")
        assert PAN not in out
        assert "0000000" not in out


class TestBracketsStillMeanNothingSurvived:
    def test_a_cvv_keeps_its_label(self, mask):
        assert mask({"cvv": "123"}) == {"cvv": "[CVV-MASKED]"}

    def test_an_expiry_keeps_its_label(self, mask):
        assert mask({"expiry_month": "01"}) == {"expiry_month": "[EXPIRY-MASKED]"}

    def test_a_card_object_with_no_pan_keeps_its_label(self, mask):
        """Nothing to truncate, so nothing to carry."""
        assert mask({"card": {"holder": "Far", "scheme": "visa"}}) == {
            "card": "[CARD-MASKED]"
        }

    def test_a_card_key_holding_something_that_is_not_a_pan(self, mask):
        assert mask({"card_number": "not-a-number"}) == {"card_number": "[CARD-MASKED]"}


class TestReMaskingLeavesItAlone:
    """The same document is masked more than once — the structlog processor, the
    Sentry integration's own pass, and the handler filter."""

    def test_under_a_card_key_the_last_four_survive(self, mask):
        assert mask({"card_number": TRUNCATED}) == {"card_number": TRUNCATED}

    def test_under_any_other_key_it_is_not_tokenized(self, mask):
        """Otherwise it becomes a token of the partially-masked text, which
        correlates with nothing and loses the last four."""
        assert mask({"customer_ref": TRUNCATED}) == {"customer_ref": TRUNCATED}

    def test_in_prose_it_is_a_fixed_point(self):
        assert mask_by_all_patterns(TRUNCATED) == TRUNCATED
        assert mask_by_all_patterns(f"card {TRUNCATED} ok") == f"card {TRUNCATED} ok"

    def test_masking_twice_is_the_same_as_masking_once(self, mask):
        once = mask({"card_number": PAN, "note": f"paid with {PAN}"})
        assert mask(once) == once

    def test_a_full_pan_dressed_as_a_truncation_is_still_masked(self):
        """The shape is the marker now, so the shape has to be checked, not
        merely believed."""
        assert mask_card_value("450875******1019") == TRUNCATED
        assert mask_card_value(PAN) == TRUNCATED
        assert "4508750000001019" not in mask_card_value(f"[CARD-MASKED:{PAN}]")


class TestAValueAlreadyTruncatedUpstreamPassesThrough:
    """The surface this change widens, pinned deliberately rather than left to
    chance: with no wrapper, the shape is the marker, so a value an upstream
    system already truncated is read as masked and passed through.

    That is safe by construction, not by luck. The shape allows at most six
    leading digits and four trailing ones -- first 6 + last 4, which is exactly
    the most PCI DSS 3.5.1 permits anyone to keep -- with four or more stars
    between them. A string of this shape cannot carry a full PAN.

    And passing it through is better than the alternative: tokenizing it would
    produce a token of a partially-masked string, which correlates with nothing
    and loses the last four. That is the same reasoning as the re-masking case
    above; an upstream's truncation is no different from our own.
    """

    @pytest.mark.parametrize(
        "value", ["123456****7890", "999999****9999", "*********9301"]
    )
    def test_under_a_card_key(self, mask, value):
        assert mask({"card_number": value}) == {"card_number": value}

    @pytest.mark.parametrize("value", ["123456****7890", "999999****9999"])
    def test_under_a_tokenizable_key(self, mask, value):
        assert mask({"account_ref": value}) == {"account_ref": value}

    def test_a_full_pan_is_not_the_shape(self, mask):
        """Sixteen contiguous digits is a PAN whatever key it sits under."""
        assert mask({"account_ref": PAN}) == {"account_ref": TRUNCATED}
        assert mask({"card_number": PAN}) == {"card_number": TRUNCATED}

    @pytest.mark.parametrize(
        "value", ["4508750**0001019", "45087500**01019", "450875******101"]
    )
    def test_a_card_key_still_refuses_anything_off_the_shape(self, mask, value):
        """The pass-through is narrow. Too few stars, or too many digits kept,
        and a card key gives back the label -- it is not enough to merely
        contain stars. `4508750**0001019` keeps 14 of 16 digits, well past what
        PCI DSS 3.5.1 allows, so it must not be mistaken for a truncation."""
        assert mask({"card_number": value}) == {"card_number": "[CARD-MASKED]"}


class TestTheCvvBesideAMaskedPanStillMasks:
    """The leak this change opens if `_text_has_card_context` is not taught the
    bare shape. Rule 15 runs before rule 17, so by the time the CVV rule looks
    at the text the PAN is already truncated and `_CARD_SHAPE` no longer
    matches — the truncation itself is the only card context left.
    """

    def test_a_cvv_after_a_pan_in_one_string(self):
        # A word between them on purpose: "<pan> 123" is itself a valid
        # 19-digit space-separated PAN, and the card rule claims the whole run
        # -- correct, and not what this test is about.
        out = mask_by_all_patterns(f"{PAN} ref 123")
        assert TRUNCATED in out
        assert "[CVV-MASKED]" in out

    def test_a_cvv_after_an_already_truncated_pan(self):
        """The second pass over a document the first pass already masked."""
        out = mask_by_all_patterns(f"{TRUNCATED} ref 123")
        assert "[CVV-MASKED]" in out

    def test_a_status_code_with_no_card_anywhere_still_survives(self):
        """The other half of the same precondition, which must not regress."""
        assert mask_by_all_patterns("Response status: 400") == "Response status: 400"


class TestAnEmptyValueStaysEmpty:
    """`[ADDRESS-MASKED]` on an empty string reads as though something was
    hidden. Nothing was there — the same reason a null stays null."""

    def test_an_empty_string_under_a_pii_key(self, mask):
        assert mask({"customer_address_line1": ""}) == {"customer_address_line1": ""}

    def test_an_empty_string_under_a_card_key(self, mask):
        assert mask({"card_number": ""}) == {"card_number": ""}

    def test_a_null_still_stays_null(self, mask):
        assert mask({"email": None}) == {"email": None}
