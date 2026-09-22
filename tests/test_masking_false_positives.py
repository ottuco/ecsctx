"""The standalone-CVV rule, narrowed so it stops eating diagnostics.

It was value-shaped, not key-shaped, and it fired on a whole field value: any
3-4 digit string became ``[CVV-MASKED]`` whatever key it sat under. Every PSP
response code (``"000"``, ``"101"``, ``"199"``), every ``Content-Length`` and
every HTTP status rendered into a message was destroyed -- the one field an
operator needs to read a decline.

``_mask_value`` already left ints and floats alone "so legitimate values
(status codes, counts) are not mangled by the CVV/card patterns". The same
values arriving as strings -- which is how every PSP sends JSON -- fell
through that gap. Two fences close it: the rule never sees a whole scalar
field value, and in prose it needs card context, because a CVV is worth
nothing without the PAN it belongs to.

What must NOT change: a real CVV or PAN under a sensitive key, a keyword-
anchored match in prose, and a PAN sitting bare in a message.
"""

import pytest

from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS


@pytest.fixture
def mask():
    f = MaskPIIFilter(packs=ALL_PACKS)

    def _mask(value):
        return f._mask_value(value)

    return _mask


class TestScalarFieldValuesKeepTheirDigits:
    """A whole field value is not prose: the keyless "bare digits" rules do
    not apply to it, exactly as they already do not apply to an int."""

    @pytest.mark.parametrize(
        "field",
        [
            {"response": {"code": "000"}},
            {"response": {"code": "101"}},
            {"gateway": {"response": {"code": "199"}}},
            {"headers": {"Content-Length": "279"}},
            {"attempt": "1"},
            {"mcc": "5411"},
            {"country_code": "965"},
        ],
    )
    def test_short_digit_values_survive(self, mask, field):
        assert mask(field) == field

    # Deferred, deliberately: a 12-19 digit string still masks as a card
    # whatever key it sits under, so an epoch-millisecond timestamp sent as a
    # string ("1727394279301") still comes out as the truncation *********9301.
    # Narrowing that means gating rule 15 on a card IIN, which changes a
    # fail-safe PCI contract ("any 12-19 digit run is a card") that 75 corpus
    # cases encode. Its own change, with its own review. Note a Luhn check is
    # NOT the answer: 4508750000001019 is a card in live test use and fails
    # Luhn, while the timestamp 1727394280470 passes it.

    def test_an_int_still_survives(self, mask):
        """The behaviour these strings are being brought into line with."""
        assert mask({"code": 400, "port": 443, "amount": 3}) == {
            "code": 400,
            "port": 443,
            "amount": 3,
        }


class TestRealCardDataStillMasks:
    def test_a_pan_under_a_card_key_is_masked_by_its_key(self, mask):
        assert mask({"number": "4508750000001019"}) == {
            "number": "450875******1019"
        }

    def test_a_cvv_under_a_cvv_key_is_masked_by_its_key(self, mask):
        assert mask({"cvv": "123"}) == {"cvv": "[CVV-MASKED]"}
        assert mask({"cvc": "1234"}) == {"cvc": "[CVV-MASKED]"}

    def test_a_pan_bare_in_a_field_value_is_still_masked(self, mask):
        """The card rule keeps working without a key to go on -- it is the only
        thing standing between an unrecognised field and a PAN in the clear."""
        assert mask({"note": "4508750000001019"}) == {
            "note": "450875******1019"
        }

    def test_a_pan_that_fails_luhn_is_still_masked(self, mask):
        """4508750000001019 is a card in live test use on jade and is NOT
        Luhn-valid. Pinned so nobody "improves" the card rule with a Luhn
        check, which would unmask it."""
        assert mask({"note": "4508750000001019"}) == {"note": "450875******1019"}


class TestProseStillMasks:
    def test_a_bare_cvv_in_a_message_is_masked(self, mask):
        assert mask("the cvv is 123") == "the cvv is [CVV-MASKED]"

    def test_a_pan_in_a_message_is_masked(self, mask):
        assert "450875******1019" in mask(
            "charged card 4508750000001019 today"
        )

    def test_a_keyword_anchored_cvv_in_text_is_masked(self, mask):
        assert mask('{"cvv": "123"}') == '{"cvv": "[CVV-MASKED]"}'

    def test_a_status_in_a_message_survives(self, mask):
        """The line that made this visible: every outbound log in ottu_pg read
        `Response status: [CVV-MASKED]`."""
        assert mask("Response status: 400") == "Response status: 400"
