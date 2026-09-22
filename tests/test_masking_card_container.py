"""A card object is walked field by field, not destroyed as one label.

Until 0.12.0 a dict under a card key rendered as a single `[CARD-MASKED]`, so a
gateway response carried nothing at all where the card had been:

    "sourceOfFunds": {"provided": {"card": "[CARD-MASKED]"}}

That breaks the rule the truncation exists to serve. PCI DSS 3.5.1 lets us keep
the first six and last four *because* they are what makes a payment findable;
Sensitive Authentication Data — CVV, PIN, track — is what must be destroyed.
Collapsing the container inverted it: the PAN, the one field with a defined
readable form, was the one thing thrown away, along with expiry, scheme and
holder, which PCI never asked us to hide.

Walking it is only safe together with the classification below. An unclassified
leaf inside a card container adopts the container's type and reaches
`mask_card_value`, which deliberately reads through anything holding fewer than
twelve digits — correct for a scalar under `card_number`, a pass-through surface
on every leaf of a walked object. `holder`, `track2` and `pinBlock` all
classified as nothing before this change, and the collapse was the only reason
they never reached a log.
"""

import pytest

from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS

PAN = "4508750000001019"
TRUNCATED = "450875******1019"


@pytest.fixture
def mask():
    return MaskPIIFilter(packs=ALL_PACKS)._mask_value


@pytest.fixture
def mask_without_pci():
    return MaskPIIFilter(packs=frozenset({"default"}))._mask_value


class TestACardObjectKeepsItsShape:
    def test_every_field_is_masked_on_its_own(self, mask):
        out = mask(
            {
                "card": {
                    "number": PAN,
                    "expiry": {"month": "01", "year": "28"},
                    "scheme": "VISA",
                    "securityCode": "123",
                }
            }
        )["card"]
        assert out["number"] == TRUNCATED
        assert out["expiry"] == {"month": "01", "year": "28"}
        assert out["scheme"] == "VISA"
        assert out["securityCode"] == "[CVV-MASKED]"

    def test_the_real_mpgs_shape(self, mask):
        out = mask(
            {"sourceOfFunds": {"provided": {"card": {"number": PAN, "brand": "VISA"}}, "type": "CARD"}}
        )
        assert out["sourceOfFunds"]["provided"]["card"] == {"number": TRUNCATED, "brand": "VISA"}
        assert out["sourceOfFunds"]["type"] == "CARD"

    def test_a_list_of_cards_is_walked_too(self, mask):
        assert mask({"card": [{"number": PAN}]}) == {"card": [{"number": TRUNCATED}]}

    def test_a_card_inside_a_pii_container(self, mask):
        out = mask({"customer": {"id": 3, "card": {"number": PAN, "scheme": "VISA"}}})
        assert out["customer"]["card"] == {"number": TRUNCATED, "scheme": "VISA"}

    def test_a_scalar_under_a_card_key_is_unchanged_by_this(self, mask):
        assert mask({"card_number": PAN}) == {"card_number": TRUNCATED}
        assert mask({"card_number": "not-a-number"}) == {"card_number": "not-a-number"}


class TestTheTruncationDoesNotDependOnThePciPack:
    """The sweep inherits ``card``, not ``generic``. Under a generic sweep with
    `pci` off the PAN renders `[GENERIC-MASKED]` — destroyed, which is the bug
    being fixed, not a stricter version of the fix."""

    def test_a_walked_pan_truncates_with_pci_off(self, mask_without_pci):
        assert mask_without_pci({"card": {"number": PAN}}) == {"card": {"number": TRUNCATED}}


class TestWhatTheWalkMustNotExpose:
    """Each of these classified as nothing before this change, so each would
    have read through in clear the moment the container stopped collapsing."""

    def test_the_cardholder_name_does_not_read_through(self, mask):
        out = mask({"card": {"number": PAN, "holder": "Jane Payer"}})["card"]
        assert "Jane Payer" not in str(out), out
        assert out["number"] == TRUNCATED

    @pytest.mark.parametrize("key", ["track1", "track2", "track2Data", "magstripe"])
    def test_track_data_is_destroyed(self, mask, key):
        """Track 2 is SAD: PCI DSS forbids storing it after authorization in any
        form. Truncating the PAN inside it is not enough — the service code and
        discretionary data live after the separator."""
        out = mask({"card": {key: "4508750000001019=28121011234500000000"}})["card"]
        assert "2812101123450" not in str(out), out
        assert "4508750000001019" not in str(out), out

    @pytest.mark.parametrize("key", ["pin", "pinBlock"])
    def test_the_pin_is_destroyed(self, mask, key):
        out = mask({"card": {key: "A1B2C3D4E5F60718"}})["card"]
        assert "A1B2C3D4E5F60718" not in str(out), out

    def test_a_card_object_with_nothing_sensitive_reads_through(self, mask):
        assert mask({"card": {"scheme": "visa", "last4": "1019"}}) == {
            "card": {"scheme": "visa", "last4": "1019"}
        }
