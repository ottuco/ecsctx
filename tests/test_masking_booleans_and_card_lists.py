"""A boolean is never masked; a card number in a list keeps its truncation.

A bool carries one bit. It cannot be PII, SAD or a credential, and masking it
only destroys the flag: inside a container of a masked type every leaf took the
container's type, so Ottu's `form_fields.name = {"display": True, "required":
True}` went out as two tokens, and a card object's `is_expired` became
`[CARD-MASKED]`. A tokenized bool also hides nothing -- there are only two
tokens to tell apart.

A card *list* is the one place a keyless value inherits `card`, e.g.
`card=(pan, month, year, cvv)` passed as a field. Each element became the
label, so the PAN lost the truncation PCI DSS lets us keep. Now an element
carrying a PAN is truncated; anything else stays the label, because a list has
no key to tell a CVV or a holder's name from a brand.
"""

import copy

import pytest

from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS
from ecsctx.processors import mask_sensitive_data


@pytest.mark.parametrize(
    ("event", "path"),
    [
        ({"payment_method_data": {"form_fields": {"name": {"display": True, "required": False}}}}, ("payment_method_data", "form_fields", "name", "display")),
        ({"payment_method_data": {"form_fields": {"name": {"display": True, "required": False}}}}, ("payment_method_data", "form_fields", "name", "required")),
        ({"customer": {"is_verified": True}}, ("customer", "is_verified")),
        ({"card": {"brand": "VISA", "is_expired": False}}, ("card", "is_expired")),
        ({"cvv": True}, ("cvv",)),
    ],
)
def test_a_boolean_reads_through(event, path):
    # mask_sensitive_data masks the event in place: read the original first.
    expected = event
    for key in path:
        expected = expected[key]
    masked = mask_sensitive_data(None, None, copy.deepcopy(event))
    for key in path:
        masked = masked[key]
    assert masked is expected


def test_a_boolean_in_a_list_under_a_masked_container_reads_through():
    masked = mask_sensitive_data(None, None, {"customer": {"flags": [True, False]}})
    assert masked["customer"]["flags"] == [True, False]


class TestACardList:
    def mask(self, value):
        return MaskPIIFilter(packs=ALL_PACKS)._mask_value({"card": value})["card"]

    def test_the_pan_keeps_its_truncation(self):
        assert self.mask(["4111111111111111", "visa"]) == ["411111******1111", "[CARD-MASKED]"]

    def test_what_a_list_cannot_name_stays_masked(self):
        # A CVV and a holder's name have no key here to identify them.
        masked = self.mask(["5123450000000008", "01", "2039", "123", "JANE DOE"])
        assert masked[0] == "512345******0008"
        assert masked[1:] == ["[CARD-MASKED]"] * 4

    def test_an_empty_element_stays_empty(self):
        assert self.mask(["", "4111111111111111"]) == ["", "411111******1111"]
