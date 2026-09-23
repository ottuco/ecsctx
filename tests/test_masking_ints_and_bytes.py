"""A PAN held as an int, and a body held as bytes, are masked like text.

Numbers are left alone at the content level so a status code or an amount is
not read as a CVV -- which also let a PAN through when it arrived as an int
under a key with no rule: `{"ref": 4111111111111111}` shipped whole (verified
against 0.13.0) while the same digits as text were truncated. An int now gets
the card rule's truncation when it IS a card number: 12-19 digits, an issuer
prefix of 2-6, and a Luhn pass -- which an epoch-millisecond timestamp (it
starts with 1) never has. Like the card content rule, it is the `pci` pack's.

A `bytes` value was never decoded, so a raw body -- `b'{"nameOnCard": ...}'`
-- got only the content rules on its repr, and the name shipped. It is now
decoded and masked as the text it is, key rules included.
"""

import pytest

from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS


def mask(value, packs=ALL_PACKS):
    return MaskPIIFilter(packs=packs)._mask_value(value)


class TestAnIntPan:
    def test_is_truncated(self):
        assert mask({"ref": 4111111111111111}) == {"ref": "411111******1111"}

    @pytest.mark.parametrize(
        "number",
        [
            1727394280470,  # epoch ms: starts with 1, even when it passes Luhn
            123456789012,
            4111111111111112,  # a PAN-length number that fails Luhn
            200,
            1260,
        ],
    )
    def test_a_number_that_is_not_a_card_stays_a_number(self, number):
        assert mask({"value": number}) == {"value": number}

    def test_without_the_pci_pack_it_is_left_as_the_card_rule_would_leave_it(self):
        assert mask({"ref": 4111111111111111}, packs=frozenset({"default"})) == {"ref": 4111111111111111}


class TestABytesBody:
    def test_is_masked_by_its_keys(self):
        masked = mask({"payload": b'{"nameOnCard": "Jane Payer", "number": "4111111111111111"}'})["payload"]
        assert isinstance(masked, str)
        assert "Jane" not in masked
        assert "4111111111111111" not in masked

    def test_plain_bytes_read_as_text(self):
        assert mask({"payload": b"status=ok"}) == {"payload": "status=ok"}
