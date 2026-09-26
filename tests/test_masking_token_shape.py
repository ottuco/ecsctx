"""A value passes as already tokenized only in the exact shape ecsctx emits.

`safe_tokenize` returned any value starting "ptok:" unchanged, so
`customer_name: "ptok:Jane Payer"` shipped the name in clear, and a phone field
holding "ptok:+378282246310005" shipped a fifteen-digit card number. A card key
did the same for "ptok:<PAN>". A token is "ptok:v1:" and 43 base64url
characters -- an HMAC-SHA-256 digest, unpadded -- and anything else starting
"ptok:" is masked like any other value of its type.
"""

import re

import pytest

from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.tokens import safe_tokenize
from ecsctx.pii import configure_pii

PCI = frozenset({"default", "pci"})
_TOKEN = re.compile(r"ptok:v1:[A-Za-z0-9_-]{43}")


@pytest.fixture
def mask(token_keyset_path):
    configure_pii(token_keyset_path=token_keyset_path, env="test")
    return MaskPIIFilter(packs=PCI)._mask_value


class TestOnlyARealTokenPassesThrough:
    def test_a_real_token_passes_through_unchanged(self, mask):
        """The formatter's second pass over what the filter tokenized."""
        once = mask({"customer_name": "Jane Payer", "customer_phone": "+96550123456"})
        assert _TOKEN.fullmatch(once["customer_name"])
        assert _TOKEN.fullmatch(once["customer_phone"])
        assert mask(once) == once

    def test_a_name_behind_the_prefix_is_tokenized(self, mask):
        out = mask({"customer_name": "ptok:Jane Payer"})["customer_name"]
        assert _TOKEN.fullmatch(out)

    def test_a_card_number_behind_the_prefix_under_a_name_key(self, mask):
        """Masked since Task 1's `holds_pan_run` check (with `pci`), which
        looks inside a value shaped like a token. Pinned here beside the rest."""
        assert mask({"customer_name": "ptok:5123450000000008"}) == {"customer_name": "[NAME-MASKED]"}

    def test_a_card_number_behind_the_prefix_in_a_phone_field(self, mask):
        """A "+" run of at most 15 digits in a phone field is a phone number,
        the residual E.164 leaves: tokenized as the phone number it is written
        as, never shipped in clear."""
        out = mask({"customer_phone": "ptok:+378282246310005"})["customer_phone"]
        assert _TOKEN.fullmatch(out)
        assert out == mask({"customer_phone": "+378282246310005"})["customer_phone"]

    def test_a_card_number_behind_the_prefix_under_a_card_key(self, mask):
        assert mask({"card_number": "ptok:5123450000000008"}) == {"card_number": "ptok:512345******0008"}

    def test_without_a_keyset_it_is_the_label(self):
        out = MaskPIIFilter(packs=PCI)._mask_value(
            {"customer_name": "ptok:Jane Payer", "customer_phone": "ptok:+378282246310005"}
        )
        assert out == {"customer_name": "[NAME-MASKED]", "customer_phone": "[PHONE-MASKED]"}


class TestSafeTokenize:
    def test_a_real_token_is_returned_as_it_is(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        token = safe_tokenize("Jane Payer", "name")
        assert safe_tokenize(token, "name") == token

    @pytest.mark.parametrize(
        "value",
        [
            "ptok:Jane Payer",
            "ptok:5123450000000008",
            "ptok:v1:short",
            "ptok:v2:" + "A" * 43,
            "ptok:v1:" + "A" * 42,
            "ptok:v1:" + "A" * 44,
            "ptok:v1:" + "A" * 42 + "=",
            "ptok:v1:" + "A" * 43 + " Jane",
        ],
    )
    def test_anything_else_is_tokenized(self, token_keyset_path, value):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        out = safe_tokenize(value, "name")
        assert out != value
        assert _TOKEN.fullmatch(out)
