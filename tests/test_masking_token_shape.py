"""A value passes as already tokenized only in the exact shape ecsctx emits.

`safe_tokenize` returned any value starting "ptok:" unchanged, so
`customer_name: "ptok:Jane Payer"` shipped the name in clear, and a phone field
holding "ptok:+378282246310005" shipped a fifteen-digit card number. A card key
did the same for "ptok:<PAN>", `already_masked` for "ptok:JanePayer", and the
credential text rules for "password=ptok:hunter2". A token is "ptok:v1:" and 43
base64url characters -- an HMAC-SHA-256 digest, unpadded -- and anything else
starting "ptok:" is masked like any other value of its type.
"""

import re

import pytest

from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import mask_by_all_patterns
from ecsctx.masking.tokens import already_masked, safe_tokenize
from ecsctx.pii import configure_pii
from ecsctx.pii.crypto import hmac_tokenize

PCI = frozenset({"default", "pci"})
_TOKEN = re.compile(r"ptok:v1:[A-Za-z0-9_-]{43}")
# A real token, as tokenize() emits it.
_A_TOKEN = hmac_tokenize("hunter2", bytes(32), "secret", "test")


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


class TestAlreadyMaskedAcceptsOnlyARealToken:
    """`mask_by_field_type` asks `already_masked` first, and a value it vouches
    for passes through untouched: "ptok:JanePayer" shipped the name."""

    def test_a_real_token_and_a_label_holding_one(self):
        assert already_masked(_A_TOKEN)
        assert already_masked(f"[NAME-MASKED:{_A_TOKEN}]")

    @pytest.mark.parametrize(
        "value",
        ["ptok:JanePayer", "ptok:v1:abc", "ptok:5123450000000008", "[NAME-MASKED:ptok:JanePayer]"],
    )
    def test_anything_else(self, value):
        assert not already_masked(value)

    def test_a_name_behind_the_prefix_is_tokenized(self, mask):
        out = mask({"customer_name": "ptok:JanePayer"})["customer_name"]
        assert _TOKEN.fullmatch(out)

    def test_without_pci_nothing_behind_the_prefix_ships(self, token_keyset_path):
        """Without `pci` a card number under a name key is tokenized, as any
        name is; behind "ptok:" it shipped whole."""
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        out = MaskPIIFilter(packs=frozenset({"default"}))._mask_value(
            {"customer_name": "ptok:5123450000000008", "customer_email": "ptok:JanePayer"}
        )
        assert _TOKEN.fullmatch(out["customer_name"])
        assert _TOKEN.fullmatch(out["customer_email"])

    def test_without_a_keyset_it_is_the_label(self):
        out = MaskPIIFilter(packs=PCI)._mask_value({"customer_name": "ptok:JanePayer"})
        assert out == {"customer_name": "[NAME-MASKED]"}


class TestACredentialBehindThePrefixInText:
    """The credential text rules skipped a value starting "ptok:", and their
    value stopped at a colon, so `password=ptok:hunter2` shipped "hunter2"."""

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("password=ptok:hunter2", "password=[SECRET-MASKED]"),
            ("password: ptok:hunter2", "password: [SECRET-MASKED]"),
            ("password=ptok:v1:hunter2", "password=[SECRET-MASKED]"),
            ('"password": "ptok:hunter2"', '"password": "[SECRET-MASKED]"'),
            ("Bearer ptok:hunter2abc", "Bearer [SECRET-MASKED]"),
            # "ptok:" counts toward the eight characters a bare value needs.
            ("Bearer ptok:hunter2", "Bearer [SECRET-MASKED]"),
            # Not the exact shape: more after the token, or not as it is emitted.
            (f"password={_A_TOKEN}:hunter2", "password=[SECRET-MASKED]"),
            (f"password={_A_TOKEN.upper()}", "password=[SECRET-MASKED]"),
        ],
    )
    def test_it_is_masked(self, text, expected):
        assert mask_by_all_patterns(text) == expected

    @pytest.mark.parametrize(
        "text",
        [
            f"password={_A_TOKEN}",
            f"password: {_A_TOKEN}",
            f'"password": "{_A_TOKEN}"',
            f"Bearer {_A_TOKEN}",
            # Sentence punctuation after the token is not part of it.
            f"password={_A_TOKEN}.",
            f"password={_A_TOKEN}. Retry.",
            f"password={_A_TOKEN}, then",
            f"password={_A_TOKEN};",
            f"(password={_A_TOKEN})",
            f"Bearer {_A_TOKEN}.",
        ],
    )
    def test_a_real_token_stays_whole(self, text):
        assert mask_by_all_patterns(text) == text

    def test_with_a_keyset_it_is_a_token_and_a_second_pass_keeps_it(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        once = mask_by_all_patterns("password=ptok:hunter2")
        assert once.startswith("password=") and _TOKEN.fullmatch(once.removeprefix("password="))
        assert mask_by_all_patterns(once) == once
