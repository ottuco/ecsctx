"""A bare 3-4 digit run is a CVV only beside a card number or a CVV word (#160054).

The `pci` pack's bare-digit rule masked every 3-4 digit run in a line that
mentioned a card anywhere: `card list returned 200 in 350 ms` became
`card list returned [CVV-MASKED] in [CVV-MASKED] ms`, and `declined with code
051` lost its code. A CVV is worth nothing without the card it belongs to,
and it is written beside it: after the card number or its truncation,
perhaps with the expiry between (`4111111111111111|12/27|123`), or right
after a word naming it (`the cvv is 123`). The keyed rules (`cvv=123`,
`CVV 123`) still mask a CVV in every pack.
"""

import pytest

from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS

LABEL = "[CVV-MASKED]"

MUST_MASK = [
    ("4111111111111111 123", f"411111******1111 {LABEL}"),
    ("411111******1111 123", f"411111******1111 {LABEL}"),
    ("4111111111111111|12/27|123", f"411111******1111|12/27|{LABEL}"),
    ("pan 4111111111111111 12/27 123 ok", f"pan 411111******1111 12/27 {LABEL} ok"),
    ("4111111111111111,12,27,123", f"411111******1111,12,27,{LABEL}"),
    # Which of two such fields is the CVV cannot be told: neither ships.
    ("4111111111111111;1227;1234", f"411111******1111;{LABEL};{LABEL}"),
    ("4111111111111111 123 1227", f"411111******1111 {LABEL} {LABEL}"),
    ("pan 4111111111111111 1225", f"pan 411111******1111 {LABEL}"),
    ("card 4111111111111111 exp 12/27 123", f"card 411111******1111 exp 12/27 {LABEL}"),
    ("card 4111111111111111 expiry: 1227 123", f"card 411111******1111 expiry: 1227 {LABEL}"),
    ("4111111111111111 123 12/27", f"411111******1111 {LABEL} 12/27"),
    ("4111111111111111\n123", f"411111******1111\n{LABEL}"),
    ("paid with 4111111111111111 123.", f"paid with 411111******1111 {LABEL}."),
    ("411111******1111: 123", f"411111******1111: {LABEL}"),
    # Below 15 digits a PAN keeps its last four only.
    ("400000000002 1234", f"********0002 {LABEL}"),
    ("********1111 123", f"********1111 {LABEL}"),
    # A card number the card rule leaves -- glued to a word -- is still one.
    ("REF4111111111111111 123", f"REF4111111111111111 {LABEL}"),
    # After a word naming it, with a word or a sign between.
    ("the cvv is 123", f"the cvv is {LABEL}"),
    ("security code was 1234", f"security code was {LABEL}"),
    ("cvv - 123 entered", f"cvv - {LABEL} entered"),
    ("CVV2 # 123", f"CVV2 # {LABEL}"),
    ("cvv number 123", f"cvv number {LABEL}"),
    # The keyed rules, as before.
    ("card 411111******1111 cvv 123", f"card 411111******1111 cvv {LABEL}"),
    ("cvv=123 for 411111******1111", f"cvv={LABEL} for 411111******1111"),
]

MUST_NOT_MASK = [
    # The lines #160054 names.
    "card list returned 200 in 350 ms",
    "declined with code 051",
    "card 411111******1111 declined with code 051",
    # HTTP statuses, durations, decline codes.
    "card lookup: HTTP 200",
    "Response status: 400",
    "card 411111******1111 returned 404",
    "card verified in 350 ms",
    "card declined, code 05",
    "card declined, code 91",
    # Years and expiry.
    "card expires 2027",
    "card valid until 2027",
    "card expiry 12/27",
    "411111******1111 12/27",
    "411111******1111 exp 12/2027",
    "411111******1111 12/2027",
    "411111******1111 2026-09-30 10:30",
    # Amounts and counts.
    "card charged 100.000 KWD",
    "411111******1111 100.000 KWD",
    "411111******1111 1,250.500 KWD",
    "3 cards, 250 items, 1200 rows",
    # A word between the card and the digits: a reference, not a CVV.
    "charged card 411111******1111 ref 123",
    "411111******1111 order 1234",
    # Something about a CVV, not one.
    "cvv check returned 200",
    "cvv_required 1 of 200",
    # Digit groups of a longer number the card rule leaves whole: they were
    # [CVV-MASKED] while the text carried "card context" (a strict xfail).
    "1123 4567 8912 34567890",
    "0109 2815 9013 96245957",
]


@pytest.fixture
def mask():
    return MaskPIIFilter(packs=ALL_PACKS)._mask_value


@pytest.mark.parametrize(("text", "masked"), MUST_MASK)
def test_a_cvv_beside_a_card_or_a_cvv_word_is_masked(mask, text, masked):
    assert mask(text) == masked
    assert mask(masked) == masked


@pytest.mark.parametrize("text", MUST_NOT_MASK)
def test_other_three_and_four_digit_runs_are_left_as_they_are(mask, text):
    assert "[CVV-MASKED]" not in mask(text)


def test_the_card_line_keeps_its_numbers():
    # The card is still truncated; nothing else is touched.
    assert MaskPIIFilter(packs=ALL_PACKS)._mask_value("card 4111111111111111 listed: 200 in 350 ms") == (
        "card 411111******1111 listed: 200 in 350 ms"
    )


def test_the_rule_still_never_reads_a_whole_field_value():
    assert MaskPIIFilter(packs=ALL_PACKS)._mask_value({"code": "051", "status": "200"}) == {"code": "051", "status": "200"}


def test_the_default_pack_has_no_bare_digit_rule():
    assert MaskPIIFilter(packs=("default",))._mask_value("411111******1111 123") == "411111******1111 123"
