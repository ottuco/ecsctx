"""A canonical UUID is never a card number.

A UUID's hyphens join its digit groups the way a card number's separators
do, so 3.4% of random ones held a run of twelve or more digits: with the
`pci` pack a UUID under a PII, secret or payment-id key was its label rather
than its token (`holds_pan_run`), and the card rule truncated 0.2-0.5% of
them in free text (`request 268885*******2738ba1-…`).

A canonical UUID -- 8-4-4-4-12 hex digits with at least one hex letter,
standing on its own -- is now never read as one. An all-digit string in that
shape gets no exemption, and a card number beside a UUID is still truncated.

Every test runs with a keyset and without one.
"""

import random
import uuid

import pytest

from ecsctx.masking.config import configure_masking_packs
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS, holds_pan_run, mask_by_patterns, rules_for
from ecsctx.masking.tokens import make_label
from ecsctx.pii import configure_pii, is_configured, tokenize

# Both held a card number's worth of digits to 0.15.4: one after a free start
# (a space, `=`), one glued to a hex letter in card-style groups.
FREE = "26888535-1296-4273-8ba1-c634e90bf52f"
GLUED = "b57c1935-7613-4401-ba6e-29c8d31ec761"
UUIDS = [FREE, GLUED]
PAN = "4111111111111111"
ALL = rules_for(ALL_PACKS)


@pytest.fixture(autouse=True, params=["keyset", "no-keyset"])
def mode(request, token_keyset_path):
    if request.param == "keyset":
        configure_pii(token_keyset_path=token_keyset_path, env="test")
    return request.param


def token_or_label(value: str, field_type: str) -> str:
    return tokenize(value, field_type) if is_configured() else f"[{make_label(field_type)}]"


def _masked_twice(text: str) -> str:
    once = mask_by_patterns(text, ALL)
    assert mask_by_patterns(once, ALL) == once
    return once


class TestHoldsPanRun:
    @pytest.mark.parametrize("value", [*UUIDS, FREE.upper(), f" {GLUED} "])
    def test_a_uuid_holds_no_card_number(self, value):
        assert not holds_pan_run(value)

    @pytest.mark.parametrize("value", ["12345678-1234-1234-1234-123456789012", "00000000-0000-0000-0000-000000000000"])
    def test_an_all_digit_string_in_that_shape_gets_no_exemption(self, value):
        assert holds_pan_run(value)

    def test_a_uuid_among_other_text_is_judged_as_the_text(self):
        # Only a value that is a UUID is one: "req <uuid>" still holds the run.
        assert holds_pan_run(f"req {FREE}")


class TestUnderAKey:
    """With `pci`, a value a PII, secret or payment-id key would tokenize is
    its label when it holds a card-number run. A UUID holds none."""

    @pytest.fixture(autouse=True)
    def _pci(self):
        configure_masking_packs(["pci", "financial_ids"])

    @pytest.mark.parametrize(
        ("key", "field_type"), [("payment_id", "payment_id"), ("client_secret", "secret"), ("customer_ref", "generic")]
    )
    @pytest.mark.parametrize("value", UUIDS)
    def test_it_is_its_token(self, key, field_type, value):
        assert MaskPIIFilter()._mask_dict({key: value}) == {key: token_or_label(value, field_type)}


class TestInFreeText:
    @pytest.mark.parametrize(
        "text", ["request {} failed", "req-{} failed", "req_{}", "/v1/payments/{}/refund", "id={}", '{{"id": "{}"}}']
    )
    @pytest.mark.parametrize("value", UUIDS)
    def test_it_is_left_whole(self, text, value):
        assert _masked_twice(text.format(value)) == text.format(value)

    def test_an_all_digit_string_in_that_shape_is_read_as_any_digit_run(self):
        # The nil UUID has no hex letter: its zeros pass Luhn, as they did.
        text = "id 00000000-0000-0000-0000-000000000000 x"
        assert _masked_twice(text) == "id 000000**********************0000 x"

    def test_a_card_number_in_a_uuids_own_groups_is_the_accepted_residual(self):
        # 8-4-4 digits and then hex: a card number typed into a UUID's shape
        # stays whole in free text (ecsctx/CLAUDE.md, accepted residuals).
        text = "ref 41111111-1111-1111-abcd-ef0123456789 x"
        assert _masked_twice(text) == text


class TestACardNumberBesideAUuid:
    @pytest.mark.parametrize(
        ("text", "masked"),
        [
            (f"card {PAN} {FREE}", f"card 411111******1111 {FREE}"),
            (f"{FREE} {PAN}", f"{FREE} 411111******1111"),
            (f"{PAN}-{FREE}", f"411111******1111-{FREE}"),
            (f"{GLUED},{PAN}", f"{GLUED},411111******1111"),
            (f"{FREE} {PAN} {GLUED}", f"{FREE} 411111******1111 {GLUED}"),
        ],
    )
    def test_the_card_number_is_still_truncated(self, text, masked):
        assert _masked_twice(text) == masked


def test_ten_thousand_uuids_are_neither_labeled_nor_truncated():
    rng = random.Random(159942)
    uuids = [str(uuid.UUID(int=rng.getrandbits(128), version=4)) for _ in range(10_000)]
    assert [value for value in uuids if holds_pan_run(value)] == []
    for context in ("request {} failed", "req-{}", "/v1/payments/{}/refund", "id={}"):
        lines = [context.format(value) for value in uuids]
        masked = mask_by_patterns("\n".join(lines), ALL).split("\n")
        assert [line for line, out in zip(lines, masked, strict=True) if out != line] == []
    configure_masking_packs(["pci", "financial_ids"])
    masked = MaskPIIFilter()._mask_dict({"client_secret": uuids, "customer": uuids})
    assert masked == {
        "client_secret": [token_or_label(value, "secret") for value in uuids],
        "customer": [token_or_label(value, "generic") for value in uuids],
    }
