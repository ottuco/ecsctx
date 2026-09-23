"""A reference number under a key the service lists is left as it is.

MPGS's acquirer block carries the numbers a reconciliation or a chargeback is
fought with, and on ottu_pg (pci + financial_ids packs) every one was
destroyed: the 9-digit `acquirer.merchantId` read as a US SSN and tokenized,
the 12-digit RRN in `receipt` and the 13-digit `posData` read as short PANs and
cut to their last four. pg had listed `transactionid` as safe precisely to keep
one readable -- but a safe key only skipped the *key* rules; the content rules
still ran on its value.

A key the service lists now also frees its value from the digit rules, within
two floors, so a careless list entry can never ship a card:

- only a digits-only value of at most 14 digits -- a full-length PAN (15-19
  digits) is truncated wherever it is;
- only a key that does not classify as PII or a card or credential on its own
  (listing `mobile` does not unmask a phone number), and never under a card,
  credential, CVV or SAD container.

Unlisted keys are unchanged: a bare 9-digit value there is still an SSN.
"""

import pytest

from ecsctx.contrib.ottu.masking import SAFE_KEYS as OTTU_SAFE_KEYS
from ecsctx.masking.config import configure_masking_safe_keys
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS

PAY_RESPONSE = {
    "transaction": {
        "acquirer": {
            "batch": 20260923,
            "id": "KFH_S2I",
            "merchantId": "121234345",
            "transactionId": "123456789",
        },
        "receipt": "123456785957",
        "terminal": "KFHS2I01",
    },
    "authorizationResponse": {"posData": "1025100006600", "stan": "145957"},
}


@pytest.fixture
def mask():
    # ottu_pg's own list: the Ottu preset plus its transaction ids.
    configure_masking_safe_keys([*OTTU_SAFE_KEYS, "transactionid"])
    return MaskPIIFilter(packs=ALL_PACKS)._mask_value


def test_the_acquirer_references_read_through(mask):
    import copy

    assert mask(copy.deepcopy(PAY_RESPONSE)) == PAY_RESPONSE


def test_a_full_length_pan_under_a_listed_key_is_still_truncated(mask):
    assert mask({"receipt": "4111111111111111"}) == {"receipt": "411111******1111"}


def test_a_listed_key_inside_a_card_is_not_freed(mask):
    assert mask({"card": {"receipt": "123456785957"}}) != {"card": {"receipt": "123456785957"}}


def test_listing_a_phone_key_does_not_free_its_digits():
    # Listing `mobile` switches off its key rule (as it always did); it must
    # not also switch off the content rule that still catches the number.
    configure_masking_safe_keys(["mobile"])
    assert MaskPIIFilter(packs=ALL_PACKS)._mask_value({"mobile": "5551234567"}) != {"mobile": "5551234567"}


def test_an_unlisted_key_keeps_the_ssn_rule(mask):
    assert mask({"tax_ref": "123456789"}) != {"tax_ref": "123456789"}
