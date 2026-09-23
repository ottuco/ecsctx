"""A national identity number is PII by its key, in every service.

Verified against 0.13.0 with every pack on: `national_id`, `qid` and
`passport_number` came out in clear, and a Kuwaiti `civil_id` was masked only
by accident -- its 12 digits look like a short PAN to the `pci` pack's card
rule, so a service without that pack shipped it whole. For a platform whose
customers are in Kuwait, Saudi Arabia, Bahrain and Qatar these are the most
common identity numbers in a KYC payload.

They are classified as `ssn` -- the existing type for a national identifier --
by the key, which needs no pack: a key naming a person's identity number is PII
whatever the service opted into.
"""

import pytest

from ecsctx.masking.patterns import classify_key
from ecsctx.processors import mask_sensitive_data


def classify(key):
    # The default pack only: a national id must not depend on opting in.
    return classify_key(key, frozenset({"default"}))


@pytest.mark.parametrize(
    "key",
    [
        "civil_id",
        "civilId",
        "customer_civil_id",
        "national_id",
        "nationalIdNumber",
        "qid",
        "iqama",
        "iqama_number",
        "cpr",
        "nid",
        "emirates_id",
        "passport_number",
        "passport",
        "ssn",
        "social_security_number",
        "tax_id",
        "tin",
        "aadhaar",
        "id_number",
    ],
)
def test_is_a_national_id(key):
    assert classify(key) == "ssn"


@pytest.mark.parametrize(
    "key",
    ["customer_id", "session_id", "order_id", "transaction_id", "nationality", "idempotency_key", "pid", "tint"],
)
def test_an_id_that_names_no_person_is_not(key):
    assert classify(key) != "ssn"


def test_a_kyc_payload_does_not_ship_them():
    # `kyc` is not a person container, so nothing here is masked by
    # inheritance: the ids are masked by their own names.
    event = {"kyc": {"civil_id": "287010100123", "document_type": "passport", "passport_number": "K1234567"}}
    masked = mask_sensitive_data(None, None, event)["kyc"]
    assert "287010100123" not in str(masked)
    assert "K1234567" not in str(masked)
    assert masked["document_type"] == "passport"
