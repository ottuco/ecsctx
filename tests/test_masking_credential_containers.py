"""A container under a credential, CVV or SAD key is walked, not flattened.

Until 0.14.0 a non-exemptable key holding a container was `str()`'d and masked
as one unit. For a real credential object that is harmless; for the two shapes
Ottu actually logs it destroyed everything:

- ottu_pg's webhook sends the saved card as `token = CardSerializer(card).data`
  -- brand, masked number, expiry, name on card, the gateway token, flags. It
  went out on both services as ONE `ptok:v1:` hash: which card was saved, and
  whether it has expired, could not be read.
- MPGS answers its CVV check with `response.cardSecurityCode =
  {"acquirerCode": "M", "gatewayCode": "MATCH"}`, which went out as
  `[CVV-MASKED]`: the verdict, not a CVV.

Walking must not open what flattening kept closed, so:

- Under a credential, a key with no rule of its own still takes the
  credential's type; only safe keys (expiry, `customer_id`, `brand`, OAuth's
  `expires_in`) read through.
- A card-shaped object under a credential key -- a card number plus an expiry
  -- is walked as the card it is, so its masked number and brand read, while
  its own `token` is still a credential.
- A credential that looks like a PAN is masked whole, never truncated: the
  saved card's gateway token is sixteen digits, and truncation would show ten
  of them. A numeric `api_key` or `password` was partly shown the same way.
- Under a CVV or SAD key nothing is weaker than the container: only a key the
  service listed (validated by `never_safe`) reads through.
"""

import pytest

from ecsctx.contrib.ottu.masking import SAFE_KEYS as OTTU_SAFE_KEYS
from ecsctx.masking.config import configure_masking_safe_keys
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS

SAVED_CARD = {
    "customer_id": "e2e-014",
    "brand": "MASTERCARD",
    "name_on_card": "Jane Payer",
    "bin": "512345",
    "number": "512345******0008",
    "expiry_month": "01",
    "expiry_year": "39",
    "token": "9923960000004314",
    "pg_code": "mpgs-direct",
    "pg_name": "mpgs",
    "is_preferred": True,
    "is_expired": False,
    "will_expire_soon": False,
    "cvv_required": True,
    "agreements": ["AGR-100231"],
    "submit_url": "https://pg.ottu.dev/v1/sdk/token/",
}


@pytest.fixture
def mask():
    configure_masking_safe_keys(OTTU_SAFE_KEYS)
    return MaskPIIFilter(packs=ALL_PACKS)._mask_value


class TestTheSavedCardInTheWebhook:
    def test_it_is_walked_as_the_card_it_is(self, mask):
        token = mask({"token": dict(SAVED_CARD)})["token"]
        assert isinstance(token, dict)
        for key in (
            "customer_id",
            "brand",
            "bin",
            "number",
            "expiry_month",
            "expiry_year",
            "pg_code",
            "pg_name",
            "is_preferred",
            "is_expired",
            "will_expire_soon",
            "cvv_required",
            "agreements",
        ):
            assert token[key] == SAVED_CARD[key], key

    def test_without_the_preset_its_agreements_stay_masked(self):
        # Ottu's word, not the core's: to the core rules it is a leaf of the
        # card with no rule of its own, so it takes the card's type.
        token = MaskPIIFilter(packs=ALL_PACKS)._mask_value({"token": dict(SAVED_CARD)})["token"]
        assert token["agreements"] == ["[CARD-MASKED]"]

    def test_its_bookkeeping_timestamps_read_through(self, mask):
        # `Card.as_dict()` carries `created`/`modified`: fourteen digits each,
        # which the card rule refuses as "not a clean PAN" under a card key.
        card = dict(SAVED_CARD, created="2026-09-23 11:30:00", modified="2026-09-23 11:30:05")
        token = mask({"token": card})["token"]
        assert token["created"] == "2026-09-23 11:30:00"
        assert token["modified"] == "2026-09-23 11:30:05"

    def test_the_holder_and_the_gateway_token_are_not(self, mask):
        token = mask({"token": dict(SAVED_CARD)})["token"]
        assert "Jane" not in str(token)
        assert token["token"] == "[SECRET-MASKED]"
        assert "9923960000004314" not in str(token)
        assert "4314" not in str(token)

    def test_a_token_object_without_a_card_number_is_walked_as_a_credential(self, mask):
        # Connect's pinned callback fixture: no number, so not a card.
        token = mask({"token": {"name_on_card": "Jane Payer", "expiry_month": "01", "is_preferred": True}})["token"]
        assert token["expiry_month"] == "01"
        assert token["is_preferred"] is True
        assert token["name_on_card"] == "[NAME-MASKED]"


class TestACredentialObjectStaysClosed:
    def test_an_oauth_response_keeps_its_metadata(self, mask):
        token = mask(
            {"token": {"access_token": "eyJx.y.z", "refresh_token": "r-1234567890", "token_type": "Bearer", "expires_in": 3600, "scope": "read"}}
        )["token"]
        assert token["token_type"] == "Bearer"
        assert token["expires_in"] == 3600
        assert token["scope"] == "read"
        assert "r-1234567890" not in str(token)
        assert "eyJx" not in str(token)

    @pytest.mark.parametrize(
        "event",
        [
            {"password": {"current": "hunter2", "new": "hunter3"}},
            {"credentials": {"user": "u", "pass": "hunter2"}},
            {"secret": {"value": "hunter2"}},
            {"token": {"card": "tok_live_hunter2"}},
        ],
    )
    def test_an_unnamed_leaf_takes_the_credentials_type(self, mask, event):
        assert "hunter" not in str(mask(event))

    @pytest.mark.parametrize("key", ["token", "api_key", "password", "card_token"])
    def test_a_credential_shaped_like_a_pan_is_masked_whole(self, mask, key):
        assert mask({key: "9923960000004314"}) == {key: "[SECRET-MASKED]"}


class TestTheCvvVerdictObject:
    def test_mpgs_verdict_reads_through_with_the_ottu_preset(self, mask):
        event = {"response": {"cardSecurityCode": {"acquirerCode": "M", "gatewayCode": "MATCH"}}}
        masked = mask(event)
        assert masked["response"]["cardSecurityCode"] == {"acquirerCode": "M", "gatewayCode": "MATCH"}

    def test_without_the_preset_it_stays_masked(self):
        event = {"cardSecurityCode": {"acquirerCode": "M", "gatewayCode": "MATCH"}}
        masked = MaskPIIFilter(packs=ALL_PACKS)._mask_value(event)
        assert masked == {"cardSecurityCode": {"acquirerCode": "[CVV-MASKED]", "gatewayCode": "[CVV-MASKED]"}}

    def test_nothing_under_a_cvv_is_weaker_than_the_cvv(self, mask):
        # A core safe key (`id`) or a weaker type (`name`, `card`) must not
        # carry a CVV out of its container.
        masked = mask({"cvv": {"name": "123", "card": "123", "id": "123"}})
        assert masked == {"cvv": {"name": "[CVV-MASKED]", "card": "[CVV-MASKED]", "id": "[CVV-MASKED]"}}
