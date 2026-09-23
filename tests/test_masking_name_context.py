"""A bare `name` is a person unless its container names a thing.

`name` is the one key that is a person's name in `customer.name` and a thing's
name everywhere else Ottu logs it: `payment_method_data.name = "Visa/Mastercard"`,
MPGS's `interaction.merchant.name` (the merchant's display name), a gateway's,
a product's. All of them went out tokenized as people, and the tokens were
worse than useless -- the same thing got a different token as a `name` than
anywhere else.

A bare `name` is now read as the thing's name when its nearest container is
named by a *thing* word -- matched as a word, singular or plural, so `profile`
is not `file` and `upgrade` is not `pg`. A person word anywhere in that
container's name wins (`merchant_owner`, `bank_account`, `card`), and so does
the default: an unknown container keeps `name` a person.

`form`, `field`, `param` and `attribute` containers are both: they describe
fields (`form_fields.name = {"display": true}`) and they carry submitted ones
(`params.name = "Jane"`). There, only a `name` holding a container is a thing.

`billing` stays a PII container -- in WooCommerce and Braintree payloads it
holds the city and postcode. Ottu's billing is its fee breakdown, which reads
through because the Ottu preset lists the breakdown's own keys.
"""

import pytest

from ecsctx.contrib.ottu.masking import SAFE_KEYS as OTTU_SAFE_KEYS
from ecsctx.masking.config import configure_masking_safe_keys
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS, classify_key


@pytest.fixture
def mask():
    configure_masking_safe_keys(OTTU_SAFE_KEYS)
    return MaskPIIFilter(packs=ALL_PACKS)._mask_value


def _at(masked, path):
    for key in path:
        masked = masked[key]
    return masked


class TestAThingsName:
    @pytest.mark.parametrize(
        ("event", "path"),
        [
            ({"payment_method_data": {"name": "Visa/Mastercard"}}, ("payment_method_data", "name")),
            ({"interaction": {"merchant": {"name": "Ottu Store"}}}, ("interaction", "merchant", "name")),
            ({"gateway": {"name": "mpgs"}}, ("gateway", "name")),
            ({"issuer": {"name": "KFH"}}, ("issuer", "name")),
            ({"products": [{"name": "Gold plan"}]}, ("products", 0, "name")),
            ({"items": [{"name": "Coffee"}]}, ("items", 0, "name")),
            ({"categories": {"name": "Food"}}, ("categories", "name")),
        ],
    )
    def test_reads_through(self, mask, event, path):
        assert _at(mask(event), path) == _at(event, path)

    def test_a_field_definition_is_walked_without_a_type(self, mask):
        # Ottu's form field config: the `name` field's display settings.
        event = {"form_fields": {"name": {"display": "optional", "order": 2}}}
        assert mask(event) == event


class TestAPersonsName:
    @pytest.mark.parametrize(
        "event",
        [
            {"name": "Jane Payer"},
            {"customer": {"name": "Jane Payer"}},
            {"payer": {"name": "Jane Payer"}},
            {"card": {"name": "Jane Payer"}},
            {"profile": {"name": "Jane Payer"}},
            {"merchant_owner": {"name": "Jane Payer"}},
            {"bank_account": {"name": "Jane Payer"}},
            {"upgrade": {"name": "Jane Payer"}},
            {"params": {"name": "Jane Payer"}},
            {"fields": {"name": "Jane Payer"}},
            {"form": {"name": "Jane Payer"}},
            {"beneficiaries": [{"name": "Jane Payer"}]},
        ],
    )
    def test_stays_masked(self, mask, event):
        assert "Jane" not in str(mask(event))


class TestOttusBillingBreakdown:
    def test_reads_through_via_the_preset(self, mask):
        billing = {
            "amount": {"value": "1.260", "display": "1.260 KWD", "label": "Amount", "currency_code": "KWD"},
            "fee": {"value": "0.000", "currency_code": "KWD"},
            "sub_total": {"value": "1.260", "currency_code": "KWD"},
        }
        event = {"payment_method_data": {"billing": billing}}
        assert mask(event)["payment_method_data"]["billing"] == billing

    def test_a_billing_address_is_still_masked(self, mask):
        masked = mask({"billing": {"city": "Kuwait City", "postcode": "13001", "company": "Acme"}})
        assert "Kuwait City" not in str(masked)
        assert "13001" not in str(masked)

    @pytest.mark.parametrize("key", ["billing_city", "shipping_postcode"])
    def test_a_flat_billing_field_is_still_masked(self, mask, key):
        assert mask({key: "Kuwait City"}) != {key: "Kuwait City"}


class TestAddressWords:
    @pytest.mark.parametrize("key", ["street", "streetName", "line1", "address_line2", "billAddrCity", "shipAddrLine1"])
    def test_is_an_address(self, key):
        assert classify_key(key, ALL_PACKS) == "address"

    @pytest.mark.parametrize("key", ["pipeline1", "deadline", "timeline_2"])
    def test_is_not(self, key):
        assert classify_key(key, ALL_PACKS) != "address"


class TestTheInheritanceEscape:
    def test_a_safe_key_escapes_in_either_spelling(self, mask):
        masked = mask({"customer": {"customer_id": "c-1", "customerId": "c-1"}})
        assert masked["customer"] == {"customer_id": "c-1", "customerId": "c-1"}

    def test_a_display_name_is_a_persons_under_a_person(self, mask):
        # `display_name` left the core safe keys: under a customer it is theirs.
        assert "Jane" not in str(mask({"customer": {"displayName": "Jane P"}}))
