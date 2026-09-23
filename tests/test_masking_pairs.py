"""A `{name, value}` pair: the value is judged by the name next to it.

Connect logs its checkout attempt details with `order_description` items of
this shape (live on jade):

    {"label_en": "Customer name", "name": "customer_name", "value": "<first last>"}

The key rules judged each key alone, which got it exactly backwards: `name` is
a person key, so the field id "customer_name" was tokenized, and `value` is
nothing, so the customer's name shipped in clear. The email item was safe only
because an email address has a shape a content rule knows.

The same blindness let `{"name": "cvv", "value": "123"}` ship a CVV, and on a
service without the pci pack `{"key": "card_number", "value": <PAN>}` ship a
whole PAN. HAR header lists (`{"name": "Authorization", "value": ...}`) are the
same shape.

So when a dict has a `value` and an identifier sibling whose text classifies,
the value is masked as the strictest type any identifier (or the container)
gives it, and the identifier -- a field label -- stays readable. A `name` that
reads like a person ("Eric Holder", "Pan Wei") never becomes readable that
way; only a label made of field words ("Customer name", "Card Number") or one
word does. A `name` that classifies as nothing is readable only as a snake_case
field id (`order_no`).
"""

import pytest

from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS

ORDER_DESCRIPTION = [
    {"label_ar": "رقم الطلب", "label_en": "Order no", "name": "order_no", "order": 0, "value": "E2E-014-A-103838"},
    {
        "label_ar": "البريد الإلكتروني للعميل",
        "label_en": "Customer email",
        "name": "customer_email",
        "order": 1,
        "value": "e2e-014@ottu.dev",
    },
    {"label_ar": "اسم العميل", "label_en": "Customer name", "name": "customer_name", "order": 0, "value": "Dacian Popute"},
]


def mask(value, packs=ALL_PACKS):
    return MaskPIIFilter(packs=packs)._mask_value(value)


class TestConnectsOrderDescription:
    def test_the_customers_name_is_masked_and_the_field_id_reads(self):
        masked = mask({"order_description": [dict(item) for item in ORDER_DESCRIPTION]})["order_description"]
        name_item = masked[2]
        assert "Dacian" not in str(name_item)
        assert name_item["name"] == "customer_name"
        assert name_item["label_en"] == "Customer name"

    def test_the_email_value_is_masked_and_its_id_reads(self):
        masked = mask({"order_description": [dict(item) for item in ORDER_DESCRIPTION]})["order_description"]
        assert "e2e-014@ottu.dev" not in str(masked[1])
        assert masked[1]["name"] == "customer_email"

    def test_the_order_number_reads_through(self):
        masked = mask({"order_description": [dict(item) for item in ORDER_DESCRIPTION]})["order_description"]
        assert masked[0] == ORDER_DESCRIPTION[0]


class TestTheLeaksItCloses:
    def test_a_cvv_named_by_its_sibling(self):
        assert mask({"name": "cvv", "value": "123"}) == {"name": "cvv", "value": "[CVV-MASKED]"}

    def test_a_pan_named_by_its_sibling_without_the_pci_pack(self):
        masked = mask({"key": "card_number", "value": "4111111111111111"}, packs=frozenset({"default"}))
        assert masked == {"key": "card_number", "value": "411111******1111"}

    def test_a_password_named_by_its_sibling(self):
        assert "hunter2" not in str(mask({"key": "password", "value": "hunter2"}))

    def test_a_har_header_list(self):
        headers = [
            {"name": "Authorization", "value": "Bearer abc123def456"},
            {"name": "Content-Type", "value": "application/json"},
        ]
        masked = mask({"headers": headers})["headers"]
        assert "abc123def456" not in str(masked)
        assert masked[0]["name"] == "Authorization"
        assert masked[1] == headers[1]


class TestTheStrictestTypeWins:
    def test_across_identifiers(self):
        # `customer_code` alone is generic; the label says CVV -- a keyed hash
        # of a CVV must never be what comes out.
        assert mask({"name": "customer_code", "label": "CVV", "value": "123"})["value"] == "[CVV-MASKED]"

    def test_the_container_is_a_floor(self):
        masked = mask({"cvv": {"name": "x_code", "value": "123"}})
        assert "123" not in str(masked)


class TestANameThatIsAPerson:
    @pytest.mark.parametrize("person", ["Jane Doe", "Pan Wei", "Eric Holder"])
    def test_stays_masked(self, person):
        masked = mask({"leaderboard": [{"name": person, "value": 42}]})["leaderboard"][0]
        assert person.split()[0] not in str(masked)

    def test_a_label_of_field_words_is_a_label(self):
        # Event-MS extra fields: `name` carries the field's label.
        masked = mask({"name": "Full Name", "value": "Jane Doe"})
        assert masked["name"] == "Full Name"
        assert "Jane" not in str(masked)
