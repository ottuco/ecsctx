"""A dataclass or namedtuple is masked by its fields, not only by its text.

ottu_pg logged its decrypted `Trandata` dataclass as a field value. An object
the walk could not enter was replaced by its `str()`, which only the content
rules ever saw -- and a name has no shape to match -- so `customer_first_name`
and `customer_last_name` shipped in clear inside the repr while the email and
phone beside them were masked (28 documents in a day on logs-pci-dev).

Now a dataclass (with a generated repr) and a namedtuple are walked by field
name first, then rendered back to the same `Name(field=...)` text: the value
stays a string, so an index that mapped it as one does not start rejecting
documents. A field declared `repr=False` stays out, as it was out of the repr.

A namedtuple also crashed the caller: the walk rebuilt it with
`type(value)(generator)`, which a namedtuple does not accept, and the error
escaped `filter()` into the caller's `log.info()`.
"""

import sys
from collections import namedtuple
from dataclasses import dataclass, field

from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS


@dataclass
class Trandata:
    session_id: str
    amount: str
    customer_email: str
    customer_first_name: str
    customer_last_name: str


@dataclass
class GatewayCreds:
    merchant_id: str
    key: str = field(repr=False)


Payer = namedtuple("Payer", "name email")


def mask(value):
    return MaskPIIFilter(packs=ALL_PACKS)._mask_value(value)


class TestADataclass:
    def test_its_fields_are_masked_by_name(self):
        trandata = Trandata("6626d9a4", "1.210", "e2e@ottu.dev", "Dacian", "Popute")
        masked = mask({"payload": {"trandata": trandata}})["payload"]["trandata"]
        assert isinstance(masked, str)
        assert masked.startswith("Trandata(session_id='6626d9a4', amount='1.210'")
        assert "Dacian" not in masked
        assert "Popute" not in masked
        assert "e2e@ottu.dev" not in masked

    def test_a_field_kept_out_of_its_repr_stays_out(self):
        masked = mask({"gateway": GatewayCreds("TEST1234", "sk_live_hunter2")})["gateway"]
        assert "hunter2" not in masked
        assert "TEST1234" in masked


class TestANamedtuple:
    def test_its_fields_are_masked_by_name(self):
        masked = mask({"payer": Payer("Jane Payer", "jane@example.com")})["payer"]
        assert isinstance(masked, str)
        assert "Jane" not in masked
        assert "jane@example.com" not in masked

    def test_a_set_of_them_stays_a_set(self):
        masked = mask({"payers": {Payer("Jane Payer", "a@b.co"), Payer("Omar Ali", "c@d.co")}})["payers"]
        assert isinstance(masked, set)
        assert "Jane" not in str(masked)

    def test_as_a_positional_argument(self):
        assert "Jane" not in str(MaskPIIFilter(packs=ALL_PACKS)._mask_args((Payer("Jane Payer", "a@b.co"),), MaskPIIFilter(packs=ALL_PACKS)._context()))


def test_a_tuple_that_cannot_be_rebuilt_from_an_iterable_is_masked_not_raised():
    # sys.version_info is a struct sequence: a tuple the walk could not rebuild.
    assert mask({"python": sys.version_info})["python"] is not None
