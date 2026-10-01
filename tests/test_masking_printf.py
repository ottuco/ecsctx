"""The filter reads a %-style template as CPython's `%` does (#160054).

When masking turns a number into text -- a phone number or a card number
passed as an int -- the filter renders the record from the masked arguments,
reading that number's conversion as `%s`. To find it, it counts the
template's conversions as CPython does; `%.f`, a precision with no digits,
was not read as one, so the count slipped, the `%d` meant for the masked
number met text, and the record became `[MASKING-FAILED: TypeError]`.

Hypothesis is not a test dependency, so this is a generated table: every
flag, width, precision, length modifier and conversion, each rendered by the
filter before a number masking turns into text and compared with CPython's
own rendering of the same conversion, the masked number after it, and the
line masked whole, as the filter masks what it renders.
"""

import itertools
import logging

import pytest

from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import mask_by_patterns, rules_for
from ecsctx.masking.tokens import mask_by_field_type
from ecsctx.pii import configure_pii

# A number the default pack masks as text: a phone number.
PHONE = 5551234567
# Each flag, and flags together in either order.
FLAGS = ["", "-", "0", "#", " ", "+", "-0", "0-", "- +#0"]
WIDTHS = ["", "1", "9", "*"]
PRECISIONS = ["", ".", ".0", ".2", ".*"]
LENGTHS = ["", "h", "l", "L"]
CONVERSIONS = "diouxXeEfFgGcrsa"
VALUES = {**dict.fromkeys("diouxX", 7), **dict.fromkeys("eEfFgG", 10.5), "c": "c", "r": "x", "s": "x", "a": "x"}


# The tables read templates, which no keyset changes: they run without one,
# the masked number its label. The templates below run in both modes.
@pytest.fixture(params=["keyset", "no-keyset"])
def mode(request, token_keyset_path):
    if request.param == "keyset":
        configure_pii(token_keyset_path=token_keyset_path, env="test")
    return request.param


def _rendered(msg, args) -> str:
    record = logging.LogRecord("t", logging.INFO, __file__, 0, msg, args, None)
    MaskPIIFilter(packs=("default",)).filter(record)
    return record.getMessage()


def _masked(text: str) -> str:
    """What the filter does to a line it renders: the rules, over all of it
    (`+10.500000` reads as a phone number)."""
    return mask_by_patterns(text, rules_for(frozenset({"default"})))


def _masked_phone() -> str:
    return _masked(str(PHONE))


def _mask_by_key(number: int) -> str:
    return mask_by_field_type(str(number), "phone")


def _cpython(spec: str, args):
    """CPython's rendering of one conversion, or None where it refuses it."""
    try:
        return spec % args
    except (TypeError, ValueError):
        return None


def _star_args(width: str, precision: str) -> tuple:
    return (*((3,) if width == "*" else ()), *((2,) if precision == ".*" else ()))


@pytest.mark.parametrize("length", LENGTHS)
@pytest.mark.parametrize("conversion", CONVERSIONS)
def test_every_conversion_before_a_masked_number_renders_as_cpython_renders_it(conversion, length):
    phone = _masked_phone()
    assert phone != str(PHONE)
    checked = 0
    for flags, width, precision in itertools.product(FLAGS, WIDTHS, PRECISIONS):
        spec = f"%{flags}{width}{precision}{length}{conversion}"
        args = (*_star_args(width, precision), VALUES[conversion])
        if (expected := _cpython(spec, args)) is None:
            continue
        assert _rendered(f"{spec} then %d", (*args, PHONE)) == _masked(f"{expected} then {phone}"), spec
        checked += 1
    assert checked


@pytest.mark.parametrize("length", LENGTHS)
@pytest.mark.parametrize("conversion", CONVERSIONS)
def test_every_keyed_conversion_renders_as_cpython_renders_it(conversion, length):
    # A number in a mapping is masked by its key, as in any mapping: under
    # `phone` it becomes text.
    phone = _mask_by_key(PHONE)
    for flags, width, precision in itertools.product(FLAGS, WIDTHS[:-1], PRECISIONS[:-1]):
        spec = f"%(v){flags}{width}{precision}{length}{conversion}"
        args = {"v": VALUES[conversion], "phone": PHONE}
        if (expected := _cpython(spec, args)) is None:
            continue
        assert _rendered(f"{spec} then %(phone)d", (args,)) == _masked(f"{expected} then {phone}"), spec


@pytest.mark.parametrize(
    ("msg", "args", "expected"),
    [
        # #160054: the precision with no digits.
        ("paid %.f KWD by %d", (10.5, PHONE), "paid 10 KWD by {phone}"),
        ("%5.f|%-*.*f|%d", (2.5, 8, 2, 1.5, PHONE), "    2|1.50    |{phone}"),
        # A literal percent takes no argument; `%%%d` is one and a conversion.
        ("100%% of %d", (PHONE,), "100% of {phone}"),
        ("%%%d", (PHONE,), "%{phone}"),
        # A key holding parentheses, as CPython reads it: to the one that
        # balances the first.
        ("%(a(b))s %(phone)d", ({"a(b)": "x", "phone": PHONE},), "x {keyed}"),
    ],
)
def test_templates_the_old_reading_miscounted(mode, msg, args, expected):
    assert _rendered(msg, args) == expected.format(phone=_masked_phone(), keyed=_mask_by_key(PHONE))


@pytest.mark.parametrize(
    ("msg", "args"),
    [
        # CPython reads a `%` after a flag, width, key or precision as an
        # unsupported conversion: nothing to render, the marker as before.
        ("%5% %d", (PHONE,)),
        ("%(a)% %(phone)d", ({"a": 1, "phone": PHONE},)),
    ],
)
def test_a_template_cpython_refuses_is_still_the_marker(mode, msg, args):
    assert _rendered(msg, args).startswith("[MASKING-FAILED: ")
