"""Masking never makes a log call raise, and never lets an unmasked record out.

The masking filter runs in the handler, outside `emit()`'s `handleError`, and
the processor runs in the caller's thread: an exception in either reached the
caller's `log.info()`. Verified against 0.13.0:

- a cyclic dict (or dataclass) recursed until `RecursionError`;
- a JSON body nested a few hundred levels deep -- about 700 bytes, which a
  crafted callback can send -- did the same once parsed;
- an object whose `__str__` raises propagated its error.

A log line is never worth a failed payment. The walk now stops at a depth
nothing legitimate reaches, and if masking fails for any other reason the
message is replaced whole by a fixed marker -- the one outcome that can never
leak what it failed to mask.
"""

import json
import logging

from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS
from ecsctx.processors import mask_sensitive_data


class Unprintable:
    def __str__(self):
        raise ValueError("no text for you")


def _record(msg, args=()):
    return logging.LogRecord("t", logging.INFO, __file__, 0, msg, args, None)


class TestDepth:
    def test_a_cyclic_dict_is_masked_not_raised(self):
        cyclic = {"name": "Jane"}
        cyclic["self"] = cyclic
        masked = MaskPIIFilter(packs=ALL_PACKS)._mask_value({"payload": cyclic})
        assert "Jane" not in str(masked)

    def test_a_deeply_nested_json_body_is_masked_not_raised(self):
        # ~3.6 KB: 600 levels raised RecursionError in 0.13.0.
        body = '{"a":' * 600 + '"x"' + "}" * 600
        assert json.loads(body)  # valid JSON, just deep
        masked = MaskPIIFilter(packs=ALL_PACKS)._mask_value({"http": {"request": {"body": body}}})
        assert masked["http"]["request"]["body"] is not None


class TestAFailureReplacesTheMessage:
    def test_the_filter_does_not_raise(self):
        record = _record({"event": "paid", "payer": Unprintable(), "name": "Jane Payer"})
        assert MaskPIIFilter(packs=ALL_PACKS).filter(record) is True
        assert "Jane" not in str(record.msg)
        assert "MASKING-FAILED" in str(record.msg)

    def test_the_filter_does_not_raise_on_an_argument(self):
        record = _record("paid by %s", (Unprintable(),))
        assert MaskPIIFilter(packs=ALL_PACKS).filter(record) is True
        assert "MASKING-FAILED" in record.getMessage()

    def test_the_processor_does_not_raise(self):
        event = {"event": "paid", "level": "info", "payer": Unprintable(), "name": "Jane Payer"}
        masked = mask_sensitive_data(None, None, event)
        assert "Jane" not in str(masked)
        assert "MASKING-FAILED" in masked["event"]
        assert masked["level"] == "info"
