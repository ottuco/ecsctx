"""A value split between a record's template and its argument is masked in
the record itself (#160054).

`logger.info("cvv=%s", "123")` shipped masked: the formatter's processor
masks the formatted line whole. But the filter masks a record's template and
its arguments apart, and `cvv=%s` and `123` hold nothing to mask on their
own, so after it `record.getMessage()` still read `cvv=123` -- what a handler
that never calls `format()` prints, and what Sentry's logging integration and
`handleError` read. A record whose rendering masks differently from its masked
arguments rendered is now rendered, masked whole, its arguments `()`. One
where nothing spans the two keeps its template and arguments, as before.
"""

import logging

import pytest

from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS
from ecsctx.pii import configure_pii, is_configured, tokenize


@pytest.fixture(autouse=True, params=["keyset", "no-keyset"])
def mode(request, token_keyset_path):
    if request.param == "keyset":
        configure_pii(token_keyset_path=token_keyset_path, env="test")
    return request.param


def secret(value: str) -> str:
    return tokenize(value, "secret") if is_configured() else "[SECRET-MASKED]"


def _filtered(msg, args, packs=None):
    record = logging.LogRecord("t", logging.INFO, __file__, 0, msg, args, None)
    MaskPIIFilter(packs=packs).filter(record)
    return record


class _Lines(logging.Handler):
    """A handler that never calls format(): it reads the record itself."""

    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


class TestAValueSplitBetweenTemplateAndArgument:
    @pytest.mark.parametrize(
        ("msg", "args", "packs", "expected"),
        [
            ("cvv=%s", ("123",), None, "cvv=[CVV-MASKED]"),
            ("declined: cvv %s rejected", ("1234",), None, "declined: cvv [CVV-MASKED] rejected"),
            ("the cvv is %s", ("123",), ALL_PACKS, "the cvv is [CVV-MASKED]"),
            ("card %s %s", ("4111111111111111", "123"), ALL_PACKS, "card 411111******1111 [CVV-MASKED]"),
        ],
    )
    def test_the_record_renders_masked(self, msg, args, packs, expected):
        record = _filtered(msg, args, packs)
        assert record.getMessage() == expected
        assert record.args == ()

    def test_a_credential_after_its_scheme(self):
        record = _filtered("retried with Bearer %s", ("abc123def456",))
        assert record.getMessage() == f"retried with Bearer {secret('abc123def456')}"

    def test_a_handler_that_never_formats_prints_it_masked(self, logging_state):
        logger = logging.getLogger("ecsctx.tests.template_split")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        handler = _Lines()
        handler.addFilter(MaskPIIFilter())
        logger.addHandler(handler)
        logger.info("cvv=%s", "123")
        assert handler.lines == ["cvv=[CVV-MASKED]"]


class TestNothingSpansTheTwo:
    def test_the_template_and_arguments_stay(self):
        record = _filtered("user %s paid %s KWD", ("bob", "12.500"))
        assert (record.msg, record.args) == ("user %s paid %s KWD", ("bob", "12.500"))

    def test_an_argument_masked_on_its_own_keeps_the_template(self):
        record = _filtered("sent to %s", ("jane@example.com",))
        assert record.msg == "sent to %s"
        assert "jane@example.com" not in record.getMessage()

    def test_a_mapping_keeps_them_too(self):
        record = _filtered("paid %(amount)s by %(user)s", ({"amount": "12.500", "user": "bob"},))
        assert (record.msg, record.args) == ("paid %(amount)s by %(user)s", {"amount": "12.500", "user": "bob"})
