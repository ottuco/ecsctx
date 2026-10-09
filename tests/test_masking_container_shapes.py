"""A logged body keeps its line when masking meets an awkward container.

Both shapes come from DRF responses that `api_logging` logs as `response.data`
(Event, #160126). Since 0.7.0 the line was lost; from 0.14.0 the masker caught
the failure but the record became a str that `ProcessorFormatter` cannot take:

- an integer key (an error body keyed by list index) reached `ecs_logging`,
  which tests `"." in key`;
- a list subclass whose `__init__` needs an argument (`ReturnList`) could not
  be rebuilt, raising `KeyError`, which only `TypeError` was caught for.
"""

import io
import json
import logging
import logging.config

import pytest
import structlog

from ecsctx.contrib.django import get_logging_config, setup_logging
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS


class NeedsKeyword(list):
    """The shape of DRF's ReturnList, without Django."""

    def __init__(self, *args, **kwargs):
        self.serializer = kwargs.pop("serializer")
        super().__init__(*args, **kwargs)


@pytest.fixture
def shipped():
    """Lines the real handler chain writes, and every error it swallowed."""
    logging.config.dictConfig(get_logging_config(root_level="INFO", handler_level="INFO"))
    setup_logging()
    root = logging.getLogger()
    handler = next(h for h in root.handlers if h.formatter is not None)
    stream, handler.stream = handler.stream, io.StringIO()
    errors = []
    handle_error = handler.handleError
    handler.handleError = lambda record: errors.append(record)
    try:
        yield handler.stream, errors
    finally:
        handler.stream = stream
        handler.handleError = handle_error


def _lines(stream):
    return [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]


def test_an_integer_key_ships_as_a_string(shipped):
    stream, errors = shipped

    structlog.get_logger("t").info(
        "response sent", http={"response": {"body": {"sub_ticket": {0: {"id": ["required"]}}}}}
    )

    assert not errors
    (line,) = [x for x in _lines(stream) if x["message"] == "response sent"]
    assert line["http"]["response"]["body"] == {"sub_ticket": {"0": {"id": ["required"]}}}


def test_a_list_subclass_that_cannot_be_rebuilt_ships_as_a_list(shipped):
    stream, errors = shipped
    body = NeedsKeyword([{"email": "jane@example.com"}], serializer=object())

    structlog.get_logger("t").info("response sent", http={"response": {"body": body}})

    assert not errors
    (line,) = [x for x in _lines(stream) if x["message"] == "response sent"]
    shipped_body = line["http"]["response"]["body"]
    assert isinstance(shipped_body, list)
    assert "jane@example.com" not in json.dumps(shipped_body)


def test_masking_a_dict_with_integer_keys_gives_string_keys():
    masked = MaskPIIFilter(packs=ALL_PACKS)._mask_value({"errors": {0: {"id": ["x"]}}})

    assert masked == {"errors": {"0": {"id": ["x"]}}}
