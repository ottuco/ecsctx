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



class Unbuildable(list):
    def __init__(self, *args):
        raise ValueError("foreign constructor ran")


def test_a_subclass_constructor_never_runs(shipped):
    stream, errors = shipped
    body = list.__new__(Unbuildable)
    body.append({"email": "jane@example.com"})

    structlog.get_logger("t").info("response sent", http={"response": {"body": body}})

    assert not errors
    (line,) = [x for x in _lines(stream) if x["message"] == "response sent"]
    shipped_body = line["http"]["response"]["body"]
    assert type(shipped_body) is list
    assert "jane@example.com" not in json.dumps(shipped_body)


def test_a_drf_list_serializer_data_ships(shipped):
    from rest_framework import serializers

    class Item(serializers.Serializer):
        email = serializers.EmailField()

    stream, errors = shipped
    data = Item([{"email": "jane@example.com"}], many=True).data

    structlog.get_logger("t").info("response sent", http={"response": {"body": data}})

    assert not errors
    (line,) = [x for x in _lines(stream) if x["message"] == "response sent"]
    assert "jane@example.com" not in json.dumps(line["http"])
    assert isinstance(line["http"]["response"]["body"], list)


def test_a_drf_list_field_error_body_ships(shipped):
    from rest_framework import serializers

    class Ticket(serializers.Serializer):
        ids = serializers.ListField(child=serializers.IntegerField())

    stream, errors = shipped
    serializer = Ticket(data={"ids": [1, "x", 3, "y"]})
    assert not serializer.is_valid()

    structlog.get_logger("t").info("response sent", http={"response": {"body": serializer.errors}})

    assert not errors
    (line,) = [x for x in _lines(stream) if x["message"] == "response sent"]
    assert set(line["http"]["response"]["body"]["ids"]) == {"1", "3"}


def test_a_masking_failure_on_a_dict_record_ships_a_marker_line(shipped, monkeypatch):
    stream, errors = shipped

    def boom(self, args, ctx):
        raise RuntimeError("masker broke")

    monkeypatch.setattr(MaskPIIFilter, "_mask_args", boom)

    structlog.get_logger("t").info("response sent", email="jane@example.com", http={"body": {"a": 1}})

    assert not errors
    (line,) = [x for x in _lines(stream) if "MASKING-FAILED" in x["message"]]
    assert line["message"] == "[MASKING-FAILED: RuntimeError]"
    assert "service" in line and "log" in line
    assert "jane@example.com" not in json.dumps(line)
    assert "http" not in line and "email" not in line


def test_a_masking_failure_on_a_str_record_keeps_the_str_marker(shipped, monkeypatch):
    stream, errors = shipped
    monkeypatch.setattr(MaskPIIFilter, "_mask_args", lambda self, args, ctx: 1 / 0)

    logging.getLogger("plain").info("card 4111111111111111")

    assert not errors
    (line,) = [x for x in _lines(stream) if "MASKING-FAILED" in x["message"]]
    assert line["message"] == "[MASKING-FAILED: ZeroDivisionError]"
    assert "4111111111111111" not in json.dumps(line)
