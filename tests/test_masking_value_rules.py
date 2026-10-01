"""Value rules: a service's own shapes of value, masked as their label
wherever they are logged (ECSCTX_MASK_VALUE_RULES).

ecsctx names no such shape itself. A service lists its rules, and the engine
asks them about every mapping the key walk meets, every string that is JSON
text, and every JSON object written in free text or in a body redact_body
masks: a matching value is the rule's label, never hashed, in every pack.
These tests use a rule of their own. Every test runs with a keyset and
without one.
"""

import json
import logging

import pytest
from django.test import override_settings

from ecsctx.contrib.django.checks import find_masking_errors
from ecsctx.contrib.net import redact_body
from ecsctx.masking import (
    ValueRule,
    configure_masking_value_rules,
    get_masking_value_rules,
)
from ecsctx.masking.config import _reset_masking_config, configure_masking_packs
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS, mask_by_patterns, rules_for
from ecsctx.pii import configure_pii
from ecsctx.processors import mask_sensitive_data

LABEL = "[SAD-MASKED]"
SECRET = "c2VjcmV0LWJsb2I="
BLOB = {"kind": "vault-blob", "payload": SECRET, "meta": {"size": 3, "tags": ["a"]}}
NOT_A_BLOB = {"kind": "note", "payload": "hello"}
ASKED: list = []


def _is_blob(value) -> bool:
    ASKED.append(value)
    return value.get("kind") == "vault-blob" and "payload" in value


BLOB_RULE = ValueRule("sad", _is_blob, hints=("vault-blob",))
RULES = (BLOB_RULE,)


@pytest.fixture(autouse=True, params=["keyset", "no-keyset"])
def mode(request, token_keyset_path):
    if request.param == "keyset":
        configure_pii(token_keyset_path=token_keyset_path, env="test")
    ASKED.clear()
    return request.param


@pytest.fixture
def blob_rules():
    configure_masking_value_rules(RULES)


def _walk(event: dict) -> dict:
    return mask_sensitive_data(None, "info", json.loads(json.dumps(event)))


def _text(text: str, packs=ALL_PACKS) -> str:
    return mask_by_patterns(text, rules_for(frozenset(packs)))


def _message(msg, *args, packs=None) -> str:
    record = logging.LogRecord("t", logging.INFO, __file__, 0, msg, args, None)
    MaskPIIFilter(packs=packs).filter(record)
    return record.getMessage()


@pytest.mark.usefixtures("blob_rules")
class TestAConfiguredRule:
    @pytest.mark.parametrize("key", ["payload", "token", "password", "card", "customer", "udf9"])
    def test_a_mapping_under_any_key_is_its_label(self, key):
        assert _walk({key: BLOB}) == {key: LABEL}

    @pytest.mark.parametrize("key", ["payload", "token", "note"])
    def test_json_text_under_any_key_is_its_label(self, key):
        assert _walk({key: json.dumps(BLOB)}) == {key: LABEL}

    def test_json_text_holding_one_deeper_under_a_credential_key_is_the_label(self):
        # Hashed whole, the token was a keyed hash of the value.
        assert _walk({"token": json.dumps({"wrapper": BLOB})}) == {"token": LABEL}

    def test_in_a_container_and_a_list_the_rest_reads_as_before(self):
        masked = _walk({"body": {"blob": BLOB, "amount": "10.000"}, "items": [BLOB, "x"]})
        assert masked == {"body": {"blob": LABEL, "amount": "10.000"}, "items": [LABEL, "x"]}

    @pytest.mark.parametrize("packs", [("default",), tuple(sorted(ALL_PACKS))], ids=["default", "pci"])
    def test_an_object_in_a_message_is_its_label(self, packs):
        assert _message(f"got {json.dumps(BLOB)} back", packs=packs) == f"got {LABEL} back"
        assert _text(f"got {BLOB!r} back", packs) == f"got {LABEL} back"

    def test_in_json_text_the_label_is_a_json_string(self):
        text = "sent " + json.dumps({"blob": BLOB, "amount": "10.000"})
        masked = _text(text)
        assert masked == f'sent {{"blob": "{LABEL}", "amount": "10.000"}}'
        assert json.loads(masked[5:])

    def test_json_in_a_json_string_is_its_escaped_label(self):
        text = "sent " + json.dumps({"blob": json.dumps(BLOB), "amount": "10.000"})
        assert _text(text) == f'sent {{"blob": "{LABEL}", "amount": "10.000"}}'

    def test_redact_body_masks_it_in_json_and_in_an_element(self):
        assert json.loads(redact_body(json.dumps({"blob": BLOB, "amount": "1"}))) == {"blob": LABEL, "amount": "1"}
        assert redact_body(f"<udf9>{json.dumps(BLOB)}</udf9><id>1</id>") == f"<udf9>{LABEL}</udf9><id>1</id>"
        encoded = json.dumps(BLOB).replace('"', "&quot;")
        assert redact_body(f"<udf9>{encoded}</udf9>") == f"<udf9>{LABEL}</udf9>"

    def test_masking_twice_masks_once_and_hashes_nothing(self):
        for masked in (_text(f"a {json.dumps(BLOB)} b"), redact_body(json.dumps({"t": BLOB})), _walk({"token": BLOB})):
            text = json.dumps(masked) if isinstance(masked, dict) else masked
            assert SECRET not in text
            assert "ptok:v1:" not in text
        once = _text(f"a {json.dumps(BLOB)} b")
        assert _text(once) == once
        assert redact_body(once) == once

    def test_anything_else_reads_as_before(self):
        assert _walk({"payload": NOT_A_BLOB}) == {"payload": NOT_A_BLOB}
        text = f"got {json.dumps(NOT_A_BLOB)} back, vault-blob mentioned"
        assert _text(text) == text

    def test_text_holding_none_of_its_hints_is_never_parsed_to_ask(self):
        ASKED.clear()
        text = f"got {json.dumps(NOT_A_BLOB)} back"
        assert _text(text) == text
        assert redact_body(text) == text
        assert ASKED == []

    def test_the_label_is_the_rules_field_type(self):
        configure_masking_value_rules([ValueRule("secret", lambda value: "vault" in value)])
        assert _walk({"x": {"vault": 1}}) == {"x": "[SECRET-MASKED]"}


class TestConfiguration:
    def test_an_explicit_call_wins_and_none_goes_back(self):
        configure_masking_value_rules(RULES)
        assert get_masking_value_rules() == RULES
        configure_masking_value_rules(None)
        assert BLOB_RULE not in get_masking_value_rules()

    def test_a_dotted_path_to_a_rule_or_a_collection(self):
        configure_masking_value_rules(["tests.test_masking_value_rules.BLOB_RULE"])
        assert get_masking_value_rules() == (BLOB_RULE,)
        configure_masking_value_rules("tests.test_masking_value_rules.RULES")
        assert get_masking_value_rules() == RULES

    def test_the_django_setting(self):
        with override_settings(ECSCTX_MASK_VALUE_RULES=["tests.test_masking_value_rules.RULES"]):
            assert _walk({"x": BLOB}) == {"x": LABEL}

    def test_the_environment_variable_names_import_paths(self, monkeypatch):
        monkeypatch.setenv("ECSCTX_MASK_VALUE_RULES", "tests.test_masking_value_rules.RULES")
        assert _walk({"x": BLOB}) == {"x": LABEL}

    @pytest.mark.parametrize("item", ["tests.test_masking_value_rules.NOPE", "no_such_module.RULES", "RULES", 42])
    def test_an_explicit_item_that_is_not_a_rule_raises(self, item):
        with pytest.raises(ValueError, match="value rule|import"):
            configure_masking_value_rules([item])

    def test_a_setting_item_that_is_not_one_is_dropped_warned_and_reported(self, monkeypatch):
        monkeypatch.setenv("ECSCTX_MASK_VALUE_RULES", "no_such_module.RULES,tests.test_masking_value_rules.RULES")
        with pytest.warns(RuntimeWarning, match="no_such_module"):
            assert _walk({"x": BLOB}) == {"x": LABEL}
        [error] = [error for error in find_masking_errors({}) if "ECSCTX_MASK_VALUE_RULES" in error]
        assert "no_such_module.RULES" in error

    def test_configuring_them_forgets_the_strings_known_clean(self):
        # The known-clean set is keyed on the content rules alone: a string
        # masked clean with no value rule came back unmasked once one was on.
        text = f"got {json.dumps(BLOB)} back"
        configure_masking_value_rules(())
        assert _text(text) == text
        configure_masking_value_rules(RULES)
        assert _text(text) == f"got {LABEL} back"

    def test_a_reset_forgets_them_too(self, monkeypatch):
        text = f"got {json.dumps(BLOB)} back"
        configure_masking_value_rules(())
        assert _text(text) == text
        _reset_masking_config()
        monkeypatch.setenv("ECSCTX_MASK_VALUE_RULES", "tests.test_masking_value_rules.RULES")
        assert _text(text) == f"got {LABEL} back"

    def test_a_rule_that_raises_leaves_the_marker_never_an_exception(self):
        def broken(_value):
            raise RuntimeError("rule failed")

        configure_masking_value_rules([ValueRule("sad", broken)])
        record = logging.LogRecord("t", logging.INFO, __file__, 0, "got %s", ([{"a": 1}],), None)
        assert MaskPIIFilter().filter(record) is True
        assert record.getMessage() == "[MASKING-FAILED: RuntimeError]"


def test_every_pack_asks_it(blob_rules):
    for packs in (["default"], sorted(ALL_PACKS)):
        configure_masking_packs(packs)
        assert _walk({"event": f"got {json.dumps(BLOB)}", "blob": BLOB}) == {"event": f"got {LABEL}", "blob": LABEL}
