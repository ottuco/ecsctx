"""Keep rules: a service's own shapes of value that ship in logs as sent
(ECSCTX_MASK_VALUE_RULES).

A keep rule is a value rule that writes no label: a value it matches is left
exactly as it came, under any key, a credential's included, and the walk does
not descend into it. Rules are asked in list order and the first match wins,
so a label rule listed first still labels the same value. Two things no keep
rule can override:

- the floor: nothing is kept under a CVV or SAD key, or inside a CVV or SAD
  container, a pair labelled as one included;
- the guard: a match that holds a card, CVV or SAD key, or a card number, at
  any depth, is walked as if nothing matched.

These tests use a shape of their own. Every test runs with a keyset and
without one, and in the default pack and with every pack.
"""

import copy
import json
import logging

import pytest
from django.test import override_settings

from ecsctx.contrib.django.checks import find_masking_errors
from ecsctx.masking import (
    KeepRule,
    ValueRule,
    configure_masking_value_rules,
    get_masking_value_rules,
)
from ecsctx.masking.config import configure_masking_packs, configure_masking_safe_keys
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS
from ecsctx.masking.value_rules import keep_rules, label_rules
from ecsctx.pii import configure_pii
from ecsctx.processors import mask_sensitive_data

BOX = "c2VhbGVkLWJveC1jb250ZW50cw=="
# What ships as sent: a credential and a payment id the key rules would mask,
# and an IBAN-shaped hex id the IBAN rule would.
SEALED = {
    "kind": "sealed-box",
    "box": BOX,
    "api_key": "sk_test_fake_0123456789",
    "transaction_id": "TXN-0000-0001",
    "ref": "BE71A9F3C2D4E5F6B7C8",
}
NOT_SEALED = {"kind": "note", "api_key": "sk_test_fake_0123456789"}
ASKED: list = []


def _is_sealed(value) -> bool:
    ASKED.append(value)
    return value.get("kind") == "sealed-box" and "box" in value


KEEP_RULE = KeepRule(_is_sealed, hints=("sealed-box",))
KEEP_RULES = (KEEP_RULE,)
LABEL_RULE = ValueRule("sad", _is_sealed, hints=("sealed-box",))
LABEL = "[SAD-MASKED]"


class DuckKeep:
    """A keep rule by protocol alone: `keep` is True and `matches` is callable."""

    keep = True
    hints = ("sealed-box",)

    def matches(self, value) -> bool:
        return _is_sealed(value)


class KeepYes:
    """Not a rule: `keep` must be True itself, and there is no field_type."""

    keep = "yes"

    def matches(self, value) -> bool:
        return True


DUCK_KEEP = DuckKeep()
KEEP_YES = KeepYes()

PACKS = [["default"], sorted(ALL_PACKS)]


@pytest.fixture(autouse=True, params=["keyset", "no-keyset"])
def mode(request, token_keyset_path):
    if request.param == "keyset":
        configure_pii(token_keyset_path=token_keyset_path, env="test")
    ASKED.clear()
    return request.param


@pytest.fixture(autouse=True, params=PACKS, ids=["default", "every-pack"])
def packs(request):
    configure_masking_packs(request.param)
    return frozenset(request.param)


@pytest.fixture
def keep():
    configure_masking_value_rules(KEEP_RULES)


def _walk(event: dict) -> dict:
    return mask_sensitive_data(None, "info", json.loads(json.dumps(event)))


def _message(msg, *args) -> str:
    record = logging.LogRecord("t", logging.INFO, __file__, 0, msg, args, None)
    assert MaskPIIFilter().filter(record) is True
    return record.getMessage()


def _holds_no_box(masked) -> None:
    text = masked if isinstance(masked, str) else json.dumps(masked)
    assert BOX not in text


def _masked_as_a_walk(masked: dict) -> None:
    """What the key walk makes of SEALED when nothing keeps it."""
    assert masked["kind"] == "sealed-box"
    assert masked["api_key"] != SEALED["api_key"]


class TestConfiguration:
    def test_a_keep_rule_object_loads(self):
        configure_masking_value_rules(KEEP_RULES)
        assert get_masking_value_rules() == KEEP_RULES
        assert _walk({"x": SEALED}) == {"x": SEALED}

    def test_a_dotted_path_to_a_rule_or_a_collection(self):
        configure_masking_value_rules(["tests.test_masking_keep_rules.KEEP_RULE"])
        assert get_masking_value_rules() == (KEEP_RULE,)
        configure_masking_value_rules("tests.test_masking_keep_rules.KEEP_RULES")
        assert _walk({"x": SEALED}) == {"x": SEALED}

    def test_the_environment_variable(self, monkeypatch):
        monkeypatch.setenv("ECSCTX_MASK_VALUE_RULES", "tests.test_masking_keep_rules.KEEP_RULES")
        assert _walk({"x": SEALED}) == {"x": SEALED}

    def test_the_django_setting(self):
        with override_settings(ECSCTX_MASK_VALUE_RULES=["tests.test_masking_keep_rules.KEEP_RULES"]):
            assert _walk({"x": SEALED}) == {"x": SEALED}

    def test_nothing_configured_keeps_nothing(self):
        _masked_as_a_walk(_walk({"x": SEALED})["x"])

    def test_a_duck_typed_keep_rule_loads(self):
        configure_masking_value_rules([DUCK_KEEP])
        assert get_masking_value_rules() == (DUCK_KEEP,)
        assert _walk({"x": SEALED}) == {"x": SEALED}

    def test_keep_must_be_true_itself(self):
        with pytest.raises(ValueError, match="keep = True"):
            configure_masking_value_rules([KEEP_YES])

    @pytest.mark.parametrize("hints", [(1,), "sealed-box", None], ids=["not-text", "one-string", "none"])
    def test_hints_must_be_a_collection_of_strings(self, hints):
        # Looked for in text as it is masked, anything else raised there.
        with pytest.raises(ValueError, match="hints"):
            configure_masking_value_rules([KeepRule(_is_sealed, hints=hints)])
        with pytest.raises(ValueError, match="hints"):
            configure_masking_value_rules([ValueRule("sad", _is_sealed, hints=hints)])

    def test_label_and_keep_rules_share_one_list(self):
        rules = (LABEL_RULE, KEEP_RULE, DUCK_KEEP)
        configure_masking_value_rules(rules)
        assert get_masking_value_rules() == rules
        assert keep_rules(rules) == (KEEP_RULE, DUCK_KEEP)
        assert label_rules(rules) == (LABEL_RULE,)
        assert keep_rules(rules) is keep_rules(rules)

    def test_a_bad_item_is_reported_by_the_boot_check(self, monkeypatch):
        monkeypatch.setenv(
            "ECSCTX_MASK_VALUE_RULES",
            "tests.test_masking_keep_rules.KEEP_YES,tests.test_masking_keep_rules.KEEP_RULES",
        )
        with pytest.warns(RuntimeWarning, match="KEEP_YES"):
            assert _walk({"x": SEALED}) == {"x": SEALED}
        [error] = [error for error in find_masking_errors({}) if "ECSCTX_MASK_VALUE_RULES" in error]
        assert "KEEP_YES" in error


@pytest.mark.usefixtures("keep")
class TestTheKeyWalk:
    @pytest.mark.parametrize("key", ["payload", "token", "password", "card", "customer", "udf9"])
    def test_a_mapping_under_any_key_ships_as_sent(self, key):
        assert _walk({key: SEALED}) == {key: SEALED}

    @pytest.mark.parametrize("key", ["payload", "token", "password", "card", "customer", "udf9"])
    def test_json_text_under_any_key_ships_as_sent(self, key):
        text = json.dumps(SEALED)
        assert _walk({key: text}) == {key: text}

    def test_the_message_itself(self):
        text = json.dumps(SEALED)
        assert _walk({"event": text}) == {"event": text}
        assert _message(text) == text

    def test_a_kept_mapping_is_a_copy(self):
        sealed = copy.deepcopy(SEALED)
        masked = MaskPIIFilter()._mask_value({"payload": sealed})
        assert masked == {"payload": SEALED}
        assert masked["payload"] is not sealed

    def test_its_siblings_and_list_items_are_masked_as_before(self):
        masked = _walk({"blob": SEALED, "password": "s3cret-Hunter2", "items": [SEALED, "jane@example.com"]})
        assert masked["blob"] == SEALED
        assert masked["password"] != "s3cret-Hunter2"
        assert masked["items"][0] == SEALED
        assert masked["items"][1] != "jane@example.com"

    def test_percent_args(self):
        assert _message("got %s", SEALED) == f"got {SEALED}"
        assert _message("got %s", json.dumps(SEALED)) == f"got {json.dumps(SEALED)}"
        assert _message("got %(t)s", {"t": SEALED}) == f"got {SEALED}"

    @pytest.mark.parametrize(
        "event",
        [
            {"cvv": "VALUE"},
            {"securityCode": "VALUE"},
            {"pin": "VALUE"},
            {"cryptogram": "VALUE"},
            {"cvv": {"x": "VALUE"}},
            {"cvv": ["VALUE"]},
            {"name": "cvv", "value": "VALUE"},
        ],
        ids=["cvv", "securityCode", "pin", "cryptogram", "in-a-cvv-container", "in-a-cvv-list", "cvv-pair"],
    )
    @pytest.mark.parametrize("form", ["mapping", "json-text"])
    def test_the_floor_nothing_is_kept_under_a_cvv_or_sad_key(self, event, form):
        value = SEALED if form == "mapping" else json.dumps(SEALED)
        event = json.loads(json.dumps(event).replace('"VALUE"', json.dumps(value)))
        masked = _walk({"payload": event})
        assert masked != {"payload": event}
        _holds_no_box(masked)

    def test_the_floor_holds_below_a_key_the_service_lists_in_a_cvv_container(self):
        # A listed key reads through a CVV container; nothing below it is kept.
        configure_masking_safe_keys(["acquirercode"])
        masked = _walk({"payload": {"cvv": {"acquirercode": SEALED}}})
        _masked_as_a_walk(masked["payload"]["cvv"]["acquirercode"])

    @pytest.mark.parametrize(
        "extra",
        [
            {"cvv": "123"},
            {"cardNumber": "4111111111111111"},
            {"note": "4111 1111 1111 1111"},
            {"note": 4111111111111111},
            {"note": json.dumps({"inner": {"securityCode": "123"}})},
            {"deep": [{"pin": "1234"}]},
        ],
        ids=["cvv", "cardNumber", "a-pan-leaf", "an-int-pan", "a-nested-json-cvv", "a-pin-in-a-list"],
    )
    def test_the_guard_a_match_holding_card_data_is_walked(self, extra):
        holding = {**SEALED, **extra}
        _masked_as_a_walk(_walk({"payload": holding})["payload"])
        assert _walk({"payload": json.dumps(holding)})["payload"] != json.dumps(holding)

    def test_a_rule_that_keeps_everything_still_cannot_ship_a_card(self):
        configure_masking_value_rules([KeepRule(lambda value: True)])
        masked = _walk({"payment": {"card": {"number": "4111111111111111", "cvv": "123", "expiry": "12/27"}}})
        card = masked["payment"]["card"]
        assert card["number"] == "411111******1111"
        assert card["cvv"] == "[CVV-MASKED]"
        assert card["expiry"] == "12/27"

    def test_a_timestamp_is_not_a_card_number_to_the_guard(self):
        # Google Pay's signedKey carries keyExpiration, epoch milliseconds:
        # thirteen digits, shaped like a card number but no issuer's.
        holding = {**SEALED, "signedKey": json.dumps({"keyExpiration": "1542323393147"})}
        assert _walk({"payload": holding}) == {"payload": holding}

    @pytest.mark.parametrize(
        "event",
        [
            {"token": {"wrapper": "VALUE"}},
            {"paymentToken": "VALUE_TEXT"},
            {"token_data": "VALUE"},
            {"tokenizationData": {"token": "VALUE_TEXT"}},
            {"card": {"devicePayment": {"paymentToken": "VALUE_TEXT"}}},
        ],
        ids=["token", "paymentToken", "token_data", "tokenizationData.token", "card.devicePayment"],
    )
    def test_a_credential_or_card_key_above_a_kept_value_does_not_stop_it(self, event):
        text = json.dumps(event).replace('"VALUE_TEXT"', json.dumps(json.dumps(SEALED)))
        event = json.loads(text.replace('"VALUE"', json.dumps(SEALED)))
        assert _walk({"payload": event}) == {"payload": event}

    def test_list_order_decides_label_first(self):
        configure_masking_value_rules([LABEL_RULE, KEEP_RULE])
        assert _walk({"x": SEALED, "y": json.dumps(SEALED)}) == {"x": LABEL, "y": LABEL}

    def test_list_order_decides_keep_first(self):
        configure_masking_value_rules([KEEP_RULE, LABEL_RULE])
        assert _walk({"x": SEALED, "y": json.dumps(SEALED)}) == {"x": SEALED, "y": json.dumps(SEALED)}

    def test_a_keep_rule_that_raises_keeps_nothing_and_raises_nothing(self):
        def broken(_value):
            raise RuntimeError("rule failed")

        configure_masking_value_rules([KeepRule(broken)])
        _masked_as_a_walk(_walk({"x": SEALED})["x"])
        assert _message("got %s", SEALED) != "[MASKING-FAILED: RuntimeError]"
        # ...and counts as no match: the next rule is asked.
        configure_masking_value_rules([KeepRule(broken), LABEL_RULE])
        assert _walk({"x": SEALED}) == {"x": LABEL}

    def test_each_mapping_is_asked_once(self):
        # _mask_dict asks the rules about every value it walks; the value is
        # not asked again on the way down.
        ASKED.clear()
        _walk({"a": {"b": {"c": 1}}, "items": [{"d": 1}], "customer": {"e": {"f": 1}}})
        assert len(ASKED) == 5

    def test_json_text_holding_a_kept_value_deeper_under_a_credential_key_is_hashed_whole(self):
        # A keep never cuts a value out of a string.
        masked = _walk({"password": json.dumps({"wrapper": SEALED})})["password"]
        assert masked.startswith("ptok:v1:") or masked == "[SECRET-MASKED]"

