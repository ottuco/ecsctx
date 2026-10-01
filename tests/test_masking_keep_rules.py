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
import html
import json
import logging
import re

import pytest
from django.test import override_settings

from ecsctx.contrib.django.checks import find_masking_errors
from ecsctx.contrib.net import (
    configure_redaction,
    loggable_body,
    loggable_request_body,
    redact_body,
    redact_url,
)
from ecsctx.masking import (
    KeepRule,
    ValueRule,
    configure_masking_value_rules,
    get_masking_value_rules,
    is_kept,
    mask_outside_kept,
    patterns,
    value_rules,
)
from ecsctx.masking.config import configure_masking_packs, configure_masking_safe_keys
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS, mask_by_patterns, rules_for
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
KEEP_ALL = KeepRule(lambda value: True)
LABEL_RULE = ValueRule("sad", _is_sealed, hints=("sealed-box",))
LABEL = "[SAD-MASKED]"
OUTER_RULE = ValueRule("secret", lambda value: value.get("kind") == "outer-box", hints=("outer-box",))
# A label rule with a hint of its own, which never matches.
OTHER_RULE = ValueRule("secret", lambda value: value.get("kind") == "never", hints=("other-shape",))
PASSWORD = "password=s3cret-Hunter2"


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


class Ambiguous:
    """A label rule's `field_type` and a keep rule's `keep = True` at once."""

    field_type = "sad"
    keep = True
    hints = ("sealed-box",)

    def matches(self, value) -> bool:
        return _is_sealed(value)


DUCK_KEEP = DuckKeep()
KEEP_YES = KeepYes()
AMBIGUOUS = Ambiguous()

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


def _text(text: str, packs: frozenset[str]) -> str:
    return mask_by_patterns(text, rules_for(packs | {"default"}))


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

    def test_a_rule_with_both_a_field_type_and_keep_is_refused(self):
        # It loaded as a keep rule, the less safe reading (review M6).
        rules, problems = value_rules.load_value_rules([AMBIGUOUS, KEEP_RULE])
        assert rules == (KEEP_RULE,)
        [problem] = problems
        assert "`field_type`" in problem
        assert "`keep = True`" in problem
        with pytest.raises(ValueError, match="`field_type`"):
            configure_masking_value_rules([AMBIGUOUS])
        with pytest.raises(ValueError, match="`keep = True`"):
            configure_masking_value_rules([(KEEP_RULE, AMBIGUOUS)])

    def test_an_ambiguous_rule_is_reported_by_the_boot_check(self, monkeypatch):
        monkeypatch.setenv(
            "ECSCTX_MASK_VALUE_RULES",
            "tests.test_masking_keep_rules.AMBIGUOUS,tests.test_masking_keep_rules.KEEP_RULES",
        )
        with pytest.warns(RuntimeWarning, match="AMBIGUOUS"):
            assert _walk({"x": SEALED}) == {"x": SEALED}
        [error] = [error for error in find_masking_errors({}) if "ECSCTX_MASK_VALUE_RULES" in error]
        assert "AMBIGUOUS" in error
        assert "`field_type`" in error
        assert "`keep = True`" in error

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
            # A card number inside a longer text leaf (review I2).
            {"note": "card 4111111111111111 exp 12/27"},
            {"box": "4111111111111111+cvv+123"},
            {"ref": "4111111111111111ab"},
            {"note": "Visa 4111 1111 1111 1111 on file"},
            {"memo": ";4111111111111111=25121010000000000000?"},
            {"note": "{not json 4111111111111111"},
        ],
        ids=[
            "cvv", "cardNumber", "a-pan-leaf", "an-int-pan", "a-nested-json-cvv", "a-pin-in-a-list",
            "a-pan-in-prose", "a-pan-in-base64", "a-pan-in-hex", "a-grouped-pan-in-prose", "track-2",
            "a-pan-in-text-that-is-no-json",
        ],
    )
    def test_the_guard_a_match_holding_card_data_is_walked(self, extra):
        holding = {**SEALED, **extra}
        assert not is_kept(holding)
        _masked_as_a_walk(_walk({"payload": holding})["payload"])
        assert _walk({"payload": json.dumps(holding)})["payload"] != json.dumps(holding)

    @pytest.mark.parametrize(
        "extra",
        [
            {"note": "cvv=123"},
            {"box": "QUJD1790318444473QUJD"},
            {"ref": "order 4111111111111112 retried"},
            {"ref": "41111111111111111111"},
            {"note": json.dumps({"keyExpiration": "1790318444473"})},
        ],
        ids=["a-cvv-in-a-string", "epoch-milliseconds", "a-run-failing-luhn", "twenty-digits", "json-text-epoch"],
    )
    def test_what_the_guard_does_not_read_in_a_text_leaf(self, extra):
        # A CVV or other short value inside a longer string is the matcher's
        # to keep out; a run that is no card number is no card number.
        holding = {**SEALED, **extra}
        assert is_kept(holding)
        assert _walk({"payload": holding}) == {"payload": holding}

    def test_a_rule_that_keeps_everything_still_cannot_ship_a_card(self):
        configure_masking_value_rules([KeepRule(lambda value: True)])
        masked = _walk({"payment": {"card": {"number": "4111111111111111", "cvv": "123", "expiry": "12/27"}}})
        card = masked["payment"]["card"]
        assert card["number"] == "411111******1111"
        assert card["cvv"] == "[CVV-MASKED]"
        assert card["expiry"] == "12/27"

    @pytest.mark.parametrize(
        "pair",
        [
            {"name": "cvv", "value": "123"},
            {"Name": "Security Code", "Value": "123"},
            {"label": "Card Number", "value": "4111111111111111"},
            {"field": "pin", "value": "1234"},
            {"key": "cardCvv", "value": "123"},
        ],
        ids=["cvv", "security-code", "card-number-label", "pin-field", "card-cvv-key"],
    )
    def test_the_guard_reads_a_pair_labelled_as_card_data(self, pair):
        # The key walk masks a pair's value as its identifier names it, so the
        # guard reads the pair as a key (review I2).
        holding = {**SEALED, "fields": [pair]}
        assert not is_kept(holding)
        _masked_as_a_walk(_walk({"payload": holding})["payload"])
        configure_masking_value_rules([KeepRule(lambda value: True)])
        event = {"payment": {"fields": [pair]}}
        assert _walk(event) == _unconfigured(lambda: _walk(event))
        assert _walk(event) != event

    def test_a_pair_labelled_as_anything_else_is_kept(self):
        holding = {**SEALED, "fields": [{"name": "customer_note", "value": "gift"}]}
        assert _walk({"payload": holding}) == {"payload": holding}

    @pytest.mark.parametrize(
        "leaf",
        [
            "8171999927660000",
            "122000000000003",
            "4111111111111112",
            "3542323393147",
            "15423233931470",
            "1542 3233 9314 7",
        ],
        ids=["luhn-8-prefix", "uatp-1-prefix", "not-luhn", "13-digits-from-3", "14-digits-from-1", "13-in-groups"],
    )
    def test_every_card_number_shape_but_epoch_milliseconds_blocks_keeping(self, leaf):
        # Only Google Pay's keyExpiration shape is exempt (review M1): no
        # issuer prefix or Luhn check lets another digit run through.
        holding = {**SEALED, "note": leaf}
        assert not is_kept(holding)
        _masked_as_a_walk(_walk({"payload": holding})["payload"])

    @pytest.mark.parametrize("expiration", ["1542323393147", "2000000000000"], ids=["2018", "after-may-2033"])
    def test_a_timestamp_is_not_a_card_number_to_the_guard(self, expiration):
        # Google Pay's signedKey carries keyExpiration, epoch milliseconds:
        # thirteen digits, shaped like a card number but no issuer's. From
        # 18 May 2033 they start with a 2, and tokens must stay keepable.
        holding = {**SEALED, "signedKey": json.dumps({"keyExpiration": expiration})}
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

    def test_a_label_rule_wins_inside_a_keep_match(self, packs):
        # A keep rule matching the outer mapping first shipped what a label
        # rule names inside it unlabelled (review M8).
        configure_masking_value_rules([LABEL_RULE, KEEP_ALL])
        event = {"outer": {"inner": SEALED}, "note": "x"}
        labelled = {"outer": {"inner": LABEL}, "note": "x"}
        assert _walk({"payload": event}) == {"payload": labelled}
        assert json.loads(_walk({"payload": json.dumps(event)})["payload"]) == labelled
        assert _walk({"password": json.dumps(event)}) == {"password": LABEL}
        assert _text(f"got {json.dumps(event)} back", packs) == f"got {json.dumps(labelled)} back"
        assert json.loads(redact_body(json.dumps(event))) == labelled
        assert not is_kept(event)
        assert not is_kept(json.dumps(event))
        assert is_kept({"outer": {"note": "x"}})

    def test_a_label_rule_listed_after_a_keep_match_of_the_same_value_is_not_asked(self, packs):
        # The first match still wins for the value itself: a keep rule listed
        # first that matches every value labels nothing inside.
        configure_masking_value_rules([KEEP_ALL, LABEL_RULE])
        event = {"outer": {"inner": SEALED}, "note": "x"}
        assert _walk({"payload": event}) == {"payload": event}
        assert _text(f"got {json.dumps(event)} back", packs) == f"got {json.dumps(event)} back"
        assert is_kept(event)

    def test_a_keep_match_the_guard_refuses_asks_no_rule_listed_after_it(self, packs):
        configure_masking_value_rules([KEEP_RULE, LABEL_RULE])
        holding = {**SEALED, "cvv": "123"}
        masked = _walk({"x": holding})["x"]
        _masked_as_a_walk(masked)
        assert LABEL not in _text(f"got {json.dumps(holding)} back", packs)

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



def _kept_in(masked: str, kept: str) -> None:
    assert kept in masked
    assert "s3cret-Hunter2" not in masked


# CVV and SAD containers in text that are not the key right before the
# object (review M2), and the same keys beside the value (review I1): text
# that names a CVV or SAD key, element or pair label anywhere keeps nothing.
FLOORED = {
    "a-list-between": '{"cvv": [ PLAIN ]}',
    "a-pair-labelled-cvv": '{"name": "cvv", "value": PLAIN}',
    "a-pair-labelled-pin-as-json-text": '{"Name": "PIN", "Value": "ESCAPED"}',
    "quoted-key-equals": '"cvv" = PLAIN',
    "quoted-key-arrow": "'cvv' => PLAIN",
    "bare-key-arrow": "securityCode => PLAIN",
    "a-sibling-of-a-cvv-key": '{"cvv": "123", "token": PLAIN}',
    "a-pair-whose-name-is-written-twice": '{"name": "cvv", "name": "note", "value": PLAIN}',
    "an-object-that-does-not-parse": '{"cvv": undefined, "token": PLAIN}',
    "a-cvv-list-beside": '{"payment": {"cvv": ["123"]}, "token": PLAIN}',
    "a-cvv-pair-beside": '[{"name": "cvv", "value": "123"}, PLAIN]',
    "a-cvv-key-before": '"cvv" = "123", "token" => PLAIN',
    "a-form-field-before": "a=1&cvv=123 PLAIN",
    "an-element-after": "PLAIN <pin>1234</pin>",
}
# Keys about a CVV, not one: text naming them keeps its value.
NOT_FLOORED = {
    "a-flag-about-a-cvv": '{"cvv_required": true, "token": PLAIN}',
    "a-cvv-word-in-prose": "the cvv check passed for PLAIN",
}


def _written(template: str) -> str:
    return template.replace("ESCAPED", json.dumps(json.dumps(SEALED))[1:-1]).replace("PLAIN", json.dumps(SEALED))


@pytest.mark.usefixtures("keep")
class TestText:
    def test_a_message_ships_it_as_sent_and_masks_the_rest(self, packs):
        text = f"got {json.dumps(SEALED)} with {PASSWORD}"
        for masked in (_text(text, packs), _message(text), _walk({"event": text})["event"]):
            _kept_in(masked, json.dumps(SEALED))

    def test_a_python_repr(self, packs):
        text = f"got {SEALED!r} with {PASSWORD}"
        _kept_in(_text(text, packs), repr(SEALED))
        _kept_in(_message("got %s with %s", SEALED, PASSWORD), repr(SEALED))

    def test_json_in_a_json_string(self, packs):
        text = "sent " + json.dumps({"blob": json.dumps(SEALED), "password": "s3cret-Hunter2"})
        _kept_in(_text(text, packs), json.dumps(json.dumps(SEALED)))

    def test_json_text_walked_by_its_keys_then_read_by_the_text_rules(self):
        masked = json.loads(_walk({"body": json.dumps({"wrapper": SEALED, "password": "s3cret-Hunter2"})})["body"])
        assert masked["wrapper"] == SEALED
        assert masked["password"] != "s3cret-Hunter2"

    def test_a_template_with_a_credential_word(self):
        assert _message("token %s", json.dumps(SEALED)) == f"token {json.dumps(SEALED)}"
        assert _message("token %(t)s", {"t": SEALED}) == f"token {SEALED}"

    @pytest.mark.parametrize(
        "template",
        ["token={}", '{{"token": {}}}', "Authorization: Bearer {}", "<password>{}</password>", "password: {}"],
        ids=["token=", "quoted-token", "bearer", "password-element", "password:"],
    )
    @pytest.mark.parametrize("separators", [None, (",", ":")], ids=["spaced", "compact"])
    def test_a_credential_before_it_does_not_stop_it(self, template, separators, packs):
        sealed = json.dumps(SEALED, separators=separators)
        text = f"{template.format(sealed)} {PASSWORD}"
        _kept_in(_text(text, packs), sealed)

    @pytest.mark.parametrize(
        "template",
        ["<cvv>{}</cvv>", '{{"securityCode": {}}}', "{{'cvv': {}}}", "cvv={}", '{{"pin": "{}"}}'],
        ids=["cvv-element", "securityCode", "repr-cvv", "cvv=", "pin-json-string"],
    )
    def test_nothing_under_a_cvv_or_sad_key_is_kept(self, template, packs):
        sealed = json.dumps(SEALED)
        if template.endswith('"}}'):
            sealed = json.dumps(sealed)[1:-1]
        elif "'" in template:
            sealed = repr(SEALED)
        text = template.format(sealed)
        assert _text(text, packs) != text

    @pytest.mark.parametrize("template", FLOORED.values(), ids=FLOORED.keys())
    def test_nothing_in_a_cvv_container_is_kept_whatever_stands_between(self, template, packs):
        # Not only right after a CVV key: the key walk keeps nothing in any
        # of these (review M2).
        text = _written(template)
        masked = _text(text, packs)
        assert masked == _unconfigured(lambda: _text(text, packs))
        assert SEALED["api_key"] not in masked

    @pytest.mark.parametrize("template", NOT_FLOORED.values(), ids=NOT_FLOORED.keys())
    def test_text_naming_no_cvv_key_keeps_its_value(self, template, packs):
        assert json.dumps(SEALED) in _text(_written(template), packs)

    def test_an_outer_label_match_wins(self, packs):
        configure_masking_value_rules([KEEP_RULE, OUTER_RULE])
        text = "got " + json.dumps({"kind": "outer-box", "inner": SEALED})
        assert _text(text, packs) == "got [SECRET-MASKED]"

    def test_an_inner_label_match_wins_over_the_keep_match_around_it(self, packs):
        # 0.17.0 kept it with the kept object (review M8): the keep match is
        # now read as one nothing matches, the inner match labelled.
        configure_masking_value_rules([KEEP_RULE, OUTER_RULE])
        sealed = {**SEALED, "inner": {"kind": "outer-box"}}
        text = f"got {json.dumps(sealed)}"
        masked = _text(text, packs)
        assert '"inner": "[SECRET-MASKED]"' in masked
        assert SEALED["api_key"] not in masked
        configure_masking_value_rules([OUTER_RULE])
        assert masked == _text(text, packs)

    def test_a_label_rule_listed_first_labels_it(self, packs):
        configure_masking_value_rules([LABEL_RULE, KEEP_RULE])
        assert _text(f"got {json.dumps(SEALED)}", packs) == f"got {LABEL}"

    def test_the_guard(self, packs):
        holding = json.dumps({**SEALED, "note": json.dumps({"cvv": "123"})})
        assert _text(f"got {holding}", packs) != f"got {holding}"

    def test_a_keep_match_the_guard_refuses_is_read_as_one_nothing_matches(self, packs):
        # Rule 2 too: a label match inside it is labelled (review I1).
        text = "got " + json.dumps({"outer": 1, "cvv": "123", "inner": SEALED}) + " end"
        configure_masking_value_rules([KeepRule(lambda value: "outer" in value), LABEL_RULE])
        masked, body = _text(text, packs), redact_body(text)
        configure_masking_value_rules([LABEL_RULE])
        assert masked == _text(text, packs)
        assert body == redact_body(text)
        assert LABEL in masked
        assert LABEL in body

    def test_masking_twice_masks_once(self, packs):
        once = _text(f"a {json.dumps(SEALED)} b {PASSWORD} c {SEALED!r}", packs)
        assert _text(once, packs) == once
        assert "s3cret-Hunter2" not in once

    def test_text_already_holding_the_placeholder_is_masked_as_before(self, packs):
        text = f"[KEPT-A-MASKED] {json.dumps(SEALED)}"
        assert SEALED["api_key"] not in _text(text, packs)

    def test_a_placeholder_some_rule_destroyed_is_not_restored(self, packs):
        # Inside a credential's quoted value the rule hashes the placeholder
        # with the rest of the value: the kept object goes with it.
        text = '{"password": "x ' + json.dumps(SEALED).replace('"', '\\"') + '"}'
        masked = _text(text, packs)
        assert BOX not in masked
        assert "KEPT-" not in masked

    def test_a_placeholder_is_named_from_the_value_it_holds(self):
        # Not by position (review M3, M4): the same value has the same name in
        # any text, another value another name, all of one length.
        sealed, other = json.dumps(SEALED), json.dumps({**SEALED, "n": 1})
        stash = patterns.stash_kept(f"a {sealed} b {other} c {sealed}", KEEP_RULES)
        names = re.findall(r"\[KEPT-[A-Z]+-MASKED\]", stash.text)
        assert len(names) == 3
        assert names[0] == names[2] != names[1]
        assert len(names[0]) == len(names[1])
        assert stash.originals == {names[0]: sealed, names[1]: other}
        assert patterns.stash_kept(f"x {sealed}", KEEP_RULES).text == f"x {names[0]}"

    def test_two_identical_kept_values_are_both_restored(self, packs):
        text = f"a {json.dumps(SEALED)} b {PASSWORD} c {json.dumps(SEALED)}"
        masked = _text(text, packs)
        assert masked.count(json.dumps(SEALED)) == 2
        assert "s3cret-Hunter2" not in masked

    def test_a_credential_hashed_around_a_kept_value_carries_that_value(self, mode, packs):
        # The credential's token hashes the placeholder: named by position,
        # every kept value there gave one token, where the key walk gives
        # each its own (review M3).
        def in_a_secret(sealed: dict) -> str:
            return json.dumps({"secret": json.dumps({"k": sealed})})

        first, second = {**SEALED, "n": 1}, {**SEALED, "n": 2}
        masked = _text(in_a_secret(first), packs)
        assert BOX not in masked
        assert masked == _text(in_a_secret(first), packs)
        if mode == "keyset":
            assert masked != _text(in_a_secret(second), packs)

    def test_a_value_holding_a_lone_surrogate_is_kept_and_nothing_raises(self, packs):
        text = "got " + json.dumps({**SEALED, "note": "\ud800"}, ensure_ascii=False)
        assert _text(text, packs) == text


@pytest.mark.usefixtures("keep")
class TestCost:
    @pytest.fixture
    def finder_calls(self, monkeypatch):
        calls: list = []
        finder = patterns.kept_spans

        def counting(*args):
            calls.append(args)
            return finder(*args)

        monkeypatch.setattr(patterns, "kept_spans", counting)
        return calls

    @pytest.mark.parametrize("rules", [(), (LABEL_RULE,)], ids=["nothing", "label-rules-only"])
    def test_the_span_finder_is_never_called_without_a_keep_rule(self, rules, finder_calls, packs):
        configure_masking_value_rules(rules)
        text = f"got {json.dumps(SEALED)} back"
        _text(text, packs)
        _message(text)
        _walk({"event": text, "x": SEALED, "y": json.dumps({"z": SEALED})})
        encoded = json.dumps(SEALED).replace('"', "&quot;")
        redact_body(f"{text} <udf9>{encoded}</udf9>")
        assert finder_calls == []

    def test_the_span_finder_runs_with_one(self, finder_calls, packs):
        _text(f"got {json.dumps(SEALED)} back", packs)
        assert finder_calls

    def test_a_keep_rule_is_never_asked_about_text_holding_none_of_its_hints(self, packs):
        configure_masking_value_rules([KEEP_RULE, OTHER_RULE])
        ASKED.clear()
        text = "got " + json.dumps({"kind": "other-shape", "nested": {"kind": "other-shape"}})
        _text(text, packs)
        _message(text)
        _walk({"x": json.dumps({"kind": "other-shape"}), "y": json.dumps({"z": {"kind": "other-shape"}})})
        encoded = text.replace('"', "&quot;")
        redact_body(f"{text} <udf9>{encoded}</udf9>")
        assert ASKED == []

    def test_texts_whose_hints_select_some_rules_split_them_once(self, monkeypatch, packs):
        # A text holding one rule's hints asks a selection of the rules: the
        # same tuple for every such text, so its split is cached once and the
        # configured rules' split is not emptied out of the cache with it.
        configure_masking_value_rules([KEEP_RULE, OTHER_RULE])
        calls: list = []
        split_of = value_rules._split_of
        monkeypatch.setattr(value_rules, "_splits", {})
        monkeypatch.setattr(value_rules, "_split_of", lambda rules: calls.append(rules) or split_of(rules))
        for n in range(100):
            text = f"got {json.dumps({**SEALED, 'n': n})} back"
            _text(text, packs)
            _walk({"x": json.dumps({**SEALED, "n": n})})
            redact_body(KPAY.format(json.dumps({**SEALED, "n": n}).replace('"', "&quot;")))
        assert len(calls) <= 2

    def test_rule_2_does_not_run_with_keep_rules_only(self, monkeypatch, packs):
        calls: list = []
        monkeypatch.setattr(patterns, "_mask_object", lambda m, rules: calls.append(m) or m.group(0))
        text = "got " + json.dumps({"kind": "note", "about": "sealed-box"})
        assert not patterns._has_value_object(text, text.lower())
        _text(text, packs)
        assert calls == []
        configure_masking_value_rules([KEEP_RULE, LABEL_RULE])
        assert patterns._has_value_object(text, text.lower())


# Keys Connect lists as extra secret body keys (ECSCTX_REDACT_EXTRA_SECRET_KEYS).
SIGNED = {**SEALED, "signature": "c2lnbmF0dXJlLWJsb2I=", "hash": "aGFzaC1ibG9i"}
# Past the default body cap, as an Apple Pay token is (about 5 KB).
LARGE = {**SEALED, "box": "QUJD" * 1500}
KPAY = "<request><id>TRANPORTAL123</id><password>S3cretPassw0rd</password><udf9>{}</udf9><amt>10.000</amt></request>"


class _Response:
    def __init__(self, text: str) -> None:
        self.text = text
        self.headers = {"Content-Type": "application/json"}
        self.status_code = 200


@pytest.mark.usefixtures("keep")
class TestBodies:
    def test_a_json_body(self):
        masked = json.loads(redact_body(json.dumps({"blob": SEALED, "password": "s3cret-Hunter2"})))
        assert masked["blob"] == SEALED
        assert masked["password"] != "s3cret-Hunter2"

    def test_json_text_in_a_json_string_under_a_credential_key(self):
        # Split around the object, the JSON value rule left `""` behind.
        body = json.dumps({"token": json.dumps(SEALED), "access_token": "s3cret-Hunter2"})
        masked = redact_body(body)
        assert json.loads(masked)["token"] == json.dumps(SEALED)
        assert "s3cret-Hunter2" not in masked
        assert redact_body(masked) == masked

    def test_connects_extra_secret_keys_leave_it_intact(self):
        configure_redaction(extra_secret_keys=["signature", "hash"])
        body = json.dumps({"blob": SIGNED, "signature": "outer-signature"})
        masked = json.loads(redact_body(body))
        assert masked["blob"] == SIGNED
        assert masked["signature"] != "outer-signature"

    def test_an_element_holding_it_with_a_password_beside_it(self):
        configure_redaction(extra_secret_keys=["signature", "hash"])
        body = KPAY.format(json.dumps(SIGNED))
        masked = redact_body(body)
        assert f"<udf9>{json.dumps(SIGNED)}</udf9>" in masked
        assert "S3cretPassw0rd" not in masked
        assert redact_body(masked) == masked

    def test_an_entity_encoded_element(self):
        configure_redaction(extra_secret_keys=["signature", "hash"])
        encoded = json.dumps(SIGNED).replace('"', "&quot;")
        masked = redact_body(KPAY.format(encoded))
        assert f"<udf9>{encoded}</udf9>" in masked
        assert "S3cretPassw0rd" not in masked

    def test_an_entity_encoded_element_whose_base64_reads_as_a_form_field(self):
        # `…cvvXYZ==` is a form field named like a CVV to the form rule: the
        # kept text is set aside with its element, so no rule reads it.
        padded = {**SEALED, "box": "QUJDcvvXYZ=="}
        encoded = json.dumps(padded).replace('"', "&quot;")
        plain = json.dumps(padded)
        assert f"<udf9>{encoded}</udf9>" in redact_body(KPAY.format(encoded))
        assert f"<udf9>{plain}</udf9>" in redact_body(KPAY.format(plain))

    def test_loggable_request_body_with_a_raised_cap(self):
        configure_redaction(body_log_cap=64 * 1024)
        masked = json.loads(loggable_request_body(None, {"blob": LARGE, "password": "s3cret-Hunter2"}))
        assert masked["blob"] == LARGE
        assert masked["password"] != "s3cret-Hunter2"

    def test_loggable_body_with_a_raised_cap(self):
        configure_redaction(body_log_cap=64 * 1024)
        masked = json.loads(loggable_body(_Response(json.dumps({"blob": LARGE, "password": "s3cret-Hunter2"}))))
        assert masked["blob"] == LARGE
        assert masked["password"] != "s3cret-Hunter2"

    def test_the_default_cap_cuts_it(self):
        assert len(loggable_request_body(None, {"blob": LARGE})) == 4096

    def test_nothing_under_a_cvv_key_is_kept(self):
        assert SEALED["api_key"] not in redact_body(KPAY.format(json.dumps({"cvv": SEALED})))
        assert BOX not in redact_body(f"<cvv>{json.dumps(SEALED)}</cvv>")

    @pytest.mark.parametrize("template", FLOORED.values(), ids=FLOORED.keys())
    def test_nothing_in_a_cvv_container_is_kept_whatever_stands_between(self, template):
        body = _written(template)
        assert patterns.kept_spans(body, KEEP_RULES) == []
        assert redact_body(body) == _unconfigured(lambda: redact_body(body))

    @pytest.mark.parametrize("template", NOT_FLOORED.values(), ids=NOT_FLOORED.keys())
    def test_text_naming_no_cvv_key_keeps_its_value(self, template):
        assert json.dumps(SEALED) in redact_body(_written(template))

    def test_an_element_naming_a_placeholder_gets_no_copy_of_a_kept_value(self):
        # Its entity-encoded text decodes to a placeholder's name, which the
        # outer restore filled with the kept value beside it (review M4).
        forged = "&#123;&quot;password&quot;:&quot;pw&quot;,&quot;n&quot;:&quot;&#91;KEPT-A-MASKED&#93;&quot;&#125;"
        masked = redact_body(f"<r><x>{forged}</x><udf9>{json.dumps(SEALED)}</udf9></r>")
        element = json.loads(html.unescape(masked.split("<x>")[1].split("</x>")[0]))
        assert element["n"] == "[KEPT-A-MASKED]"
        assert element["password"] != "pw"
        assert f"<udf9>{json.dumps(SEALED)}</udf9>" in masked

    def test_two_identical_entity_encoded_elements_are_both_restored(self):
        encoded = json.dumps(SEALED).replace('"', "&quot;")
        masked = redact_body(f"<r><udf8>{encoded}</udf8><password>S3cretPassw0rd</password><udf9>{encoded}</udf9></r>")
        assert f"<udf8>{encoded}</udf8>" in masked
        assert f"<udf9>{encoded}</udf9>" in masked
        assert "S3cretPassw0rd" not in masked

    def test_a_label_rule_that_raises_inside_a_keep_match_refuses_it_and_raises_nothing(self, packs):
        # Asked about a keep match's members (review M5): its error refuses
        # the keep, and the value is masked as with the label rule alone.
        def raises_on_members(value):
            if value.get("kind") == "inner-box":
                raise RuntimeError("rule failed")
            return False

        label_rule = ValueRule("sad", raises_on_members, hints=("sealed-box",))
        sealed = {**SEALED, "inner": {"kind": "inner-box"}}
        compact = json.dumps(sealed, separators=(",", ":"))

        def every_path():
            return (
                _text(f"got {json.dumps(sealed)} back", packs),
                redact_body(json.dumps(sealed)),
                redact_body(KPAY.format(json.dumps(sealed).replace('"', "&quot;"))),
                redact_url(f"https://pg.example/pay?card_number={compact}&password=s3cret"),
                mask_outside_kept(f"got {json.dumps(sealed)} back", str.upper),
            )

        configure_masking_value_rules([KEEP_RULE, label_rule])
        masked = every_path()
        configure_masking_value_rules([label_rule])
        assert masked == every_path()
        assert SEALED["api_key"] not in masked[0]

    def test_redact_url_never_raises_with_a_keep_rule_that_raises(self):
        def broken(_value):
            raise RuntimeError("rule failed")

        configure_masking_value_rules([KeepRule(broken)])
        url = "https://pg.example/pay?card_number=" + json.dumps(SEALED).replace(" ", "") + "&password=s3cret"
        assert "s3cret" not in redact_url(url)
        assert "s3cret-Hunter2" not in redact_body(f"{json.dumps(SEALED)} {PASSWORD}")


def _shout(text: str) -> str:
    """A service's own pass: every word `secret` masked."""
    return text.replace("secret", "[OWN-MASKED]")


class TestHelpers:
    @pytest.mark.usefixtures("keep")
    def test_is_kept_for_a_mapping_and_for_json_text(self):
        assert is_kept(SEALED)
        assert is_kept(json.dumps(SEALED))
        assert is_kept(f"  {json.dumps(SEALED, indent=2)}")
        assert is_kept(SEALED, key="token")

    def test_is_kept_is_false_with_nothing_configured(self):
        assert not is_kept(SEALED)
        assert not is_kept(json.dumps(SEALED))

    def test_is_kept_is_false_for_a_label_match(self):
        configure_masking_value_rules([LABEL_RULE, KEEP_RULE])
        assert not is_kept(SEALED)

    @pytest.mark.usefixtures("keep")
    @pytest.mark.parametrize("key", ["cvv", "securityCode", "pin", "cryptogram"])
    def test_is_kept_is_false_under_a_cvv_or_sad_key(self, key):
        assert not is_kept(SEALED, key=key)
        assert not is_kept(json.dumps(SEALED), key=key)

    @pytest.mark.usefixtures("keep")
    def test_is_kept_is_false_when_the_guard_refuses_it(self):
        assert not is_kept({**SEALED, "cvv": "123"})
        assert not is_kept(json.dumps({**SEALED, "note": "4111111111111111"}))

    @pytest.mark.usefixtures("keep")
    @pytest.mark.parametrize("value", [NOT_SEALED, "not json", 42, None, ["sealed-box"], json.dumps([SEALED])])
    def test_is_kept_is_false_for_anything_else(self, value):
        assert not is_kept(value)

    def test_is_kept_never_raises(self):
        def broken(_value):
            raise RuntimeError("rule failed")

        configure_masking_value_rules([KeepRule(broken), ValueRule("sad", broken)])
        assert not is_kept(SEALED)
        assert not is_kept(json.dumps(SEALED))

    @pytest.mark.usefixtures("keep")
    def test_mask_outside_kept_masks_only_outside(self):
        sealed = {**SEALED, "note": "secret"}
        text = f"secret {json.dumps(sealed)} and secret"
        assert mask_outside_kept(text, _shout) == f"[OWN-MASKED] {json.dumps(sealed)} and [OWN-MASKED]"

    @pytest.mark.usefixtures("keep")
    def test_mask_outside_kept_does_not_restore_a_destroyed_placeholder(self):
        masked = mask_outside_kept(f"secret {json.dumps(SEALED)}", lambda text: "[OWN-MASKED] everything")
        assert masked == "[OWN-MASKED] everything"
        masked = mask_outside_kept(f"a {json.dumps(SEALED)}", lambda text: text.replace("[KEPT-", "[GONE-"))
        assert BOX not in masked

    def test_mask_outside_kept_with_nothing_configured_masks_it_all(self):
        sealed = {**SEALED, "note": "secret"}
        assert "secret" not in mask_outside_kept(f"secret {json.dumps(sealed)}", _shout)


# What ships is the text as written, so a keep decision rests on it as
# written: a duplicate key json.loads drops, or a comment ast.literal_eval
# drops, must not carry card data past the guard (review C1).
DUP_PAN = '{"kind": "sealed-box", "box": "4111111111111111", "box": "Zm9v", "api_key": "sk_test_fake_0123456789"}'
DUP_CVV = '{"kind": "sealed-box", "box": "Zm9v", "meta": {"cvv": "123"}, "meta": {"n": 1}}'
NESTED_DUP = {
    "kind": "sealed-box",
    "box": "Zm9v",
    "inner": '{"blob": {"cvv": "123", "number": "4111111111111111"}, "blob": "ZW5j"}',
}
REPR_COMMENT = "{'kind': 'sealed-box', 'box': 'Zm9v', 'meta': {'n': 'abc' # 4111111111111111 cvv=123\n}}"


def _unconfigured(mask):
    """What ``mask()`` gives with no value rule configured."""
    rules = get_masking_value_rules()
    configure_masking_value_rules(())
    try:
        return mask()
    finally:
        configure_masking_value_rules(rules)


@pytest.mark.usefixtures("keep")
class TestWhatShipsIsWhatWasJudged:
    @pytest.mark.parametrize("written", [DUP_PAN, DUP_CVV, json.dumps(NESTED_DUP)], ids=["pan", "cvv", "nested"])
    def test_the_key_walk_keeps_no_json_text_with_a_duplicate_key(self, written):
        for event in ({"payload": written}, {"token": written}, {"event": written}):
            assert _walk(event) == _unconfigured(lambda event=event: _walk(event))
        assert _message(written) == _unconfigured(lambda: _message(written))
        assert _walk({"payload": written}) != {"payload": written}

    def test_a_json_text_leaf_with_a_duplicate_key_is_card_data(self):
        assert _walk({"payload": NESTED_DUP}) == _unconfigured(lambda: _walk({"payload": NESTED_DUP}))
        assert _walk({"payload": NESTED_DUP}) != {"payload": NESTED_DUP}

    @pytest.mark.parametrize("written", [DUP_PAN, DUP_CVV, json.dumps(NESTED_DUP), REPR_COMMENT])
    def test_text_keeps_no_object_written_otherwise_than_it_parses(self, written, packs):
        text = f"got {written} end"
        masked = _text(text, packs)
        assert masked == _unconfigured(lambda: _text(text, packs))
        assert masked != text
        escaped = "sent " + json.dumps({"blob": written})
        assert _text(escaped, packs) == _unconfigured(lambda: _text(escaped, packs))

    def test_a_python_repr_that_round_trips_is_still_kept(self, packs):
        text = f"got {SEALED!r} end"
        assert _text(text, packs) == text

    @pytest.mark.parametrize("written", [DUP_PAN, json.dumps(NESTED_DUP)], ids=["pan", "nested"])
    def test_bodies(self, written):
        body = f'{{"token": {written}, "amt": "1"}}'
        masked = redact_body(body)
        assert masked == _unconfigured(lambda: redact_body(body))
        if written == DUP_PAN:
            assert SEALED["api_key"] not in masked
        escaped = json.dumps({"paymentToken": written, "amt": "1"})
        assert redact_body(escaped) == _unconfigured(lambda: redact_body(escaped))

    @pytest.mark.parametrize("written", [DUP_PAN, DUP_CVV, json.dumps(NESTED_DUP)], ids=["pan", "cvv", "nested"])
    def test_is_kept(self, written):
        assert not is_kept(written)

    def test_is_kept_reads_a_json_text_leaf_strictly(self):
        assert not is_kept(NESTED_DUP)

    def test_mask_outside_kept(self, packs):
        def own(text: str) -> str:
            return text.replace("123", "[OWN-MASKED]")

        text = f"got {DUP_CVV}"
        assert mask_outside_kept(text, own) == own(text)
