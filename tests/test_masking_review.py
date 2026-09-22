"""Regressions an adversarial review of the masking-packs change found.

Each test reproduces a leak or a failure the review demonstrated against the
branch, compared with v0.7.2: what the engine must mask, and how bad
configuration must fail.
"""

import json
import logging
import logging.config
import time
from decimal import Decimal

import pytest

from ecsctx.contrib.django import get_logging_config
from ecsctx.contrib.django.checks import find_masking_errors
from ecsctx.masking.config import get_masking_packs
from ecsctx.masking.exemptions import configure_masking
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import (
    ALL_PACKS,
    classify_key,
    mask_by_patterns,
    mask_card_value,
    rules_for,
)


def _filter(msg, args=None, packs=None):
    record = logging.LogRecord("t", logging.INFO, __file__, 0, msg, args, None)
    MaskPIIFilter(packs=packs).filter(record)
    return record


class TestTheShippedPipeline:
    """Through get_logging_config() and structlog, as a service runs it."""

    def _run(self, emit, capsys):
        import structlog

        from ecsctx.contrib.django import setup_logging

        cfg = get_logging_config(use_cid_filter=False)
        cfg["loggers"] = {}
        logging.config.dictConfig(cfg)
        setup_logging()
        seen = []

        class AfterHandlers(logging.Handler):
            """Reads the record after the console handler, as Sentry's
            LoggingIntegration and Handler.handleError do."""

            def emit(self, record):
                seen.append(record.getMessage())

        spy = AfterHandlers()
        logging.getLogger().addHandler(spy)
        try:
            emit()
        finally:
            logging.getLogger().removeHandler(spy)
            structlog.reset_defaults()
        lines = [json.loads(line) for line in capsys.readouterr().err.splitlines() if line.startswith("{")]
        return lines[-1], seen[-1]

    def test_stdlib_dict_args_keep_key_masking_and_the_record_is_masked_in_place(self, capsys):
        doc, after = self._run(
            lambda: logging.getLogger("std").info(
                "login %(first_name)s pw=%(password)s", {"first_name": "Jane", "password": "hunter2"}
            ),
            capsys,
        )
        assert doc["message"] == "login [NAME-MASKED] pw=[SECRET-MASKED]"
        assert after == "login [NAME-MASKED] pw=[SECRET-MASKED]"

    def test_event_reason_and_labels_are_scanned(self, capsys):
        import structlog

        doc, _ = self._run(
            lambda: structlog.get_logger("s").info(
                "evt",
                ecs_event={"action": "payment.declined", "reason": "declined for jane@example.com"},
                labels={"customer_email": "jane@example.com", "namespace": "cybersource"},
            ),
            capsys,
        )
        assert doc["event"]["reason"] == "declined for [EMAIL-MASKED]"
        assert doc["labels"] == {"customer_email": "[EMAIL-MASKED]", "namespace": "cybersource"}


class TestCardData:
    def test_a_pan_in_track_2_data_is_truncated(self):
        record = _filter("5413330089020011D2512601079360805F", packs=("pci",))
        assert record.msg == "541333******0011D2512601079360805F"

    def test_a_phone_rule_still_ignores_a_digit_run_touching_letters(self):
        session_id = "8231045567ab34cd9f0e1a2b3c4d5e6f7a8b9c0d"
        assert _filter(session_id).msg == session_id

    def test_a_card_value_with_a_marker_inside_is_still_truncated(self):
        # Truncated in place now, rather than collapsed: the PAN goes, the
        # context that makes the line readable stays.
        assert (
            mask_card_value("4111111111111111 cvv [CVV-MASKED]")
            == "411111******1111 cvv [CVV-MASKED]"
        )
        assert mask_card_value("411111******1111") == "411111******1111"


class TestKeyNamesFailClosed:
    """Glued and plural key names that payloads use are masked, as in 0.7.2;
    only listed false positives are safe."""

    @pytest.mark.parametrize(
        "key,expected",
        [
            ("cardcvv", "cvv"),
            ("cvvnumber", "cvv"),
            ("CVVCode", "cvv"),
            ("cardsecuritycode", "cvv"),
            ("phonenumber", "phone"),
            ("mobileno", "phone"),
            ("customerphone", "phone"),
            ("nameoncard", "name"),
            ("customername", "name"),
            ("accountholdername", "name"),
            ("eMail", "email"),
            ("emailid", "email"),
            ("tokens", "secret"),
            ("passwordhash", "secret"),
            ("merchantapikey", "secret"),
            ("addressline1", "address"),
            ("billingdetails", "generic"),
            ("card_number", "card"),
            ],
    )
    def test_masked(self, key, expected):
        assert classify_key(key, frozenset({"default"})) == expected

    @pytest.mark.parametrize(
        "key", ["namespace", "hostname", "filename", "token_type", "card_id"]
    )
    def test_listed_false_positives_are_safe(self, key):
        assert classify_key(key, frozenset({"default"})) is None


class TestArgs:
    def test_an_object_is_masked_through_its_text_not_kept_for_repr(self):
        class Card:
            def __str__(self):
                return "Visa card"

            def __repr__(self):
                return "Card(number='4111111111111111', holder='Jane Doe')"

        assert MaskPIIFilter()._mask_value(Card()) == "Visa card"

    def test_a_number_is_kept_so_numeric_placeholders_format(self):
        record = _filter("refunded %.3f", (Decimal("12.5"),))
        assert record.getMessage() == "refunded 12.500"


class TestMaskedMarker:
    def test_a_record_masked_with_fewer_packs_is_masked_again(self):
        record = logging.LogRecord("t", logging.INFO, __file__, 0, "card 4111111111111111 cvv 123", None, None)
        MaskPIIFilter(packs=("default",)).filter(record)
        MaskPIIFilter(packs=ALL_PACKS).filter(record)
        assert record.msg == "card 411111******1111 cvv [CVV-MASKED]"


class TestConfigurationFailsClosed:
    def test_a_string_setting_is_a_comma_separated_list(self, settings):
        settings.ECSCTX_MASKING_PACKS = "pci, financial_ids"
        assert get_masking_packs() == ALL_PACKS

    def test_an_unknown_pack_masks_with_every_pack_instead_of_raising(self, monkeypatch, recwarn):
        monkeypatch.setenv("ECSCTX_MASKING_PACKS", "pci,finacial_ids")
        assert get_masking_packs() == ALL_PACKS
        assert _filter("cvv 123").msg == "cvv [CVV-MASKED]"

    def test_the_boot_check_reports_an_unknown_pack(self, settings):
        settings.ECSCTX_MASKING_PACKS = ["pcii"]
        errors = find_masking_errors(get_logging_config())
        assert any("pcii" in error for error in errors)


class TestExemptionAnchors:
    def test_a_pattern_applies_from_the_root_or_a_payload_container(self):
        configure_masking(exempt_paths=["payment_methods[*].name"])
        masked = MaskPIIFilter()._mask_dict(
            {"payload": {"payment_methods": [{"name": "KNET"}]}, "extra": {"payment_methods": [{"name": "VISA"}]}}
        )
        assert masked == {
            "payload": {"payment_methods": [{"name": "KNET"}]},
            "extra": {"payment_methods": [{"name": "VISA"}]},
        }

    def test_a_short_pattern_does_not_reach_into_nested_objects(self):
        configure_masking(exempt_paths=["audit"])
        masked = MaskPIIFilter()._mask_dict({"payload": {"order": {"audit": {"first_name": "Jane"}}}})
        assert masked == {"payload": {"order": {"audit": {"first_name": "[NAME-MASKED]"}}}}

    def test_user_name_keeps_content_masking(self):
        masked = MaskPIIFilter()._mask_dict({"user": {"id": "7", "name": "admin"}, "u2": {"name": "x"}})
        assert masked["user"] == {"id": "7", "name": "admin"}
        email_user = MaskPIIFilter()._mask_dict({"user": {"name": "jane@example.com"}})
        assert email_user == {"user": {"name": "[EMAIL-MASKED]"}}


class TestLinearTime:
    @pytest.mark.parametrize(
        "text",
        ["key" * 1666, "token" * 4000, "a-" * 10000 + "token=x"],
        ids=["key_x1666", "token_x4000", "dash_run_then_token"],
    )
    def test_pathological_credential_input_is_fast(self, text):
        rules = rules_for(frozenset({"default"}))
        started = time.perf_counter()
        mask_by_patterns(text, rules)
        assert time.perf_counter() - started < 0.25


class TestUnicodeCaseFolding:
    @pytest.mark.parametrize("text", ["paſſword=hunter2", "authorızation: abc12345", "payment_İD=abc12345xyz"])
    def test_gated_masking_equals_the_plain_rules(self, text):
        for rule in rules_for(ALL_PACKS):
            assert mask_by_patterns(text, (rule,)) == rule.pattern.sub(rule.repl, text), rule.name


class TestProcessorOnly:
    def test_free_text_event_fields_are_masked_but_bounded_ones_left_alone(self):
        from ecsctx.processors import mask_sensitive_data

        out = mask_sensitive_data(
            None,
            "info",
            {"event.action": "payment.declined", "event.outcome": "failure", "event.reason": "for a@b.co"},
        )
        assert out == {"event.action": "payment.declined", "event.outcome": "failure", "event.reason": "for [EMAIL-MASKED]"}


class TestSecondPassIsReal:
    """Masking is not idempotent: masking the CVV-shaped group after a PAN on
    the first pass frees the PAN for the card rule on the second. The
    formatter's pass must really rescan what the filter produced."""

    def test_the_formatter_pass_masks_what_the_filter_pass_uncovered(self):
        masking_filter = MaskPIIFilter(packs=("pci",))
        once = masking_filter._mask_string("pan 4111111111111111 1225")
        assert masking_filter._mask_string(once) == "pan 411111******1111 [CVV-MASKED]"

    def test_a_partly_masked_string_seen_before_is_not_trusted(self):
        masking_filter = MaskPIIFilter(packs=("pci",))
        masking_filter._mask_string("pan 4111111111111111 1225")
        assert "4111111111111111" not in masking_filter._mask_string("pan 4111111111111111 [CVV-MASKED]")


class TestNumbersInStructuredFields:
    def test_a_decimal_field_renders_as_its_text(self):
        assert MaskPIIFilter()._mask_dict({"amount": Decimal("100.000")}) == {"amount": "100.000"}

    def test_a_decimal_arg_holding_a_pan_is_masked(self):
        record = _filter("ref %s", (Decimal("4111111111111111"),), packs=("pci",))
        assert record.getMessage() == "ref 411111******1111"


class TestMoreLinearTime:
    @pytest.mark.parametrize(
        "text",
        ["a-" * 10000 + " a@b.co", "é" + "a-" * 20000 + "token=x"],
        ids=["long_run_then_email", "non_ascii_long_run_then_token"],
    )
    def test_pathological_input_is_fast(self, text):
        rules = rules_for(ALL_PACKS)
        started = time.perf_counter()
        mask_by_patterns(text, rules)
        assert time.perf_counter() - started < 0.25


class TestMarkersAndSettings:
    def test_a_card_key_holding_a_fake_marker_with_a_pan_is_masked(self):
        # A full PAN dressed as a marker is not a truncation: the shape is
        # checked, not believed, so the PAN inside is truncated like any other.
        for fake in ("[CARD-MASKED:4111111111111111]", "[X-MASKED:4111111111111111 exp 1225]"):
            out = mask_card_value(fake)
            assert "4111111111111111" not in out
            assert "411111******1111" in out

    @pytest.mark.parametrize("value", [True, 1, ["pci", 1]])
    def test_a_non_string_pack_setting_fails_closed(self, settings, value):
        from ecsctx.masking.config import masking_pack_errors

        settings.ECSCTX_MASKING_PACKS = value
        assert get_masking_packs() == ALL_PACKS
        assert masking_pack_errors() != []


class TestFixedPoint:
    def test_the_filter_pass_alone_masks_to_a_fixed_point(self):
        # What Sentry's logging integration reads is the record the filter
        # masked; it must not need the formatter's pass to be complete.
        record = _filter("charge pan 4111111111111111 0827 ok", packs=("pci",))
        assert record.msg == "charge pan 411111******1111 [CVV-MASKED] ok"


class TestGatewayBodiesAreNotLogRecords:
    def test_a_name_in_a_gateway_body_is_masked(self):
        # user.name is exempt from the name rule in a log record (a login, for
        # audit trails); a gateway body's "user.name" is a person's name.
        from ecsctx.contrib.net import loggable_request_body

        logged = loggable_request_body(None, {"user": {"name": "Jane Doe"}})
        assert "Jane Doe" not in logged
