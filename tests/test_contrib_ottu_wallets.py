"""Ottu's wallet tokens in logs (#159487, decided 2026-10-01).

Apple Pay and Google Pay tokens ship exactly as sent: a token is
single-use, and the token as it was sent is what debugs a wallet payment.
Saved-card tokens stay masked.

- `WALLET_RULES` are keep rules: a token they match is left as sent under any
  key -- `paymentData`, TAP's `token_data`, MPGS's `paymentToken` (a JSON
  string), Google Pay's `tokenizationData.token`, KPay's `<udf9>` -- and in a
  message or a body, and no rule reads into it. The matchers are strict: a
  token with a key no wallet writes is walked as before.
- `WALLET_SAD_RULES` are 0.16.0's label rules: the token's payment data is
  `[SAD-MASKED]`, for a service that must not log it.

The shapes are Ottu's, not ecsctx's: value rules a service lists in
ECSCTX_MASK_VALUE_RULES. With nothing configured core keeps and labels no
wallet token. Every test runs with a keyset and without one, in the default
pack and with every pack.
"""

import json
import logging

import pytest

from ecsctx.contrib.net import configure_redaction, loggable_request_body, redact_body
from ecsctx.contrib.ottu.masking import (
    APPLE_PAY_KEEP_RULE,
    APPLE_PAY_RULE,
    APPLE_PAY_TOKEN_KEEP_RULE,
    GOOGLE_PAY_KEEP_RULE,
    GOOGLE_PAY_RULE,
    WALLET_RULES,
    WALLET_SAD_RULES,
)
from ecsctx.masking import is_kept, patterns
from ecsctx.masking.config import configure_masking_packs, configure_masking_value_rules
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS, mask_by_patterns, rules_for
from ecsctx.masking.value_rules import is_keep_rule
from ecsctx.pii import configure_pii
from ecsctx.processors import mask_sensitive_data

SAD = "[SAD-MASKED]"

APPLE_PAY = {
    "data": "ZGF0YWJsb2JkYXRhYmxvYg==",
    "signature": "c2lnbmF0dXJlLWJsb2I=",
    "header": {
        "publicKeyHash": "cGtoYXNo",
        "ephemeralPublicKey": "ZXBoZW1lcmFsLWtleQ==",
        "transactionId": "7134e7d22988391fa183a61a191ae14c",
    },
    "version": "EC_v1",
}
APPLE_PAY_RSA = {
    "data": "cnNhLWRhdGE=",
    "signature": "c2ln",
    "header": {"wrappedKey": "d3JhcHBlZA==", "publicKeyHash": "cGto", "transactionId": "abc"},
    "version": "RSA_v1",
}
PK_PAYMENT_TOKEN = {
    "paymentData": APPLE_PAY,
    "paymentMethod": {"displayName": "Visa 1234", "network": "Visa", "type": "debit"},
    "transactionIdentifier": "7134E7D22988391FA183A61A191AE14C",
}
GOOGLE_PAY = {
    "signature": "MEQCIGZha2Utc2lnbmF0dXJl",
    "intermediateSigningKey": {
        "signedKey": json.dumps({"keyValue": "a2V5", "keyExpiration": "1700000000000"}),
        "signatures": ["MEYCIQDmYWtl"],
    },
    "protocolVersion": "ECv2",
    "signedMessage": json.dumps({"encryptedMessage": "ZW5j", "ephemeralPublicKey": "ZXBr", "tag": "dGFn"}),
}
GOOGLE_PAY_V1 = {"signature": "MEQCIA==", "protocolVersion": "ECv1", "signedMessage": '{"encryptedMessage":"ZW5j"}'}
NOT_A_WALLET = {"amount": "10.000", "currency": "KWD"}
TOKENS = [APPLE_PAY, APPLE_PAY_RSA, PK_PAYMENT_TOKEN, GOOGLE_PAY, GOOGLE_PAY_V1]
TOKEN_IDS = ["apple-pay", "apple-pay-rsa", "pk-payment-token", "google-pay", "google-pay-v1"]

# Google Pay's PaymentData: the token is a JSON string under
# tokenizationData.token, beside the payer's own details.
GOOGLE_PAYMENT_DATA = {
    "apiVersion": 2,
    "apiVersionMinor": 0,
    "email": "jane.roe@example.com",
    "paymentMethodData": {
        "type": "CARD",
        "description": "Visa 1234",
        "info": {
            "cardNetwork": "VISA",
            "cardDetails": "1234",
            "billingAddress": {"name": "Jane Roe", "postalCode": "13001", "phoneNumber": "+96550000000"},
        },
        "tokenizationData": {"type": "PAYMENT_GATEWAY", "token": json.dumps(GOOGLE_PAY)},
    },
}
# ottu_pg's webhook sends the saved card under `token`.
SAVED_CARD = {
    "token": "tok_saved_card_fake_0001",
    "brand": "VISA",
    "number": "4111111111111111",
    "expiry_month": "12",
    "expiry_year": "27",
    "pg_code": "mpgs",
}
KPAY_BODY = (
    "<request><id>TRANPORTAL123</id><password>S3cretPassw0rd</password><action>1</action>"
    "<amt>10.000</amt><trackid>TRK1</trackid><udf9>{}</udf9></request>"
)
PASSWORD = "password=s3cret-Hunter2"
# A token written so that what parses is not what ships: a duplicate key
# json.loads drops, a comment ast.literal_eval drops (review C1).
DUP_DATA = (
    '{"version":"EC_v1","data":"4111111111111111","data":"Zm9v","signature":"c2ln",'
    '"header":{"transactionId":"abc"}}'
)
DUP_HEADER = (
    '{"version":"EC_v1","data":"Zm9v","signature":"c2ln",'
    '"header":{"cvv":"123"},"header":{"transactionId":"abc"}}'
)
NESTED_DUP = {
    "signature": "MEQC",
    "protocolVersion": "ECv2",
    "signedMessage": '{"encryptedMessage": {"cvv": "123", "number": "4111111111111111"}, "encryptedMessage": "ZW5j"}',
}
REPR_COMMENT = "{'version': 'EC_v1', 'data': 'Zm9v', 'header': {'transactionId': 'abc' # 4111111111111111 cvv=123\n}}"

PACKS = [["default"], sorted(ALL_PACKS)]


@pytest.fixture(autouse=True, params=["keyset", "no-keyset"])
def mode(request, token_keyset_path):
    if request.param == "keyset":
        configure_pii(token_keyset_path=token_keyset_path, env="test")
    return request.param


@pytest.fixture(autouse=True, params=PACKS, ids=["default", "every-pack"])
def packs(request):
    configure_masking_packs(request.param)
    return frozenset(request.param)


@pytest.fixture(autouse=True)
def wallet_rules():
    configure_masking_value_rules(WALLET_RULES)


def _walk(event: dict) -> dict:
    return mask_sensitive_data(None, "info", json.loads(json.dumps(event)))


def _text(text: str, packs: frozenset[str]) -> str:
    return mask_by_patterns(text, rules_for(packs | {"default"}))


def _message(msg: str, *args) -> str:
    record = logging.LogRecord("t", logging.INFO, __file__, 0, msg, args, None)
    MaskPIIFilter().filter(record)
    return record.getMessage()


def _unconfigured(mask):
    """What ``mask()`` gives with no value rule, as before WALLET_RULES."""
    configure_masking_value_rules(())
    try:
        return mask()
    finally:
        configure_masking_value_rules(WALLET_RULES)


def _holds_no_wallet_data(text: str) -> None:
    for secret in ("ZGF0YWJsb2JkYXRhYmxvYg==", "c2lnbmF0dXJlLWJsb2I=", "ZXBoZW1lcmFsLWtleQ==", "MEQCIGZha2Utc2lnbmF0dXJl"):
        assert secret not in text


class TestTheRules:
    def test_wallet_rules_are_the_keep_rules(self):
        assert WALLET_RULES == (APPLE_PAY_TOKEN_KEEP_RULE, APPLE_PAY_KEEP_RULE, GOOGLE_PAY_KEEP_RULE)
        assert all(is_keep_rule(rule) for rule in WALLET_RULES)

    def test_wallet_sad_rules_are_0_16_0s(self):
        assert WALLET_SAD_RULES == (APPLE_PAY_RULE, GOOGLE_PAY_RULE)
        assert {rule.field_type for rule in WALLET_SAD_RULES} == {"sad"}

    @pytest.mark.parametrize("token", TOKENS, ids=TOKEN_IDS)
    def test_each_token_is_kept(self, token):
        assert is_kept(token)
        assert is_kept(json.dumps(token))

    @pytest.mark.parametrize(
        "value",
        [
            {**APPLE_PAY, "extra": "x"},
            {**APPLE_PAY, "version": "EC_v2"},
            {**APPLE_PAY, "data": {"blob": "x"}},
            {**APPLE_PAY, "header": {**APPLE_PAY["header"], "extra": "x"}},
            {**APPLE_PAY, "header": {**APPLE_PAY["header"], "publicKeyHash": 1}},
            {**APPLE_PAY, "header": "cGto"},
            {key: value for key, value in APPLE_PAY.items() if key != "data"},
            {**PK_PAYMENT_TOKEN, "billingContact": {"givenName": "Jane"}},
            {**PK_PAYMENT_TOKEN, "paymentMethod": {**PK_PAYMENT_TOKEN["paymentMethod"], "billingAddress": "x"}},
            {**PK_PAYMENT_TOKEN, "paymentData": NOT_A_WALLET},
            {**GOOGLE_PAY, "extra": "x"},
            {**GOOGLE_PAY, "protocolVersion": "v3"},
            {**GOOGLE_PAY, "intermediateSigningKey": {**GOOGLE_PAY["intermediateSigningKey"], "x": 1}},
            {key: value for key, value in GOOGLE_PAY.items() if key != "signedMessage"},
            NOT_A_WALLET,
        ],
        ids=[
            "apple-extra-key", "apple-version", "apple-data-not-text", "apple-header-extra-key",
            "apple-header-not-text", "apple-header-not-a-mapping", "apple-no-data", "pk-extra-key",
            "pk-payment-method-extra-key", "pk-no-wallet", "google-extra-key", "google-version",
            "google-signing-key-extra-key", "google-no-signed-message", "not-a-wallet",
        ],
    )
    def test_the_matchers_are_strict(self, value):
        assert not is_kept(value)


class TestWalletTokensShipAsSent:
    @pytest.mark.parametrize("token", TOKENS, ids=TOKEN_IDS)
    def test_under_token(self, token):
        assert _walk({"token": token}) == {"token": token}

    def test_under_payload_content(self):
        event = {"payload": {"content": PK_PAYMENT_TOKEN, "amount": "10.000"}}
        assert _walk(event) == event

    @pytest.mark.parametrize("key", ["paymentData", "token_data", "apple_pay", "payload", "udf9", "token", "card"])
    @pytest.mark.parametrize("token", [APPLE_PAY, APPLE_PAY_RSA], ids=["ec", "rsa"])
    def test_payment_data_under_any_key(self, key, token):
        assert _walk({key: token}) == {key: token}

    @pytest.mark.parametrize("key", ["token", "paymentToken", "payload", "note"])
    @pytest.mark.parametrize("token", TOKENS, ids=TOKEN_IDS)
    def test_the_token_as_json_text(self, key, token):
        text = json.dumps(token)
        assert _walk({key: text}) == {key: text}

    def test_google_pay_under_tokenization_data_the_rest_masked_as_before(self):
        before = _unconfigured(lambda: _walk({"google_pay_payload": GOOGLE_PAYMENT_DATA}))
        after = _walk({"google_pay_payload": GOOGLE_PAYMENT_DATA})
        tokenized = after["google_pay_payload"]["paymentMethodData"]["tokenizationData"]
        assert tokenized["token"] == json.dumps(GOOGLE_PAY)
        assert before["google_pay_payload"]["paymentMethodData"]["tokenizationData"]["token"] != tokenized["token"]
        before["google_pay_payload"]["paymentMethodData"]["tokenizationData"]["token"] = tokenized["token"]
        assert after == before
        assert after["google_pay_payload"]["email"] != "jane.roe@example.com"

    def test_the_mpgs_device_payment_body(self):
        body = {
            "apiOperation": "PAY",
            "sourceOfFunds": {
                "type": "CARD",
                "provided": {"card": {"devicePayment": {"paymentToken": json.dumps(PK_PAYMENT_TOKEN)}}},
            },
            "order": {"amount": "10.000", "currency": "KWD", "walletProvider": "APPLE_PAY"},
        }
        assert _walk({"payload": body}) == {"payload": body}
        assert json.loads(loggable_request_body(None, body)) == body

    @pytest.mark.parametrize("token", TOKENS, ids=TOKEN_IDS)
    def test_a_message_and_a_repr(self, token, packs):
        for written in (json.dumps(token), repr(token)):
            text = f"apple pay token {written} received, {PASSWORD}"
            masked = _text(text, packs)
            assert written in masked
            assert "s3cret-Hunter2" not in masked
            assert _text(masked, packs) == masked
        assert _message("token %s", json.dumps(token)) == f"token {json.dumps(token)}"
        assert _message("token %r", token) == f"token {token!r}"
        assert _walk({"event": f"got {json.dumps(token)}"}) == {"event": f"got {json.dumps(token)}"}

    @pytest.mark.parametrize("token", [APPLE_PAY, PK_PAYMENT_TOKEN], ids=["payment-data", "pk-payment-token"])
    def test_kpay_udf9_through_redact_body_and_the_processor(self, token, packs):
        written = json.dumps(token)
        body = KPAY_BODY.format(written)
        for masked in (redact_body(body), _walk({"http": {"body": body}})["http"]["body"]):
            assert f"<udf9>{written}</udf9>" in masked
            assert '"transactionId": "7134e7d22988391fa183a61a191ae14c"' in masked
            assert "S3cretPassw0rd" not in masked

    @pytest.mark.parametrize("token", TOKENS, ids=TOKEN_IDS)
    def test_entity_encoded_and_with_connects_extra_secret_keys(self, token):
        configure_redaction(extra_secret_keys=["signature", "hash"])
        plain = json.dumps(token)
        for written in (plain, plain.replace('"', "&quot;")):
            masked = redact_body(KPAY_BODY.format(written))
            assert f"<udf9>{written}</udf9>" in masked
            assert "S3cretPassw0rd" not in masked
        masked = json.loads(redact_body(json.dumps({"paymentToken": plain, "signature": "outer-signature"})))
        assert masked["paymentToken"] == plain
        assert masked["signature"] != "outer-signature"

    def test_a_cvv_beside_it_is_still_masked(self):
        masked = _walk({"payload": {"paymentData": APPLE_PAY, "cvv": "123"}})
        assert masked == {"payload": {"paymentData": APPLE_PAY, "cvv": "[CVV-MASKED]"}}

    @pytest.mark.parametrize("written", ["mapping", "json-text"])
    def test_nothing_under_a_cvv_key_is_kept(self, written, packs):
        token = APPLE_PAY if written == "mapping" else json.dumps(APPLE_PAY)
        _holds_no_wallet_data(json.dumps(_walk({"cvv": token})))
        _holds_no_wallet_data(redact_body(f"<cvv>{json.dumps(APPLE_PAY)}</cvv>"))
        _holds_no_wallet_data(_text(f"<cvv>{json.dumps(APPLE_PAY)}</cvv>", packs))
        if "financial_ids" in packs:
            # Not kept, so the payment-id rule reads its transactionId; the
            # default pack has no rule for an object after a CVV key in text.
            text = f'{{"securityCode": {json.dumps(APPLE_PAY)}}}'
            assert "7134e7d22988391fa183a61a191ae14c" not in _text(text, packs)

    @pytest.mark.parametrize("written", [DUP_DATA, DUP_HEADER], ids=["duplicate-data", "duplicate-header"])
    def test_a_token_with_a_duplicate_key_is_masked_as_without_the_rules(self, written, packs):
        def every_path():
            return (
                _message("body %s", written),
                _message(written),
                _walk({"payload": written}),
                _walk({"paymentToken": written}),
                _text(f"token {written} end", packs),
                redact_body(f'{{"token": {written}, "amt": "1"}}'),
                redact_body(json.dumps({"paymentToken": written})),
            )

        assert every_path() == _unconfigured(every_path)
        assert not is_kept(written)

    def test_a_json_text_leaf_with_a_duplicate_key_is_card_data(self, packs):
        assert _walk({"payload": NESTED_DUP}) == _unconfigured(lambda: _walk({"payload": NESTED_DUP}))
        assert not is_kept(NESTED_DUP)
        text = f"got {json.dumps(NESTED_DUP)}"
        assert _text(text, packs) == _unconfigured(lambda: _text(text, packs))

    def test_a_repr_with_a_comment_is_not_kept(self, packs):
        text = f"got {REPR_COMMENT} end"
        masked = _text(text, packs)
        assert masked == _unconfigured(lambda: _text(text, packs))
        assert "cvv=123" not in masked

    def test_a_payment_data_that_is_no_wallet_is_masked_as_usual(self):
        masked = _walk({"paymentData": {"cardNumber": "4111111111111111", "email": "jane.roe@example.com"}})
        assert masked["paymentData"]["cardNumber"] == "411111******1111"
        assert masked["paymentData"]["email"] != "jane.roe@example.com"

    def test_a_token_with_extra_keys_is_not_kept_whole(self):
        wrapper = {**PK_PAYMENT_TOKEN, "cardholderName": "Jane Roe"}
        masked = _walk({"token": wrapper})["token"]
        assert masked["paymentData"] == APPLE_PAY
        assert masked["cardholderName"] != "Jane Roe"

    @pytest.mark.parametrize("saved", ["tok_saved_card_fake_0001", SAVED_CARD], ids=["string", "card-object"])
    def test_saved_card_tokens_stay_masked(self, saved):
        before = _unconfigured(lambda: _walk({"token": saved}))
        assert before != {"token": saved}
        assert _walk({"token": saved}) == before
        assert "4111111111111111" not in json.dumps(before)


class TestTheSadVariant:
    """0.16.0's assertions, with WALLET_SAD_RULES."""

    @pytest.fixture(autouse=True)
    def wallet_rules(self):
        configure_masking_value_rules(WALLET_SAD_RULES)

    @pytest.mark.parametrize("key", ["paymentData", "token_data", "apple_pay", "payload", "udf9", "token", "card"])
    def test_an_apple_pay_token_under_any_key_is_the_label(self, key):
        assert _walk({key: APPLE_PAY}) == {key: SAD}

    def test_the_rsa_version_too(self):
        assert _walk({"paymentData": APPLE_PAY_RSA}) == {"paymentData": SAD}

    def test_a_pk_payment_token_keeps_what_is_not_the_payment_data(self):
        masked = _walk({"apple_pay_payload": PK_PAYMENT_TOKEN})["apple_pay_payload"]
        assert masked["paymentData"] == SAD
        assert masked["paymentMethod"] == PK_PAYMENT_TOKEN["paymentMethod"]

    @pytest.mark.parametrize("token", [GOOGLE_PAY, GOOGLE_PAY_V1])
    def test_a_google_pay_token_object_is_the_label(self, token):
        assert _walk({"google_pay": token}) == {"google_pay": SAD}

    @pytest.mark.parametrize("key", ["token", "paymentToken", "payload"])
    @pytest.mark.parametrize("token", [APPLE_PAY, GOOGLE_PAY])
    def test_a_token_as_a_json_string_is_the_label(self, key, token):
        assert _walk({key: json.dumps(token)}) == {key: SAD}

    def test_the_mpgs_device_payment_body(self):
        body = {
            "sourceOfFunds": {"provided": {"card": {"devicePayment": {"paymentToken": json.dumps(APPLE_PAY)}}}},
            "order": {"amount": "10.000", "currency": "KWD"},
        }
        masked = _walk({"payload": body})["payload"]
        assert masked["sourceOfFunds"]["provided"]["card"]["devicePayment"]["paymentToken"] == SAD
        assert masked["order"] == body["order"]

    def test_the_google_pay_payment_data(self):
        payment_data = {
            "apiVersion": 2,
            "paymentMethodData": {
                "type": "CARD",
                "description": "Visa 1234",
                "tokenizationData": {"type": "PAYMENT_GATEWAY", "token": json.dumps(GOOGLE_PAY)},
            },
        }
        masked = _walk({"google_pay_payload": payment_data})["google_pay_payload"]
        assert masked["paymentMethodData"]["tokenizationData"] == {"type": "PAYMENT_GATEWAY", "token": SAD}
        assert masked["paymentMethodData"]["description"] == "Visa 1234"

    def test_a_token_in_a_list(self):
        assert _walk({"tokens": [APPLE_PAY, json.dumps(GOOGLE_PAY)]}) == {"tokens": [SAD, SAD]}

    def test_a_wrapper_as_a_string_under_a_credential_key_is_the_label(self):
        assert _walk({"token": json.dumps(PK_PAYMENT_TOKEN)}) == {"token": SAD}

    def test_a_wrapper_as_a_string_under_any_other_key_keeps_its_shape(self):
        masked = json.loads(_walk({"body": json.dumps(PK_PAYMENT_TOKEN)})["body"])
        assert masked["paymentData"] == SAD
        assert masked["paymentMethod"] == PK_PAYMENT_TOKEN["paymentMethod"]

    @pytest.mark.parametrize(
        "value",
        [
            NOT_A_WALLET,
            {"version": "EC_v1", "header": {"publicKeyHash": "cGto"}},
            {"version": "2", "data": "abc"},
            {"protocolVersion": "ECv2"},
            {"protocolVersion": "v3", "signedMessage": "x"},
        ],
    )
    def test_anything_else_under_payment_data_is_read_as_before(self, value):
        assert _walk({"paymentData": value}) == {"paymentData": value}

    def test_a_record_with_args(self):
        assert _message("apple pay token %s", json.dumps(APPLE_PAY)) == f"apple pay token {SAD}"
        assert _message("token %(t)s", {"t": APPLE_PAY}) == f"token {SAD}"

    @pytest.mark.parametrize("token", [APPLE_PAY, APPLE_PAY_RSA, GOOGLE_PAY, GOOGLE_PAY_V1])
    def test_a_token_in_a_message_is_the_label(self, token, packs):
        assert _text(f"apple pay token {json.dumps(token)} received", packs) == f"apple pay token {SAD} received"

    def test_compact_json_and_a_python_repr_too(self, packs):
        compact = json.dumps(APPLE_PAY, separators=(",", ":"))
        assert _text(f"token={compact}", packs) == f"token={SAD}"
        assert _text(f"token {APPLE_PAY!r}", packs) == f"token {SAD}"

    def test_in_json_text_the_label_is_a_json_string(self, packs):
        text = "sent " + json.dumps({"paymentData": APPLE_PAY, "amount": "10.000"})
        masked = _text(text, packs)
        assert masked == 'sent {"paymentData": "[SAD-MASKED]", "amount": "10.000"}'
        assert json.loads(masked[5:])

    def test_a_token_as_a_json_string_in_json_text(self, packs):
        text = "sent " + json.dumps({"paymentToken": json.dumps(GOOGLE_PAY), "amount": "10.000"})
        masked = _text(text, packs)
        assert masked == 'sent {"paymentToken": "[SAD-MASKED]", "amount": "10.000"}'

    def test_a_message_that_is_json(self):
        masked = _walk({"event": json.dumps({"paymentData": APPLE_PAY})})["event"]
        assert json.loads(masked) == {"paymentData": SAD}

    def test_the_processor_masks_it_in_any_string(self):
        event = {"event": f"apple pay token {json.dumps(APPLE_PAY)}", "note": json.dumps(GOOGLE_PAY)}
        assert _walk(event) == {"event": f"apple pay token {SAD}", "note": SAD}

    def test_an_unrelated_payment_data_stays_readable(self, packs):
        text = "paymentData " + json.dumps({"paymentData": NOT_A_WALLET})
        assert _text(text, packs) == text

    def test_masking_twice_masks_once(self, packs):
        once = _text(f"token {json.dumps(PK_PAYMENT_TOKEN)}", packs)
        _holds_no_wallet_data(once)
        assert "ptok:v1:" not in once
        assert _text(once, packs) == once

    def test_redact_body(self):
        masked = redact_body(json.dumps({"paymentData": APPLE_PAY, "amount": "10.000"}))
        assert json.loads(masked) == {"paymentData": SAD, "amount": "10.000"}
        assert redact_body(masked) == masked

    def test_redact_body_on_a_token_as_a_json_string(self):
        masked = redact_body(json.dumps({"paymentToken": json.dumps(APPLE_PAY)}))
        assert json.loads(masked) == {"paymentToken": SAD}

    def test_loggable_request_body(self):
        masked = loggable_request_body(None, {"paymentToken": json.dumps(GOOGLE_PAY), "amount": "10.000"})
        assert json.loads(masked) == {"paymentToken": SAD, "amount": "10.000"}

    def test_kpay_udf9_through_redact_body_and_the_processor(self, packs):
        body = KPAY_BODY.format(json.dumps(PK_PAYMENT_TOKEN))
        for masked in (redact_body(body), _walk({"http": {"body": body}})["http"]["body"]):
            _holds_no_wallet_data(masked)
            udf9 = masked.split("<udf9>")[1].split("</udf9>")[0]
            assert json.loads(udf9)["paymentData"] == SAD
            assert json.loads(udf9)["paymentMethod"] == PK_PAYMENT_TOKEN["paymentMethod"]

    def test_kpay_udf9_holding_the_payment_data_itself(self):
        body = f"<udf8>7134E7D2</udf8><udf9>{json.dumps(APPLE_PAY)}</udf9><amt>10.000</amt>"
        expected = f"<udf8>7134E7D2</udf8><udf9>{SAD}</udf9><amt>10.000</amt>"
        assert redact_body(body) == expected
        assert _walk({"body": body})["body"] == expected

    def test_an_entity_encoded_token_in_an_element(self):
        encoded = json.dumps(APPLE_PAY).replace('"', "&quot;")
        assert redact_body(f"<udf9>{encoded}</udf9>") == f"<udf9>{SAD}</udf9>"

    def test_a_credential_element_holding_a_token_is_the_label_not_its_hash(self):
        assert redact_body(f"<password>{json.dumps(APPLE_PAY)}</password>") == f"<password>{SAD}</password>"

    def test_the_span_finder_never_runs(self, monkeypatch, packs):
        calls: list = []
        monkeypatch.setattr(patterns, "kept_spans", lambda *args: calls.append(args) or [])
        text = f"apple pay token {json.dumps(PK_PAYMENT_TOKEN)} {json.dumps(GOOGLE_PAY)}"
        _text(text, packs)
        _message(text)
        redact_body(KPAY_BODY.format(text))
        _walk({"event": text, "token": PK_PAYMENT_TOKEN, "note": json.dumps(GOOGLE_PAY)})
        assert calls == []


class TestNothingConfigured:
    """Core names no wallet shape: without Ottu's rules in
    ECSCTX_MASK_VALUE_RULES, a wallet token is neither kept nor labelled --
    the opt-in is explicit."""

    @pytest.fixture(autouse=True)
    def no_value_rules(self, wallet_rules):
        configure_masking_value_rules(())

    def test_a_token_is_not_labelled_by_core(self, packs):
        assert _walk({"paymentData": APPLE_PAY}) != {"paymentData": SAD}
        assert SAD not in _text(f"apple pay token {json.dumps(APPLE_PAY)} received", packs)
        assert SAD not in redact_body(json.dumps({"paymentData": APPLE_PAY}))
        assert SAD not in _walk({"google_pay": json.dumps(GOOGLE_PAY)})["google_pay"]

    def test_a_token_is_not_kept_by_core(self):
        assert _walk({"paymentData": APPLE_PAY}) != {"paymentData": APPLE_PAY}
        assert not is_kept(APPLE_PAY)

    def test_the_setting_opts_in(self):
        configure_masking_value_rules(["ecsctx.contrib.ottu.masking.WALLET_RULES"])
        assert _walk({"paymentData": APPLE_PAY}) == {"paymentData": APPLE_PAY}
        configure_masking_value_rules(["ecsctx.contrib.ottu.masking.WALLET_SAD_RULES"])
        assert _walk({"paymentData": APPLE_PAY}) == {"paymentData": SAD}
