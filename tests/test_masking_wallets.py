"""A wallet token's payment data is `[SAD-MASKED]` in every pack (#160054).

An Apple Pay or Google Pay token carries the device card number and the
payment cryptogram, encrypted. It is never hashed: the whole token is the SAD
label, as a cryptogram under its own key is. It is found by its shape, not by
a key name, so an unrelated `paymentData` stays readable and the token is
masked under any key -- `paymentData`, TAP's `token_data`, MPGS's
`paymentToken` (a JSON string), Google Pay's `tokenizationData.token`, KPay's
`<udf9>`.

- Apple Pay (PKPaymentToken's `paymentData`): an object whose `version` is
  `EC_v1` or `RSA_v1`, with the encrypted `data`. `signature` and `header`
  are useless without it, so the whole object is the label.
- Google Pay (the payment method token): an object, or a JSON string, whose
  `protocolVersion` is `ECv1`, `ECv2` or `ECv2SigningOnly`, with a
  `signedMessage`.

Every test runs with a keyset and without one.
"""

import json
import logging

import pytest

from ecsctx.contrib.net import loggable_request_body, redact_body
from ecsctx.masking.config import configure_masking_packs
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS, mask_by_patterns, rules_for
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


def _walk(event: dict) -> dict:
    return mask_sensitive_data(None, "info", json.loads(json.dumps(event)))


def _text(text: str, packs: frozenset[str]) -> str:
    return mask_by_patterns(text, rules_for(packs | {"default"}))


def _message(msg: str, *args) -> str:
    record = logging.LogRecord("t", logging.INFO, __file__, 0, msg, args, None)
    MaskPIIFilter().filter(record)
    return record.getMessage()


def _holds_no_wallet_data(text: str) -> None:
    for secret in ("ZGF0YWJsb2JkYXRhYmxvYg==", "c2lnbmF0dXJlLWJsb2I=", "ZXBoZW1lcmFsLWtleQ==", "MEQCIGZha2Utc2lnbmF0dXJl"):
        assert secret not in text


class TestTheKeyWalk:
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
        # MPGS's paymentToken, Google Pay's tokenizationData.token: a JSON
        # string under a credential key was hashed.
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
        # Never hashed, even with the token inside something else.
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


class TestText:
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


class TestBodies:
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
        body = (
            "<request><id>TRANPORTAL123</id><password>S3cretPassw0rd</password><action>1</action>"
            f"<amt>10.000</amt><trackid>TRK1</trackid><udf9>{json.dumps(PK_PAYMENT_TOKEN)}</udf9></request>"
        )
        for masked in (redact_body(body), _walk({"http": {"body": body}})["http"]["body"]):
            _holds_no_wallet_data(masked)
            udf9 = masked.split("<udf9>")[1].split("</udf9>")[0]
            assert json.loads(udf9)["paymentData"] == SAD
            assert json.loads(udf9)["paymentMethod"] == PK_PAYMENT_TOKEN["paymentMethod"]

    def test_kpay_udf9_holding_the_payment_data_itself(self):
        # What KPay's client sends: udf9 is the paymentData object, unwrapped.
        body = f"<udf8>7134E7D2</udf8><udf9>{json.dumps(APPLE_PAY)}</udf9><amt>10.000</amt>"
        expected = f"<udf8>7134E7D2</udf8><udf9>{SAD}</udf9><amt>10.000</amt>"
        assert redact_body(body) == expected
        assert _walk({"body": body})["body"] == expected

    def test_an_entity_encoded_token_in_an_element(self):
        encoded = json.dumps(APPLE_PAY).replace('"', "&quot;")
        assert redact_body(f"<udf9>{encoded}</udf9>") == f"<udf9>{SAD}</udf9>"

    def test_a_credential_element_holding_a_token_is_the_label_not_its_hash(self):
        assert redact_body(f"<password>{json.dumps(APPLE_PAY)}</password>") == f"<password>{SAD}</password>"
