"""Masking's output on a fixed corpus, byte for byte (#160054).

0.15.5 made a rich event mask 1.4-1.7x slower than 0.15.4. The work that
won the time back must not change a single output, so this corpus -- the
suite's own tables, the benchmarks' inputs and seeded fragments -- was run
through every masking path, in the default pack and with every pack, with a
fixed keyset and without one, before that work began, and its outputs were
written to golden/masking_0156.json. Every run compares against them.

To capture them again, deliberately, when an output is meant to change:
`ECSCTX_WRITE_GOLDEN=1 pytest tests/test_masking_golden.py`.
"""

import base64
import importlib.util
import json
import logging
import os
import random
from pathlib import Path

from ecsctx.contrib.net import redact_body
from ecsctx.contrib.ottu.masking import WALLET_RULES
from ecsctx.masking.config import configure_masking_packs, configure_masking_value_rules
from ecsctx.masking.filters import MaskPIIFilter, _Pass
from ecsctx.masking.patterns import (
    ALL_PACKS,
    Rule,
    mask_by_patterns,
    rules_for,
    scalar_rules,
)
from ecsctx.pii import _reset as _reset_pii
from ecsctx.pii import configure_pii
from ecsctx.processors import mask_sensitive_data
from tests import (
    test_contrib_ottu_wallets,
    test_masking_cvv_bare,
    test_masking_filter,
    test_masking_secrets,
)
from tests.test_masking_xml_bodies import KPAY_BODIES

GOLDEN = Path(__file__).parent / "golden" / "masking_0156.json"
PACKS = {"default": frozenset({"default"}), "every-pack": ALL_PACKS}

# The benchmark's inputs (bench_mask.py, scratchpad of #160054).
BENCH_BODY = json.dumps(
    {
        "session_id": "21a2496f8b6c193ec61b8dd52cbe8d827b4eaa49",
        "order_no": "ORD-2026-000123",
        "amount": "12.500",
        "currency_code": "KWD",
        "customer_email": "jane.roe@example.com",
        "customer_phone": "+96550000000",
        "customer_first_name": "Jane",
        "billing_address": {"line1": "Block 1, Street 2", "city": "Kuwait City", "country": "KW"},
        "pg_codes": ["mpgs-direct", "cs-direct", "kpay"],
        "redirect_url": "https://merchant.example/return?ref=abc123&lang=en",
        "webhook_url": "https://merchant.example/hooks/ottu",
        "extra": {"note": "gift wrap", "items": [{"sku": f"SKU-{i}", "qty": i} for i in range(10)]},
        "card_acceptance_criteria": {"min_expiry_time": 30},
        "three_ds": {"directory_server_transaction_id": "3d85c5d3-8412-4f1d-9e26-4a0f00123456"},
    }
)
BENCH_EVENT = {
    "event": "api request received: POST /b/checkout/v1/pymt-txn/",
    "payload": json.loads(BENCH_BODY),
    "http": {
        "request": {
            "body": BENCH_BODY,
            "headers": {"authorization": "Api-Key abcDEF123.456ghiJKL", "user-agent": "Mozilla/5.0"},
        }
    },
    "url": {"full": "https://jade.ottu.dev/b/checkout/v1/pymt-txn/?utm=1"},
}
BENCH_TEXT = (
    "gateway replied 200 for session 21a2496f8b6c193ec61b8dd52cbe8d827b4eaa49 order ORD-2026-000123 "
    "amount 12.500 KWD at https://ap-gateway.mastercard.com/api/rest/version/100/merchant/TEST123/order/77 "
    "trace 0ca2002f-f3f9-4985-ba8f-eb80e08f37b5 took 1234 ms; result=SUCCESS gatewayCode=APPROVED "
) * 8

# Seeded fragments: shapes no table holds, the same on every run.
FRAGMENTS = (
    "password=", "token=", '"token": "', "Bearer ", "Authorization: ", "cvv=", "cvv ", "the cvv is ", "<password>",
    "</password>", "<udf9>", "</udf9>", "<cvv>", "</cvv>", "&quot;", "&amp;", "4111111111111111", "411111******1111",
    "12/27", "123", "1234", "200", "350 ms", "s3cr3t", "abc123", "jane@example.com", "+96550000000", "https://u:p@h/",
    "https://4111111111111111@h.example/", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", "GB33BUKB20201555555555",
    "123-45-6789", "payment_id=abc12345", "[SECRET-MASKED]", "ptok:v1:" + "A" * 43, " ", "|", ",", ":", "'", '"', "{",
    "}", "[", "]", "(", ")", "\\", "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----",
    json.dumps(test_contrib_ottu_wallets.APPLE_PAY), json.dumps(json.dumps(test_contrib_ottu_wallets.GOOGLE_PAY)),
)


def _bench_fixtures() -> list[dict]:
    path = Path(__file__).parent.parent / "scripts" / "bench_masking.py"
    spec = importlib.util.spec_from_file_location("_bench_masking", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return [event for event, _packs in module.FIXTURES.values()]


def _texts() -> list[str]:
    texts: list[str] = []
    for table in (
        test_masking_filter.PEM_MASKED_CASES,
        test_masking_filter.CREDENTIAL_MASKED_CASES,
        test_masking_filter.CVV_KEYWORD_CASES,
        test_masking_filter.PAYMENT_ID_QUOTE_CASES,
        test_masking_filter.IBAN_MASKED_CASES,
        test_masking_filter.PHONE_MASKED_CASES,
        test_masking_filter.EMAIL_MASKED_CASES,
        test_masking_filter.JWT_MASKED_CASES,
        test_masking_filter.CARD_NUMBER_CASES,
        test_masking_filter.SSN_MASKED_CASES,
        test_masking_filter.NOT_MASKED,
        test_masking_filter.ACCEPTED_LEAK_CASES,
    ):
        texts += [case[1] for case in table if isinstance(case[1], str)]
    texts += test_masking_secrets.PAN_SHAPES
    texts += [text for text, *_ in test_masking_secrets.USERINFO_TEXTS]
    texts += [template % "s3cr3t-Hunter2" for template in test_masking_secrets.CREDENTIAL_TEXTS]
    texts += [text for text, _masked in test_masking_cvv_bare.MUST_MASK]
    texts += test_masking_cvv_bare.MUST_NOT_MASK
    texts += [body.replace("{password}", "S3cretPassw0rd") for body in KPAY_BODIES.values()]
    texts += [BENCH_BODY, BENCH_TEXT]
    rng = random.Random(160054)
    texts += ["".join(rng.choice(FRAGMENTS) for _ in range(rng.randint(1, 10))) for _ in range(300)]
    return list(dict.fromkeys(texts))


def _events() -> list[dict]:
    events = [BENCH_EVENT, *_bench_fixtures()]
    events += [case[1] for case in test_masking_filter.DICT_KEY_VALUE_MASKING_CASES]
    events.append(
        {"payload": {"paymentData": test_contrib_ottu_wallets.APPLE_PAY, "note": json.dumps(test_contrib_ottu_wallets.GOOGLE_PAY)}}
    )
    events += [
        {"http": {"request": {"body": {"content": body.replace("{password}", "S3cretPassw0rd")}}}}
        for body in KPAY_BODIES.values()
    ]
    events += [{"event": text} for text in _texts()[:200]]
    return events


RECORDS = [
    ("user %s paid %s KWD for %s", ("bob", "12.500", "ORD-1")),
    ("cvv=%s", ("123",)),
    ("card %s %s", ("4111111111111111", "123")),
    ("password=%(pw)s", ({"pw": ["a", "b"]},)),
    ("paid %.f KWD by %d", (10.5, 5551234567)),
    ("sent to %s", ("jane@example.com",)),
    ("apple pay token %s", (json.dumps(test_contrib_ottu_wallets.APPLE_PAY),)),
    ("retried with Bearer %s", ("abc123def456",)),
    ("%s", ({"card_number": "4111111111111111", "cvv": "123"},)),
]


def _keyset(tmp: Path) -> str:
    key = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
    keyset = {
        "schema_version": 1,
        "primary_kid": "golden",
        "keys": {"golden": {"alg": "HMAC-SHA-256", "created_at": "2026-09-30T00:00:00Z", "key_b64": key}},
    }
    path = tmp / "golden-keyset.json"
    path.write_text(json.dumps(keyset))
    return str(path)


def _record(msg, args, packs) -> list:
    record = logging.LogRecord("golden", logging.INFO, __file__, 0, msg, args, None)
    MaskPIIFilter(packs=packs).filter(record)
    return [str(record.msg), repr(record.args), record.getMessage()]


def _changed(text: str, masked: str) -> str | None:
    """The output, or None where it is the text as it came."""
    return None if masked == text else masked


def _outputs(tmp: Path) -> dict:
    # As an Ottu service runs: its wallet shapes are value rules it lists,
    # no longer core's, and the corpus holds wallet tokens.
    configure_masking_value_rules(WALLET_RULES)
    texts, events = _texts(), _events()
    outputs: dict = {}
    for mode in ("no-keyset", "keyset"):
        _reset_pii()
        if mode == "keyset":
            configure_pii(token_keyset_path=_keyset(tmp), env="golden")
        outputs[f"{mode}/redact_body"] = [_changed(text, redact_body(text)) for text in texts]
        for name, packs in PACKS.items():
            configure_masking_packs(packs)
            rules = rules_for(packs)
            prose = MaskPIIFilter(packs=packs)
            masked = [mask_by_patterns(text, rules) for text in texts]
            outputs[f"{mode}/{name}/text"] = [_changed(text, out) for text, out in zip(texts, masked, strict=True)]
            # The filter's reading of a message, where it differs from the
            # rules' own (a JSON message is walked by its keys first).
            outputs[f"{mode}/{name}/prose"] = [
                _changed(out, prose._mask_value(text)) for text, out in zip(texts, masked, strict=True)
            ]
            outputs[f"{mode}/{name}/events"] = [
                mask_sensitive_data(None, "info", json.loads(json.dumps(event))) for event in events
            ]
            outputs[f"{mode}/{name}/records"] = [_record(msg, args, packs) for msg, args in RECORDS]
    _reset_pii()
    return outputs


class _NeverHashed(Rule):
    def __hash__(self):
        raise AssertionError("a rule was hashed")


def test_a_rule_set_is_cached_by_its_identity_never_hashed():
    # What 0.15.5 lost its time to: lru_cache keyed on the rule tuple hashed
    # every rule, and a compiled pattern hashes its whole program -- 30 µs a
    # string for the default pack, more than all the masking it guarded.
    rules = tuple(_NeverHashed(*rule) for rule in rules_for(ALL_PACKS))
    assert scalar_rules(rules) is scalar_rules(rules)
    assert mask_by_patterns("card 4111111111111111 123 for jane@example.com", rules) == (
        "card 411111******1111 [CVV-MASKED] for [EMAIL-MASKED]"
    )
    assert MaskPIIFilter()._mask_string("password=s3cr3t", _Pass(ALL_PACKS, rules, (), frozenset()), scalar=True)


def test_masking_outputs_are_byte_identical_to_the_golden_file(tmp_path):
    outputs = _outputs(tmp_path)
    text = json.dumps(outputs, ensure_ascii=False, indent=0, sort_keys=True, separators=(",", ":"))
    if os.environ.get("ECSCTX_WRITE_GOLDEN"):
        GOLDEN.parent.mkdir(exist_ok=True)
        GOLDEN.write_text(text + "\n", encoding="utf-8")
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    for key in sorted(golden):
        for index, expected in enumerate(golden[key]):
            assert outputs[key][index] == expected, (key, index)
    assert text + "\n" == GOLDEN.read_text(encoding="utf-8")
