"""The structural keys skip the fields ecsctx writes there, not whole subtrees.

`service`, `project`, `log`, `trace`, `span` are skipped so ecsctx's own
metadata -- `service.name` above all -- is not mistaken for data. But the skip
covered everything under them, and a caller can put anything there; the
processor even merges a caller's `service=` dict into the event. Verified in
clear against 0.13.0: `service.password`, a full PAN in `service.card_number`,
`trace.headers.Authorization`, a CVV under `log`, and a HAR document logged as
the message (its root key is `log`).

Now only the fields ecsctx owns under those keys pass untouched; everything
else is masked like any other field. A skip key a service chose itself is
still skipped whole -- that is an explicit opt-out.
"""

from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS


def mask(event):
    return MaskPIIFilter(packs=ALL_PACKS)._mask_dict(event)


def test_ecsctx_own_fields_pass_untouched():
    event = {
        "service": {"name": "connect", "version": "1.0.0", "target": {"name": "mpgs"}},
        "project": {"name": "ottu_pg"},
        "log": {"level": "info", "logger": "pg.client", "origin": {"file": {"name": "client.py", "line": 93}}},
        "trace": {"id": "4bf92f3577b34da6a3ce929d0e0e4736"},
        "span": {"id": "00f067aa0ba902b7"},
        "session_id": "b6993fb163967ffc1ef84809d6514c2404c47b70",
    }
    assert mask(event) == event


def test_what_a_caller_put_under_them_is_masked():
    masked = mask(
        {
            "service": {"name": "connect", "password": "hunter2", "card_number": "4111111111111111"},
            "trace": {"id": "4bf92f35", "headers": {"Authorization": "Bearer sk_live_1234567890abcdef"}},
            "log": {"level": "info", "postData": {"cvv": "123"}},
        }
    )
    assert masked["service"]["name"] == "connect"
    assert "hunter2" not in str(masked)
    assert masked["service"]["card_number"] == "411111******1111"
    assert "sk_live_1234567890abcdef" not in str(masked)
    assert masked["log"]["postData"]["cvv"] == "[CVV-MASKED]"
    assert masked["log"]["level"] == "info"


def test_a_har_document_logged_as_the_message_is_masked():
    har = {
        "log": {
            "version": "1.2",
            "entries": [{"request": {"headers": [{"name": "Cookie", "value": "sessionid=abc123def456"}]}}],
        }
    }
    assert "abc123def456" not in str(mask(har))


def test_a_skip_key_the_service_chose_is_still_skipped_whole():
    masked = MaskPIIFilter(packs=ALL_PACKS, skip_keys={"audit"})._mask_dict({"audit": {"name": "Jane Payer"}})
    assert masked == {"audit": {"name": "Jane Payer"}}
