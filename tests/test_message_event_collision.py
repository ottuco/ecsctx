import json

from ecs_logging import StructlogFormatter

from ecsctx import (
    ecs_validator,
    mask_sensitive_data,
    namespace_ecs_fields,
)


def _render(event_dict: dict) -> dict:
    """Run an event dict through the real ProcessorFormatter tail + ECS formatter,
    exactly as ecsctx.contrib.django.logging.get_logging_config wires it.
    """
    for proc in (namespace_ecs_fields, mask_sensitive_data, ecs_validator):
        event_dict = proc(None, "info", event_dict)
    return json.loads(StructlogFormatter()(None, "info", event_dict))


def test_message_is_human_readable_and_event_is_nested():
    # What the api_logging decorator produces after structlog formats the message:
    out = _render({
        "event": "OUTBOUND POST /b/checkout/v1/pymt-txn/ (201)",
        "ecs_event": {
            "kind": "event",
            "category": ["web"],
            "type": ["access"],
            "outcome": "success",
        },
        "view": "CheckoutCreateApiView",
        "url": {"path": "/b/checkout/v1/pymt-txn/"},
    })

    assert out["message"] == "OUTBOUND POST /b/checkout/v1/pymt-txn/ (201)"
    assert out["event"] == {
        "kind": "event",
        "category": ["web"],
        "type": ["access"],
        "outcome": "success",
    }
    # The staging key must be gone, and the message must never be the dict repr.
    assert "ecs_event" not in out
    assert not out["message"].startswith("{")


def test_event_keys_survive_double_processor_pass():
    """foreign_pre_chain + main processors can run namespace_ecs_fields twice on
    stdlib records; the dotted event.* keys must not leak into `extra`."""
    first = namespace_ecs_fields(None, "info", {
        "event": "INBOUND GET /x",
        "ecs_event": {"kind": "event", "category": ["web"], "type": ["access"]},
    })
    second = namespace_ecs_fields(None, "info", dict(first))
    out = json.loads(StructlogFormatter()(None, "info", second))
    assert out["message"] == "INBOUND GET /x"
    assert out["event"] == {"kind": "event", "category": ["web"], "type": ["access"]}
    assert "extra" not in out or "event.kind" not in out.get("extra", {})
