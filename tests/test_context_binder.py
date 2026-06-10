import structlog

from ecsctx.contrib.django.context_binder import LogContextBinder


def test_base_extract_context_is_empty():
    # The generic base must bind NOTHING — no hardcoded domain fields.
    binder = LogContextBinder.__new__(LogContextBinder)
    assert binder.extract_context(object()) == {}


def test_base_resolve_source_is_passthrough():
    binder = LogContextBinder.__new__(LogContextBinder)
    sentinel = object()
    assert binder.resolve_source_instance(sentinel) is sentinel


def test_subclass_extract_context_is_bound():
    """An integration overrides extract_context; bind_context binds whatever it
    returns onto structlog contextvars."""

    class _Binder(LogContextBinder):
        def get_model_instance(self):
            return object()  # source; resolve_source_instance passes it through

        def extract_context(self, source):
            return {"session_id": "abc", "payment": {"order_no": "ON-1"}}

    structlog.contextvars.clear_contextvars()
    try:
        _Binder(log_entry=None).bind_context()
        ctx = structlog.contextvars.get_contextvars()
        assert ctx.get("session_id") == "abc"
        assert ctx.get("payment") == {"order_no": "ON-1"}
    finally:
        structlog.contextvars.clear_contextvars()


def test_bind_context_records_error_without_crashing():
    """Resolution failures must degrade to a log_bind_error, not raise."""

    class _Binder(LogContextBinder):
        def get_model_instance(self):
            raise ValueError("boom")

    structlog.contextvars.clear_contextvars()
    try:
        _Binder(log_entry=None).bind_context()
        ctx = structlog.contextvars.get_contextvars()
        assert ctx.get("log_bind_error") == "boom"
    finally:
        structlog.contextvars.clear_contextvars()
