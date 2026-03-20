"""Tests for PII masking and field reshaping in log processors."""

from ecsctx.pii import configure_pii, is_configured
from ecsctx.processors import _tokenize, namespace_ecs_fields, reshape_log_event


class TestTokenizeInProcessor:
    def test_redacted_when_unconfigured(self):
        assert not is_configured()
        result = _tokenize("user@example.com", "email")
        assert result == "[PII_REDACTED]"

    def test_returns_token_when_configured(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        result = _tokenize("user@example.com", "email")
        assert result.startswith("ptok:v1:")

    def test_idempotent_already_tokenized(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        token = _tokenize("user@example.com", "email")
        # Tokenizing an already-tokenized value returns it unchanged
        result = _tokenize(token, "email")
        assert result == token

    def test_redacted_when_quoted(self):
        result = _tokenize('"user@example.com"', "email")
        assert result == '"[PII_REDACTED]"'

    def test_empty_value_passthrough(self):
        assert _tokenize("", "email") == ""

    def test_processor_auto_configures_from_env(self, token_keyset_path, monkeypatch):
        """_tokenize() triggers env auto-config without explicit configure_pii() call."""
        monkeypatch.setenv("PII_PROVIDER", "file")
        monkeypatch.setenv("PII_TOKEN_KEYSET_PATH", token_keyset_path)
        monkeypatch.setenv("PII_ENV", "test")
        result = _tokenize("user@example.com", "email")
        assert result.startswith("ptok:v1:")


class TestReshapeLogEvent:
    def test_allowlisted_keys_stay_at_root(self):
        event = {
            "message": "hello",
            "merchant_id": "m1",
            "session_id": "s1",
            "http": {"request": {"method": "GET"}},
            "labels": {"env": "prod"},
        }
        result = reshape_log_event(event)
        assert result["message"] == "hello"
        assert result["merchant_id"] == "m1"
        assert result["session_id"] == "s1"
        assert result["http"] == {"request": {"method": "GET"}}
        assert result["labels"] == {"env": "prod"}
        assert "extra" not in result

    def test_bare_scalars_wrapped_in_extra(self):
        event = {
            "message": "hello",
            "merchant_id": "m1",
            "some_random_key": "val",
            "another_key": 42,
        }
        result = reshape_log_event(event)
        assert result["merchant_id"] == "m1"
        assert "some_random_key" not in result
        assert result["extra"] == {"some_random_key": "val", "another_key": 42}

    def test_allowlisted_dicts_stay_at_root(self):
        event = {
            "message": "hello",
            "payment": {"orn": "123"},
            "http": {"request": {"method": "POST"}},
        }
        result = reshape_log_event(event)
        assert result["payment"] == {"orn": "123"}
        assert result["http"] == {"request": {"method": "POST"}}
        assert "extra" not in result

    def test_non_allowlisted_dicts_go_to_extra(self):
        event = {
            "message": "hello",
            "payment": {"orn": "123"},
            "customer": {"id": "c1", "email": "x@y.com"},
        }
        result = reshape_log_event(event)
        assert result["payment"] == {"orn": "123"}
        assert "customer" not in result
        assert result["extra"] == {"customer": {"id": "c1", "email": "x@y.com"}}

    def test_lists_go_into_extra(self):
        event = {"message": "hello", "tags": ["a", "b"]}
        result = reshape_log_event(event)
        assert result["extra"] == {"tags": ["a", "b"]}

    def test_extra_merge_with_existing(self):
        """If event already has an 'extra' dict plus bare kwargs, they merge."""
        event = {
            "message": "hello",
            "extra": {"foo": "bar"},
            "baz": 123,
        }
        result = reshape_log_event(event)
        # 'extra' is in ROOT_ALLOWLIST, so it stays. 'baz' merges into it.
        assert result["extra"] == {"foo": "bar", "baz": 123}

    def test_non_dict_passthrough(self):
        assert reshape_log_event("not a dict") == "not a dict"

    def test_ecs_event_stays_at_root(self):
        event = {"message": "hello", "ecs_event": {"kind": "event"}}
        result = reshape_log_event(event)
        assert result["ecs_event"] == {"kind": "event"}
        assert "extra" not in result

    def test_structlog_internal_keys_preserved(self):
        """Keys starting with _ (structlog internals like _record) stay at root."""
        record = object()  # simulate a logging.LogRecord
        event = {
            "message": "hello",
            "_record": record,
            "_from_structlog": False,
            "some_random_key": "val",
        }
        result = reshape_log_event(event)
        assert result["_record"] is record
        assert result["_from_structlog"] is False
        assert "some_random_key" not in result
        assert result["extra"] == {"some_random_key": "val"}


class TestNamespaceEcsFields:
    def test_ecs_event_renamed_to_event(self):
        event_dict = {
            "event": "test message",
            "ecs_event": {"kind": "event", "category": ["web"]},
            "level": "info",
        }
        result = namespace_ecs_fields(None, None, event_dict)
        assert result["event"] == {"kind": "event", "category": ["web"]}
        assert "ecs_event" not in result
        assert "level" not in result

    def test_no_ecs_event_passthrough(self):
        event_dict = {"event": "test message", "merchant_id": "m1"}
        result = namespace_ecs_fields(None, None, event_dict)
        assert "ecs_event" not in result
        assert result["merchant_id"] == "m1"
