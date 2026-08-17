"""Tests for PII masking and field reshaping in log processors."""

from ecsctx.masking.exemptions import _compile_path, _path_is_exempt
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.pii import configure_pii, is_configured
from ecsctx.processors import (
    callsite_ecs_fields,
    error_ecs_fields,
    safe_tokenize,
    configure_masking,
    configure_masking_from_env,
    configure_root_fields,
    masking_is_configured,
    root_fields_are_configured,
    namespace_ecs_fields,
    reshape_log_event,
)

# MaskPIIFilter._mask_value is the direct engine entry point the old
# ecsctx.processors._safe_dump_and_mask used to wrap — mask_sensitive_data
# (the structlog processor) now delegates to the same MaskPIIFilter instance.
_mask = MaskPIIFilter()._mask_value


class TestTokenizeInProcessor:
    def test_redacted_when_unconfigured(self):
        assert not is_configured()
        result = safe_tokenize("user@example.com", "email")
        assert result == "[PII_REDACTED]"

    def test_returns_token_when_configured(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        result = safe_tokenize("user@example.com", "email")
        assert result.startswith("ptok:v1:")

    def test_idempotent_already_tokenized(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        token = safe_tokenize("user@example.com", "email")
        # Tokenizing an already-tokenized value returns it unchanged
        result = safe_tokenize(token, "email")
        assert result == token

    def test_redacted_when_quoted(self):
        """No quote re-wrapping on output — quoted or bare, unconfigured
        always falls back to the same redaction marker."""
        result = safe_tokenize('"user@example.com"', "email")
        assert result == "[PII_REDACTED]"

    def test_empty_value_passthrough(self):
        assert safe_tokenize("", "email") == ""

    def test_processor_auto_configures_from_env(self, token_keyset_path, monkeypatch):
        """safe_tokenize() triggers env auto-config without explicit configure_pii() call."""
        monkeypatch.setenv("PII_PROVIDER", "file")
        monkeypatch.setenv("PII_TOKEN_KEYSET_PATH", token_keyset_path)
        monkeypatch.setenv("PII_ENV", "test")
        result = safe_tokenize("user@example.com", "email")
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

    def test_structlog_internal_keys_preserved_at_root(self):
        record = object()
        event = {
            "message": "hello",
            "_record": record,
            "_from_structlog": True,
            "custom_key": "val",
        }
        result = reshape_log_event(event)
        assert result["_record"] is record
        assert result["_from_structlog"] is True
        assert result["extra"] == {"custom_key": "val"}


class TestNamespaceEcsFields:
    def test_ecs_event_emitted_as_dotted_keys_preserving_message(self):
        # The message (structlog's "event") must be preserved; ECS event fields
        # are emitted as dotted keys so ecs-logging de-dots them into event.*
        # AFTER popping "event" -> "message". (Previously this clobbered the
        # message with the ecs_event dict.)
        event_dict = {
            "event": "test message",
            "ecs_event": {"kind": "event", "category": ["web"]},
            "level": "info",
        }
        result = namespace_ecs_fields(None, None, event_dict)
        assert result["event"] == "test message"
        assert result["event.kind"] == "event"
        assert result["event.category"] == ["web"]
        assert "ecs_event" not in result
        assert "level" not in result

    def test_no_ecs_event_passthrough(self):
        event_dict = {"event": "test message", "merchant_id": "m1"}
        result = namespace_ecs_fields(None, None, event_dict)
        assert "ecs_event" not in result
        assert result["merchant_id"] == "m1"


class TestCompilePath:
    def test_array_wildcard(self):
        assert _compile_path("payment_methods[*].name") == (
            "payment_methods",
            "[*]",
            "name",
        )

    def test_dotted(self):
        assert _compile_path("customer.name") == ("customer", "name")

    def test_dict_wildcard(self):
        assert _compile_path("a.*.b") == ("a", "*", "b")


class TestPathExempt:
    @staticmethod
    def _ex(*paths):
        return tuple(_compile_path(p) for p in paths)

    def test_exact_leaf(self):
        ex = self._ex("payment_methods[*].name")
        assert _path_is_exempt(("payment_methods", "[*]", "name"), ex)

    def test_subtree_prefix(self):
        ex = self._ex("payment_methods")
        assert _path_is_exempt(("payment_methods", "[*]", "card", "cvv"), ex)

    def test_non_match(self):
        ex = self._ex("payment_methods[*].name")
        assert not _path_is_exempt(("customer", "name"), ex)

    def test_star_is_dict_only(self):
        ex = self._ex("x.*")
        assert _path_is_exempt(("x", "y"), ex)
        assert not _path_is_exempt(("x", "[*]"), ex)

    def test_array_token_requires_array(self):
        ex = self._ex("items[*]")
        assert _path_is_exempt(("items", "[*]"), ex)
        assert not _path_is_exempt(("items", "name"), ex)


class TestMaskWalker:
    """MaskPIIFilter._mask_value walks dicts/lists, tokenizing sensitive-key
    values (unless whitelisted/exempted) and content-scanning every string.

    Note: a top-level dict key that is itself a sensitive keyword (e.g.
    "customer" — see ecsctx.masking.patterns.KEYWORD_REGEX_FIELD_TYPE) is
    blanket-masked as a whole, not recursed into — so these tests use
    "profile" (not itself sensitive) as the non-colliding wrapper key when
    they need to assert on a *nested* field.
    """

    def test_exempted_leaf_notsafe_tokenized(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        configure_masking(exempt_paths=["payment_methods[*].name"])
        out = _mask({"payment_methods": [{"name": "VISA-John"}]})
        assert out["payment_methods"][0]["name"] == "VISA-John"

    def test_same_key_non_exempt_tokenized(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        configure_masking(exempt_paths=["payment_methods[*].name"])
        out = _mask({"profile": {"name": "John Doe"}})
        assert out["profile"]["name"].startswith("[NAME-MASKED:ptok:v1:")

    def test_subtree_exemption_with_email_still_scrubbed(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        configure_masking(exempt_paths=["audit"])
        out = _mask(
            {"audit": {"customer_name": "X", "billing_email": "a@b.com"}}
        )
        assert out["audit"]["customer_name"] == "X"
        # Key-based masking is exempted under "audit", but the email regex
        # still catches the value content-wise (defense in depth).
        assert out["audit"]["billing_email"].startswith("[EMAIL-MASKED:ptok:v1:")

    def test_nested_dict_path(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        configure_masking(exempt_paths=["a.b.customer_name"])
        out = _mask(
            {"a": {"b": {"customer_name": "Keep", "payer_name": "Mask"}}}
        )
        assert out["a"]["b"]["customer_name"] == "Keep"
        assert out["a"]["b"]["payer_name"].startswith("[NAME-MASKED:ptok:v1:")

    def test_arrays_of_arrays(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        configure_masking(exempt_paths=[])
        out = _mask({"matrix": [[{"customer_email": "x@y.com"}]]})
        assert out["matrix"][0][0]["customer_email"].startswith("[EMAIL-MASKED:ptok:v1:")

    def test_list_of_strings_email_scrubbed(self, token_keyset_path):
        # "notes" (not itself a sensitive key, unlike "emails") so each list
        # item is content-scanned independently rather than the whole list
        # being blanket-masked as one key-based match.
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        out = _mask({"notes": ["x@y.com", "plain"]})
        assert out["notes"][0].startswith("[EMAIL-MASKED:ptok:v1:")
        assert out["notes"][1] == "plain"

    def test_non_sensitive_key_scalars_untouched(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        out = _mask({"amount": 10, "flag": True, "nope": None})
        assert out["amount"] == 10
        assert out["flag"] is True
        assert out["nope"] is None

    def test_sensitive_key_scalar_masked_regardless_of_type(self, token_keyset_path):
        """A sensitive key (e.g. containing "name") blanket-masks its value
        even when the value isn't a string — key-based masking overrides the
        numeric/bool/None content-level passthrough."""
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        out = _mask({"customer_name": 123})
        assert out["customer_name"].startswith("[NAME-MASKED:ptok:v1:")

    def test_idempotent_rerun(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        payload = {"profile": {"name": "John", "email": "a@b.com"}}
        once = _mask(payload)
        twice = _mask(once)
        assert once == twice


class TestMaskWalkerUnconfiguredPII:
    def test_unconfigured_redacts(self):
        assert not is_configured()
        out = _mask({"customer_name": "John"})
        assert out["customer_name"] == "[NAME-MASKED]"

    def test_unconfigured_idempotent(self):
        once = _mask({"customer_name": "John"})
        twice = _mask(once)
        assert once == twice


class TestMaskTopLevel:
    def test_top_level_list(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        out = _mask([{"customer_name": "John"}])
        assert out[0]["customer_name"].startswith("[NAME-MASKED:ptok:v1:")

    def test_top_level_string_email(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        out = _mask("contact a@b.com please")
        assert "[EMAIL-MASKED:ptok:v1:" in out

    def test_top_level_scalars(self):
        assert _mask(42) == 42
        assert _mask(None) is None

    def test_empty_containers(self):
        assert _mask({}) == {}
        assert _mask([]) == []


class TestMaskConfigEnv:
    def test_env_var_config(self, token_keyset_path, monkeypatch):
        monkeypatch.setenv("PII_MASK_EXEMPT_PATHS", "payment_methods[*].name, audit")
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        out = _mask(
            {"payment_methods": [{"name": "KNET"}], "profile": {"name": "John"}}
        )
        assert out["payment_methods"][0]["name"] == "KNET"
        assert out["profile"]["name"].startswith("[NAME-MASKED:ptok:v1:")

    def test_explicit_beats_env(self, token_keyset_path, monkeypatch):
        monkeypatch.setenv("PII_MASK_EXEMPT_PATHS", "profile.name")
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        configure_masking(exempt_paths=[])
        out = _mask({"profile": {"name": "John"}})
        assert out["profile"]["name"].startswith("[NAME-MASKED:ptok:v1:")

    def test_empty_default_still_configured(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        out = _mask({"profile": {"name": "John"}})
        assert out["profile"]["name"].startswith("[NAME-MASKED:ptok:v1:")
        assert masking_is_configured()


class TestConfigureMaskingFromEnv:
    def test_parses_csv_ignoring_blanks(self, monkeypatch):
        from ecsctx.masking.exemptions import _get_exempt_patterns

        monkeypatch.setenv("PII_MASK_EXEMPT_PATHS", "a.b, c[*].d ,, ")
        configure_masking_from_env()
        assert _get_exempt_patterns() == (("a", "b"), ("c", "[*]", "d"))

    def test_idempotent_second_call_does_not_reload(self, monkeypatch):
        from ecsctx.masking.exemptions import _get_exempt_patterns

        monkeypatch.setenv("PII_MASK_EXEMPT_PATHS", "first")
        configure_masking_from_env()
        monkeypatch.setenv("PII_MASK_EXEMPT_PATHS", "second")
        configure_masking_from_env()
        assert _get_exempt_patterns() == (("first",),)

    def test_explicit_configure_beats_a_later_env_load(self, monkeypatch):
        from ecsctx.masking.exemptions import _get_exempt_patterns

        configure_masking(exempt_paths=["explicit"])
        monkeypatch.setenv("PII_MASK_EXEMPT_PATHS", "fromenv")
        configure_masking_from_env()
        assert _get_exempt_patterns() == (("explicit",),)

    def test_unset_env_yields_no_exemptions_but_marks_configured(self, monkeypatch):
        from ecsctx.masking.exemptions import _get_exempt_patterns

        monkeypatch.delenv("PII_MASK_EXEMPT_PATHS", raising=False)
        configure_masking_from_env()
        assert _get_exempt_patterns() == ()
        assert masking_is_configured()


class TestRootFieldsConfig:
    def test_default_non_allowlisted_goes_to_extra(self):
        result = reshape_log_event({"message": "hi", "customer": {"id": "c1"}})
        assert "customer" not in result
        assert result["extra"] == {"customer": {"id": "c1"}}

    def test_configured_field_stays_at_root(self):
        configure_root_fields(extra_fields=["customer"])
        result = reshape_log_event({"message": "hi", "customer": {"id": "c1"}})
        assert result["customer"] == {"id": "c1"}
        assert "extra" not in result

    def test_builtin_allowlist_unaffected_by_config(self):
        configure_root_fields(extra_fields=["customer"])
        result = reshape_log_event({"message": "hi", "session_id": "s1", "other": 1})
        assert result["session_id"] == "s1"
        assert result["extra"] == {"other": 1}

    def test_env_var_config(self, monkeypatch):
        monkeypatch.setenv("ECSCTX_ROOT_FIELDS", "customer, booking")
        result = reshape_log_event({
            "message": "hi",
            "customer": {"id": "c1"},
            "booking": {"ref": "b1"},
            "other": 1,
        })
        assert result["customer"] == {"id": "c1"}
        assert result["booking"] == {"ref": "b1"}
        assert result["extra"] == {"other": 1}

    def test_explicit_beats_env(self, monkeypatch):
        monkeypatch.setenv("ECSCTX_ROOT_FIELDS", "customer")
        configure_root_fields(extra_fields=[])
        result = reshape_log_event({"message": "hi", "customer": {"id": "c1"}})
        assert "customer" not in result
        assert result["extra"] == {"customer": {"id": "c1"}}
        assert root_fields_are_configured()


class TestCallsiteEcsFields:
    def _event(self, **extra):
        event = {
            "message": "hi",
            "logger": "core.gateway.knet.KnetClient",
            "func_name": "connect",
            "pathname": "/app/core/gateway/knet/client.py",
            "lineno": 42,
        }
        event.update(extra)
        return event

    def test_reshapes_flat_keys_into_log_container(self):
        result = callsite_ecs_fields(None, "info", self._event())
        assert result["log"] == {
            "logger": "core.gateway.knet.KnetClient",
            "origin": {
                "function": "connect",
                "file": {"name": "/app/core/gateway/knet/client.py", "line": 42},
            },
        }
        for flat in ("logger", "func_name", "pathname", "lineno"):
            assert flat not in result

    def test_caller_provided_origin_wins_over_frame(self):
        result = callsite_ecs_fields(
            None,
            "info",
            self._event(log={"origin": {"function": "decorated_site"}}),
        )
        assert result["log"]["origin"] == {"function": "decorated_site"}
        assert result["log"]["logger"] == "core.gateway.knet.KnetClient"

    def test_caller_provided_logger_wins(self):
        result = callsite_ecs_fields(
            None, "info", self._event(log={"logger": "explicit"})
        )
        assert result["log"]["logger"] == "explicit"

    def test_partial_callsite_keys(self):
        result = callsite_ecs_fields(
            None, "info", {"message": "hi", "logger": "a.b", "lineno": 7}
        )
        assert result["log"] == {"logger": "a.b", "origin": {"file": {"line": 7}}}

    def test_no_callsite_keys_is_a_noop(self):
        result = callsite_ecs_fields(None, "info", {"message": "hi"})
        assert result == {"message": "hi"}

    def test_non_dict_log_value_is_replaced(self):
        result = callsite_ecs_fields(
            None, "info", {"message": "hi", "logger": "a.b", "log": "oops"}
        )
        assert result["log"]["logger"] == "a.b"


class TestErrorEcsFields:
    def _exc_info(self):
        try:
            raise FileNotFoundError(2, "No such file or directory")
        except FileNotFoundError:
            import sys

            return sys.exc_info()

    def test_consumes_exc_info_into_full_error_object(self):
        result = error_ecs_fields(None, "error", {"exc_info": self._exc_info()})
        assert result["error"]["type"] == "FileNotFoundError"
        assert result["error"]["message"] == "[Errno 2] No such file or directory"
        assert result["error"]["stack_trace"].startswith("Traceback")
        assert "FileNotFoundError" in result["error"]["stack_trace"]
        # the raw tuple must never survive to a formatter
        assert "exc_info" not in result

    def test_explicit_error_values_win(self):
        result = error_ecs_fields(
            None,
            "error",
            {"exc_info": self._exc_info(), "error": {"message": "custom", "type": "X"}},
        )
        assert result["error"]["message"] == "custom"
        assert result["error"]["type"] == "X"
        # stack_trace is still derived — the caller didn't provide one
        assert result["error"]["stack_trace"].startswith("Traceback")

    def test_caller_error_dict_is_not_mutated(self):
        shared = {"message": "custom"}
        result = error_ecs_fields(None, "error", {"exc_info": self._exc_info(), "error": shared})
        assert shared == {"message": "custom"}
        assert result["error"] is not shared

    def test_non_dict_error_value_is_replaced(self):
        # error="..." already violates the ECS object rule; with exc_info present
        # the derived object wins (explicitly asserted, not accidental).
        result = error_ecs_fields(
            None, "error", {"exc_info": self._exc_info(), "error": "some string"}
        )
        assert result["error"]["type"] == "FileNotFoundError"

    def test_bare_exception_instance(self):
        result = error_ecs_fields(None, "error", {"exc_info": ValueError("boom")})
        assert result["error"]["type"] == "ValueError"
        assert result["error"]["message"] == "boom"
        assert "exc_info" not in result

    def test_exc_info_true_resolves_current_exception(self):
        try:
            raise KeyError("missing")
        except KeyError:
            result = error_ecs_fields(None, "error", {"exc_info": True})
        assert result["error"]["type"] == "KeyError"
        assert "exc_info" not in result

    def test_noop_without_exc_info(self):
        assert error_ecs_fields(None, "info", {"event": "x"}) == {"event": "x"}


class TestExceptionKeysInReshape:
    def test_rendered_exception_string_stays_at_root(self):
        from ecsctx.processors import reshape_log_event

        result = reshape_log_event({"exception": "Traceback...", "custom_key": 1})
        assert result["exception"] == "Traceback..."
        assert result["extra"] == {"custom_key": 1}

    def test_stray_raw_exc_info_still_swept_to_extra(self):
        # A pipeline without error_ecs_fields keeps the old (pre-0.5.6) sweep —
        # a raw tuple never lands at the document root.
        from ecsctx.processors import reshape_log_event

        ei = (ValueError, ValueError("boom"), None)
        result = reshape_log_event({"exc_info": ei})
        assert "exc_info" not in result
        assert result["extra"]["exc_info"] is ei


class TestStandalonePipelineSafety:
    def test_no_raw_exc_info_at_root_without_exception_renderer(self):
        """The README quickstart-style manual pipeline (no ExceptionRenderer):
        error_ecs_fields alone must produce a JSON-safe document."""
        import json

        event = {"event": "boom happened", "exc_info": None}
        try:
            raise RuntimeError("standalone")
        except RuntimeError:
            import sys

            event["exc_info"] = sys.exc_info()
        event = error_ecs_fields(None, "error", event)
        event = namespace_ecs_fields(None, "error", event)
        json.dumps(event)  # must not raise, no repr-garbage tuples anywhere
        assert event["error"]["type"] == "RuntimeError"
        assert event["error"]["stack_trace"].startswith("Traceback")
        assert "exc_info" not in event
        assert "exc_info" not in event.get("extra", {})
