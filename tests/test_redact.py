"""Tests for network-boundary credential redaction (ecsctx.contrib.net)."""

from django.test import override_settings

from ecsctx.contrib.net import (
    configure_redaction,
    loggable_body,
    redact_body,
    redact_url,
)


class _FakeResponse:
    def __init__(self, text, content_type):
        self.text = text
        self.headers = {"Content-Type": content_type}


class TestRedactUrl:
    def test_credential_query_params_are_masked(self):
        url = "https://sms.example.com/send?username=bob&password=s3cret&to=123"
        redacted = redact_url(url)
        assert "s3cret" not in redacted
        assert "bob" not in redacted
        assert "to=123" in redacted

    def test_access_code_and_apikey_hints_are_masked(self):
        url = "https://gw.example.com/pay?access_code=AAAA&order_id=42"
        redacted = redact_url(url)
        assert "AAAA" not in redacted
        assert "order_id=42" in redacted

    def test_single_letter_legacy_keys_are_masked(self):
        assert "P=s3cret" not in redact_url("https://fcc.example.com/?P=s3cret")

    def test_non_credential_query_survives_verbatim(self):
        url = "https://api.example.com/v1?order_id=42&reference=REF-1"
        assert redact_url(url) == url

    def test_empty_none_and_non_string_pass_through(self):
        assert redact_url("") == ""
        assert redact_url(None) is None
        assert redact_url(123) == 123

    def test_unparseable_url_is_fully_redacted(self):
        assert redact_url("http://[::1") == "[REDACTED]"


class TestRedactBody:
    def test_json_secret_values_are_masked(self):
        body = '{"access_token": "tok123", "token_type": "bearer"}'
        redacted = redact_body(body)
        assert "tok123" not in redacted
        assert "bearer" in redacted

    def test_form_secret_values_are_masked(self):
        body = "client_secret=s3cret&grant_type=client_credentials"
        redacted = redact_body(body)
        assert "s3cret" not in redacted
        assert "grant_type=client_credentials" in redacted

    def test_bare_token_key_is_left_alone(self):
        # Gateways reuse `token` for non-secret payment/session identifiers.
        body = '{"token": "pay_abc123"}'
        assert redact_body(body) == body

    def test_clean_body_returns_unchanged(self):
        body = '{"status": "ok", "id": 42}'
        assert redact_body(body) == body


class TestLoggableBody:
    def test_non_textual_body_is_omitted(self):
        assert loggable_body(_FakeResponse("...binary...", "application/pdf")) is None

    def test_textual_body_is_redacted_and_capped(self):
        body = '{"access_token": "tok123"}' + ("x" * 9000)
        logged = loggable_body(_FakeResponse(body, "application/json"))
        assert "tok123" not in logged
        assert len(logged) <= 4096

    def test_redact_runs_before_the_cap(self):
        # A cap landing mid-value must not leave a token head exposed: the
        # JSON pattern needs the closing quote, so redact first, then slice.
        secret = "s" * 5000
        body = '{"access_token": "' + secret + '"}'
        logged = loggable_body(_FakeResponse(body, "application/json"))
        assert secret not in logged
        assert "[REDACTED]" in logged


class TestRedactionConfig:
    def test_extra_keys_via_call(self):
        configure_redaction(extra_secret_keys=["merchant_pin"])
        assert "1234" not in redact_body('{"merchant_pin": "1234"}')

    def test_extra_keys_via_env(self, monkeypatch):
        monkeypatch.setenv("ECSCTX_REDACT_EXTRA_SECRET_KEYS", "merchant_pin, terminal_secret")
        assert "1234" not in redact_body('{"merchant_pin": "1234"}')

    def test_body_cap_via_env(self, monkeypatch):
        monkeypatch.setenv("ECSCTX_REDACT_BODY_LOG_CAP", "16")
        logged = loggable_body(_FakeResponse("x" * 100, "text/plain"))
        assert logged == "x" * 16

    def test_invalid_cap_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("ECSCTX_REDACT_BODY_LOG_CAP", "not-a-number")
        logged = loggable_body(_FakeResponse("x" * 5000, "text/plain"))
        assert len(logged) == 4096

    def test_raising_text_property_returns_none(self):
        # A body that can't be read is omitted, never raised nor logged raw.
        class _Boom:
            def __init__(self):
                self.headers = {"Content-Type": "application/json"}

            @property
            def text(self):
                raise ValueError("cannot decode")

        assert loggable_body(_Boom()) is None


class TestDjangoSettingsBridge:
    def test_django_settings_override_keys(self):
        with override_settings(ECSCTX_REDACT_EXTRA_SECRET_KEYS=["merchant_pin"]):
            assert "1234" not in redact_body('{"merchant_pin": "1234"}')

    def test_django_settings_accept_csv_string(self):
        with override_settings(ECSCTX_REDACT_EXTRA_SECRET_KEYS="a_pin, b_pin"):
            assert "1" not in redact_body('{"a_pin": "1"}')
            assert "2" not in redact_body('{"b_pin": "2"}')

    def test_explicit_call_wins_over_django_settings(self):
        configure_redaction(extra_secret_keys=["svc_key"])
        with override_settings(ECSCTX_REDACT_EXTRA_SECRET_KEYS=["merchant_pin"]):
            assert "[REDACTED]" in redact_body('{"svc_key": "aaa"}')
            assert redact_body('{"merchant_pin": "1234"}') == '{"merchant_pin": "1234"}'

    def test_django_settings_win_over_env(self, monkeypatch):
        monkeypatch.setenv("ECSCTX_REDACT_EXTRA_SECRET_KEYS", "env_key")
        with override_settings(ECSCTX_REDACT_EXTRA_SECRET_KEYS=["dj_key"]):
            assert "1" not in redact_body('{"dj_key": "1"}')
            assert redact_body('{"env_key": "2"}') == '{"env_key": "2"}'

    def test_django_settings_cap(self):
        with override_settings(ECSCTX_REDACT_BODY_LOG_CAP=16):
            assert loggable_body(_FakeResponse("x" * 100, "text/plain")) == "x" * 16
