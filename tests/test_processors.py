"""Tests for PII masking in log processors."""

from logctx.pii import configure_pii, is_configured
from logctx.processors import _tokenize


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
