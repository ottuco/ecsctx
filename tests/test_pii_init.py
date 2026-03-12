"""Tests for PII module auto-configuration and access control."""

import base64
import json
import os

import pytest

from ecsctx.pii import (
    PIIAccessDeniedError,
    PIINotConfiguredError,
    _reset,
    configure_pii,
    configure_pii_from_env,
    is_configured,
    protect,
    reveal,
    tokenize,
)
from tests.conftest import make_keyset_json


class TestConfigurePiiBackwardCompat:
    def test_explicit_paths(self, token_keyset_path, reveal_keyset_path):
        configure_pii(
            token_keyset_path=token_keyset_path,
            reveal_keyset_path=reveal_keyset_path,
            env="test",
        )
        assert is_configured()
        result = tokenize("user@example.com", "email")
        assert result.startswith("ptok:v1:")

    def test_env_vars(self, token_keyset_path, monkeypatch):
        monkeypatch.setenv("PII_TOKEN_KEYSET_PATH", token_keyset_path)
        monkeypatch.setenv("PII_ENV", "test")
        configure_pii()
        assert is_configured()

    def test_no_path_raises(self, monkeypatch):
        monkeypatch.delenv("PII_TOKEN_KEYSET_PATH", raising=False)
        with pytest.raises(PIINotConfiguredError):
            configure_pii()


class TestConfigurePiiFromEnv:
    def test_file_provider(self, token_keyset_path, monkeypatch):
        monkeypatch.setenv("PII_PROVIDER", "file")
        monkeypatch.setenv("PII_TOKEN_KEYSET_PATH", token_keyset_path)
        monkeypatch.setenv("PII_ENV", "test")
        configure_pii_from_env()
        assert is_configured()

    def test_legacy_compat_no_provider_var(self, token_keyset_path, monkeypatch):
        """PII_TOKEN_KEYSET_PATH without PII_PROVIDER defaults to file."""
        monkeypatch.delenv("PII_PROVIDER", raising=False)
        monkeypatch.setenv("PII_TOKEN_KEYSET_PATH", token_keyset_path)
        configure_pii_from_env()
        assert is_configured()

    def test_no_env_vars_stays_unconfigured(self, monkeypatch):
        monkeypatch.delenv("PII_PROVIDER", raising=False)
        monkeypatch.delenv("PII_TOKEN_KEYSET_PATH", raising=False)
        configure_pii_from_env()
        assert not is_configured()

    def test_idempotent(self, token_keyset_path, monkeypatch):
        monkeypatch.setenv("PII_PROVIDER", "file")
        monkeypatch.setenv("PII_TOKEN_KEYSET_PATH", token_keyset_path)
        configure_pii_from_env()
        configure_pii_from_env()  # should be a no-op
        assert is_configured()

    def test_unknown_provider_raises(self, monkeypatch):
        monkeypatch.setenv("PII_PROVIDER", "unknown")
        with pytest.raises(PIINotConfiguredError, match="unknown"):
            configure_pii_from_env()

    def test_file_provider_missing_path_raises(self, monkeypatch):
        monkeypatch.setenv("PII_PROVIDER", "file")
        monkeypatch.delenv("PII_TOKEN_KEYSET_PATH", raising=False)
        with pytest.raises(PIINotConfiguredError, match="PII_TOKEN_KEYSET_PATH"):
            configure_pii_from_env()


class TestAutoConfigureFromTokenize:
    def test_tokenize_triggers_auto_config(self, token_keyset_path, monkeypatch):
        monkeypatch.setenv("PII_PROVIDER", "file")
        monkeypatch.setenv("PII_TOKEN_KEYSET_PATH", token_keyset_path)
        monkeypatch.setenv("PII_ENV", "test")
        # No explicit configure call — tokenize() should auto-configure
        result = tokenize("user@example.com", "email")
        assert result.startswith("ptok:v1:")
        assert is_configured()

    def test_unconfigured_raises(self, monkeypatch):
        monkeypatch.delenv("PII_PROVIDER", raising=False)
        monkeypatch.delenv("PII_TOKEN_KEYSET_PATH", raising=False)
        with pytest.raises(PIINotConfiguredError):
            tokenize("value")


class TestAccessControl:
    def test_protect_denied_in_tokenize_mode(self, token_keyset_path, monkeypatch):
        monkeypatch.setenv("PII_PROVIDER", "file")
        monkeypatch.setenv("PII_ACCESS", "tokenize")
        monkeypatch.setenv("PII_TOKEN_KEYSET_PATH", token_keyset_path)
        configure_pii_from_env()
        with pytest.raises(PIIAccessDeniedError, match="PII_ACCESS=full"):
            protect("value")

    def test_reveal_denied_in_tokenize_mode(self, token_keyset_path, monkeypatch):
        monkeypatch.setenv("PII_PROVIDER", "file")
        monkeypatch.setenv("PII_ACCESS", "tokenize")
        monkeypatch.setenv("PII_TOKEN_KEYSET_PATH", token_keyset_path)
        configure_pii_from_env()
        with pytest.raises(PIIAccessDeniedError, match="PII_ACCESS=full"):
            reveal("penc:v1:rk1:payload")

    def test_full_access_allows_protect_reveal(
        self, token_keyset_path, reveal_keyset_path, monkeypatch
    ):
        monkeypatch.setenv("PII_PROVIDER", "file")
        monkeypatch.setenv("PII_ACCESS", "full")
        monkeypatch.setenv("PII_TOKEN_KEYSET_PATH", token_keyset_path)
        monkeypatch.setenv("PII_REVEAL_KEYSET_PATH", reveal_keyset_path)
        monkeypatch.setenv("PII_ENV", "test")
        configure_pii_from_env()
        ct = protect("user@example.com", "email")
        assert ct.startswith("penc:v1:")
        pt = reveal(ct, "email")
        assert pt == "user@example.com"


class TestKeyRotation:
    def test_old_ciphertext_decrypts_after_rotation(self, tmp_path, monkeypatch):
        """Encrypt with key v1, add key v2 as primary, old ciphertext still decrypts."""
        # Create reveal keyset with one key
        key1 = os.urandom(32)
        key1_b64 = base64.urlsafe_b64encode(key1).rstrip(b"=").decode()
        keyset_v1 = {
            "schema_version": 1,
            "primary_kid": "rk1",
            "keys": {
                "rk1": {"alg": "AES-256-GCM", "created_at": "2025-01-01", "key_b64": key1_b64},
            },
        }
        reveal_path = tmp_path / "reveal.json"
        reveal_path.write_text(json.dumps(keyset_v1))

        # Token keyset (required for configure_pii)
        token_path = tmp_path / "token.json"
        token_path.write_text(make_keyset_json(primary_kid="tk1"))

        configure_pii(
            token_keyset_path=str(token_path),
            reveal_keyset_path=str(reveal_path),
            env="test",
        )

        ct = protect("secret@example.com", "email")
        assert ct.startswith("penc:v1:rk1:")

        # Rotate: add rk2 as new primary, keep rk1
        _reset()
        key2 = os.urandom(32)
        key2_b64 = base64.urlsafe_b64encode(key2).rstrip(b"=").decode()
        keyset_v2 = {
            "schema_version": 1,
            "primary_kid": "rk2",
            "keys": {
                "rk1": {"alg": "AES-256-GCM", "created_at": "2025-01-01", "key_b64": key1_b64},
                "rk2": {"alg": "AES-256-GCM", "created_at": "2025-06-01", "key_b64": key2_b64},
            },
        }
        reveal_path.write_text(json.dumps(keyset_v2))

        configure_pii(
            token_keyset_path=str(token_path),
            reveal_keyset_path=str(reveal_path),
            env="test",
        )

        # Old ciphertext (encrypted with rk1) still decrypts
        pt = reveal(ct, "email")
        assert pt == "secret@example.com"

        # New encryptions use rk2
        ct2 = protect("new@example.com", "email")
        assert ct2.startswith("penc:v1:rk2:")
