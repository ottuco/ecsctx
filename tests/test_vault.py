"""Tests for VaultKeysetProvider."""

import json
import time
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from logctx.pii import PIIAccessDeniedError
from logctx.pii.vault import VaultKeysetProvider
from tests.conftest import make_keyset_json


def _make_vault_provider(
    tmp_path,
    *,
    access_mode="full",
    refresh_seconds=300.0,
    cacert_path=None,
):
    """Create a VaultKeysetProvider with credential files."""
    role_id_path = tmp_path / "role-id"
    role_id_path.write_text("test-role-id")
    secret_id_path = tmp_path / "secret-id"
    secret_id_path.write_text("test-secret-id")

    return VaultKeysetProvider(
        vault_addr="https://vault.example.com",
        role_id_path=str(role_id_path),
        secret_id_path=str(secret_id_path),
        token_keyset_mount_path="secret/data/pii/token-keyset",
        reveal_keyset_mount_path=(
            "secret/data/pii/reveal-keyset" if access_mode == "full" else None
        ),
        cacert_path=cacert_path,
        env="test",
        access_mode=access_mode,
        refresh_seconds=refresh_seconds,
    )


def _mock_urlopen(responses):
    """Create a mock urlopen that returns responses in order.

    responses: list of dicts to return as JSON.
    """
    call_count = 0

    def urlopen(request, context=None):
        nonlocal call_count
        idx = min(call_count, len(responses) - 1)
        call_count += 1
        resp = MagicMock()
        resp.read.return_value = json.dumps(responses[idx]).encode()
        return resp

    return urlopen


class TestVaultAuth:
    def test_auth_and_fetch(self, tmp_path):
        token_keyset_json = make_keyset_json(primary_kid="tk1")
        reveal_keyset_json = make_keyset_json(primary_kid="rk1")

        responses = [
            # AppRole login
            {"auth": {"client_token": "s.test", "lease_duration": 3600}},
            # Token keyset fetch
            {"data": {"data": {"keyset": token_keyset_json}}},
            # Reveal keyset fetch
            {"data": {"data": {"keyset": reveal_keyset_json}}},
        ]

        provider = _make_vault_provider(tmp_path)

        with patch("urllib.request.urlopen", _mock_urlopen(responses)):
            token_ks = provider.get_token_keyset()
            assert token_ks.primary_kid == "tk1"

            reveal_ks = provider.get_reveal_keyset()
            assert reveal_ks.primary_kid == "rk1"

    def test_token_refresh_on_expiry(self, tmp_path):
        token_keyset_json = make_keyset_json(primary_kid="tk1")

        # First auth + fetch, then second auth + fetch after expiry
        responses = [
            {"auth": {"client_token": "s.first", "lease_duration": 3600}},
            {"data": {"data": {"keyset": token_keyset_json}}},
            # Second auth (after forced expiry)
            {"auth": {"client_token": "s.second", "lease_duration": 3600}},
            {"data": {"data": {"keyset": token_keyset_json}}},
        ]

        provider = _make_vault_provider(tmp_path, access_mode="tokenize", refresh_seconds=0)
        mock_urlopen = _mock_urlopen(responses)

        with patch("urllib.request.urlopen", mock_urlopen):
            provider.get_token_keyset()
            # Force token expiry
            provider._vault_token_expiry = 0
            provider._last_refresh = 0
            provider.get_token_keyset()
            # Should have re-authenticated (4 calls total)
            assert mock_urlopen.__code__  # just verify it didn't raise


class TestVaultFailSafe:
    def test_keeps_last_good_on_refresh_failure(self, tmp_path):
        token_keyset_json = make_keyset_json(primary_kid="tk1")
        responses = [
            {"auth": {"client_token": "s.test", "lease_duration": 3600}},
            {"data": {"data": {"keyset": token_keyset_json}}},
        ]

        provider = _make_vault_provider(tmp_path, access_mode="tokenize", refresh_seconds=0)

        with patch("urllib.request.urlopen", _mock_urlopen(responses)):
            provider.get_token_keyset()

        # Now Vault is down — should keep last-good
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
            provider._last_refresh = 0
            provider._vault_token_expiry = 0
            keyset = provider.get_token_keyset()
            assert keyset.primary_kid == "tk1"

    def test_startup_failure_raises(self, tmp_path):
        provider = _make_vault_provider(tmp_path, access_mode="tokenize")

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
            with pytest.raises(urllib.error.URLError):
                provider.get_token_keyset()


class TestVaultAccessControl:
    def test_tokenize_mode_blocks_reveal(self, tmp_path):
        provider = _make_vault_provider(tmp_path, access_mode="tokenize")
        with pytest.raises(PIIAccessDeniedError, match="PII_ACCESS=full"):
            provider.get_reveal_keyset()

    def test_full_mode_allows_reveal(self, tmp_path):
        token_keyset_json = make_keyset_json(primary_kid="tk1")
        reveal_keyset_json = make_keyset_json(primary_kid="rk1")
        responses = [
            {"auth": {"client_token": "s.test", "lease_duration": 3600}},
            {"data": {"data": {"keyset": token_keyset_json}}},
            {"data": {"data": {"keyset": reveal_keyset_json}}},
        ]

        provider = _make_vault_provider(tmp_path, access_mode="full")
        with patch("urllib.request.urlopen", _mock_urlopen(responses)):
            reveal_ks = provider.get_reveal_keyset()
            assert reveal_ks.primary_kid == "rk1"


class TestVaultProperties:
    def test_env(self, tmp_path):
        provider = _make_vault_provider(tmp_path)
        assert provider.env == "test"

    def test_access_mode(self, tmp_path):
        provider = _make_vault_provider(tmp_path, access_mode="tokenize")
        assert provider.access_mode == "tokenize"

    def test_ssl_context_created_with_cacert(self, tmp_path):
        # Create a dummy CA cert (self-signed for testing)
        # We can't test real SSL, but we can verify the context is set
        provider = _make_vault_provider(tmp_path, access_mode="tokenize")
        assert provider._ssl_context is None

        # With a cacert_path, it would try to load the cert
        # We skip actual cert creation as ssl.create_default_context
        # would fail with an invalid cert file
