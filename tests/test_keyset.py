"""Tests for keyset parsing and FileKeysetProvider."""

import json
import os
import time

import pytest

from ecsctx.pii import PIIAccessDeniedError
from ecsctx.pii.keyset import FileKeysetProvider, Keyset, parse_keyset
from tests.conftest import make_keyset_json


class TestParseKeyset:
    def test_valid_keyset(self, token_keyset_json):
        keyset = parse_keyset(token_keyset_json)
        assert isinstance(keyset, Keyset)
        assert keyset.schema_version == 1
        assert keyset.primary_kid == "tk1"
        assert "tk1" in keyset.keys
        assert len(keyset.primary_key.key) == 32

    def test_multiple_keys(self):
        raw = make_keyset_json(primary_kid="k1", kids=["k1", "k2"])
        keyset = parse_keyset(raw)
        assert len(keyset.keys) == 2
        assert keyset.primary_kid == "k1"
        assert "k2" in keyset.keys

    def test_invalid_json(self):
        with pytest.raises(json.JSONDecodeError):
            parse_keyset("not json")

    def test_missing_keys_field(self):
        with pytest.raises(KeyError):
            parse_keyset('{"schema_version": 1, "primary_kid": "k1"}')


class TestFileKeysetProvider:
    def test_loads_token_keyset(self, token_keyset_path):
        provider = FileKeysetProvider(
            token_keyset_path=token_keyset_path,
            reveal_keyset_path=None,
            env="test",
        )
        keyset = provider.get_token_keyset()
        assert keyset.primary_kid == "tk1"

    def test_loads_both_keysets(self, token_keyset_path, reveal_keyset_path):
        provider = FileKeysetProvider(
            token_keyset_path=token_keyset_path,
            reveal_keyset_path=reveal_keyset_path,
            env="test",
        )
        token_ks = provider.get_token_keyset()
        reveal_ks = provider.get_reveal_keyset()
        assert token_ks.primary_kid == "tk1"
        assert reveal_ks.primary_kid == "rk1"

    def test_access_mode_tokenize(self, token_keyset_path):
        provider = FileKeysetProvider(
            token_keyset_path=token_keyset_path,
            reveal_keyset_path=None,
            env="test",
        )
        assert provider.access_mode == "tokenize"

    def test_access_mode_full(self, token_keyset_path, reveal_keyset_path):
        provider = FileKeysetProvider(
            token_keyset_path=token_keyset_path,
            reveal_keyset_path=reveal_keyset_path,
            env="test",
        )
        assert provider.access_mode == "full"

    def test_reveal_denied_in_tokenize_mode(self, token_keyset_path):
        provider = FileKeysetProvider(
            token_keyset_path=token_keyset_path,
            reveal_keyset_path=None,
            env="test",
        )
        with pytest.raises(PIIAccessDeniedError, match="PII_ACCESS=full"):
            provider.get_reveal_keyset()

    def test_hot_reload(self, tmp_path):
        path = tmp_path / "keyset.json"
        path.write_text(make_keyset_json(primary_kid="v1"))

        provider = FileKeysetProvider(
            token_keyset_path=str(path),
            reveal_keyset_path=None,
            env="test",
            stale_seconds=0,  # always check
        )
        assert provider.get_token_keyset().primary_kid == "v1"

        # Write new keyset with different primary_kid
        path.write_text(make_keyset_json(primary_kid="v2"))
        # Force mtime change (some filesystems have 1s resolution)
        os.utime(str(path), (time.time() + 1, time.time() + 1))

        keyset = provider.get_token_keyset()
        assert keyset.primary_kid == "v2"

    def test_env_property(self, token_keyset_path):
        provider = FileKeysetProvider(
            token_keyset_path=token_keyset_path,
            reveal_keyset_path=None,
            env="staging",
        )
        assert provider.env == "staging"
