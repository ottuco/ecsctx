"""Shared fixtures for PII tests."""

import base64
import json
import os

import pytest

from ecsctx.pii import _reset as _reset_pii
from ecsctx.processors import _reset_masking, _reset_root_fields


def _make_key_b64(length: int = 32) -> str:
    """Generate a random key and return as URL-safe base64 (no padding)."""
    return base64.urlsafe_b64encode(os.urandom(length)).rstrip(b"=").decode()


def make_keyset_json(
    *,
    primary_kid: str = "k1",
    kids: list[str] | None = None,
    alg: str = "HMAC-SHA-256",
) -> str:
    """Build a keyset JSON string with random keys."""
    if kids is None:
        kids = [primary_kid]
    keys = {}
    for kid in kids:
        keys[kid] = {
            "alg": alg,
            "created_at": "2025-01-01T00:00:00Z",
            "key_b64": _make_key_b64(),
        }
    return json.dumps({
        "schema_version": 1,
        "primary_kid": primary_kid,
        "keys": keys,
    })


@pytest.fixture()
def token_keyset_path(tmp_path):
    """Write a token keyset file and return its path."""
    path = tmp_path / "token-keyset.json"
    path.write_text(make_keyset_json(primary_kid="tk1"))
    return str(path)


@pytest.fixture()
def reveal_keyset_path(tmp_path):
    """Write a reveal keyset file and return its path."""
    path = tmp_path / "reveal-keyset.json"
    path.write_text(make_keyset_json(primary_kid="rk1", alg="AES-256-GCM"))
    return str(path)


@pytest.fixture()
def token_keyset_json():
    """Return a token keyset JSON string."""
    return make_keyset_json(primary_kid="tk1")


@pytest.fixture()
def reveal_keyset_json():
    """Return a reveal keyset JSON string."""
    return make_keyset_json(primary_kid="rk1", alg="AES-256-GCM")


@pytest.fixture(autouse=True)
def _reset_pii_module():
    """Reset PII module state between tests."""
    yield
    _reset_pii()


@pytest.fixture(autouse=True)
def _reset_masking_module():
    """Reset masking exemption config between tests."""
    yield
    _reset_masking()


@pytest.fixture(autouse=True)
def _reset_root_fields_module():
    """Reset configurable root-fields state between tests."""
    yield
    _reset_root_fields()
