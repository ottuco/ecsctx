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


@pytest.fixture
def logging_state():
    """Snapshot and restore process-wide logging state.

    Logging is a module-level singleton nothing resets between tests, so any
    test that installs/removes filters across live handlers, or adds loggers,
    must put the tree back the way it found it.
    """
    import logging

    manager = logging.Logger.manager
    known_names = set(manager.loggerDict)
    loggers = [logging.root] + [
        lg for lg in manager.loggerDict.values() if isinstance(lg, logging.Logger)
    ]
    saved_handlers = [(lg, list(lg.handlers)) for lg in loggers]
    saved_filters = {}
    for lg in loggers:
        for handler in lg.handlers:
            saved_filters.setdefault(id(handler), (handler, list(handler.filters)))

    yield

    for name in list(manager.loggerDict):
        if name not in known_names:
            del manager.loggerDict[name]
    for logger, handlers in saved_handlers:
        logger.handlers = list(handlers)
    for handler, filters in saved_filters.values():
        handler.filters = list(filters)


@pytest.fixture
def isolated_logging_tree(logging_state):
    """An empty logging tree for the duration of the test.

    Builds on logging_state for the restore, then clears every logger and
    root's handlers, so a test asserting on the whole tree sees only what it
    put there — pytest and Django both leave real loggers behind otherwise.
    """
    import logging

    logging.Logger.manager.loggerDict.clear()
    logging.root.handlers = []
    yield
