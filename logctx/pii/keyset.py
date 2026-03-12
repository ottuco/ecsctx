"""Keyset loading and hot-reload provider.

A keyset is a JSON document stored in Vault and delivered to pods as a
mounted file by ESO.  Structure::

    {
        "schema_version": 1,
        "primary_kid": "tk1",
        "keys": {
            "tk1": {"alg": "HMAC-SHA-256", "created_at": "...", "key_b64": "..."},
            "tk2": {"alg": "HMAC-SHA-256", "created_at": "...", "key_b64": "..."}
        }
    }
"""

import base64
import json
import os
import threading
import time
from dataclasses import dataclass, field


@dataclass(frozen=True)
class KeyEntry:
    kid: str
    alg: str
    key: bytes
    created_at: str = ""


@dataclass(frozen=True)
class Keyset:
    schema_version: int
    primary_kid: str
    keys: dict[str, KeyEntry]

    @property
    def primary_key(self) -> KeyEntry:
        return self.keys[self.primary_kid]


def parse_keyset(raw: str) -> Keyset:
    """Parse a JSON keyset document into a Keyset object."""
    doc = json.loads(raw)
    keys = {}
    for kid, entry in doc["keys"].items():
        key_bytes = base64.urlsafe_b64decode(entry["key_b64"] + "==")
        keys[kid] = KeyEntry(
            kid=kid,
            alg=entry["alg"],
            key=key_bytes,
            created_at=entry.get("created_at", ""),
        )
    return Keyset(
        schema_version=doc["schema_version"],
        primary_kid=doc["primary_kid"],
        keys=keys,
    )


@dataclass
class FileKeysetProvider:
    """Reads keysets from mounted files with mtime-based hot reload.

    Args:
        token_keyset_path: Path to the token keyset JSON file.
        reveal_keyset_path: Path to the reveal keyset JSON file, or None
            for tokenize-only access.
        env: Environment name (e.g., "dev", "prod"). Included in HMAC/AAD
            context to prevent cross-env token collisions.
        stale_seconds: How often to check file mtime for changes.
    """

    token_keyset_path: str
    reveal_keyset_path: str | None
    env: str
    stale_seconds: float = 10.0

    _token_keyset: Keyset | None = field(default=None, init=False, repr=False)
    _reveal_keyset: Keyset | None = field(default=None, init=False, repr=False)
    _token_mtime: float = field(default=0.0, init=False, repr=False)
    _reveal_mtime: float = field(default=0.0, init=False, repr=False)
    _last_check: float = field(default=0.0, init=False, repr=False)
    _lock: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False
    )

    def _maybe_reload(self) -> None:
        now = time.monotonic()
        if (
            now - self._last_check < self.stale_seconds
            and self._token_keyset is not None
        ):
            return

        with self._lock:
            # Double-check after acquiring lock
            if (
                now - self._last_check < self.stale_seconds
                and self._token_keyset is not None
            ):
                return
            self._last_check = now

            token_mtime = os.path.getmtime(self.token_keyset_path)
            if token_mtime != self._token_mtime or self._token_keyset is None:
                with open(self.token_keyset_path) as f:
                    self._token_keyset = parse_keyset(f.read())
                self._token_mtime = token_mtime

            if self.reveal_keyset_path:
                reveal_mtime = os.path.getmtime(self.reveal_keyset_path)
                if reveal_mtime != self._reveal_mtime or self._reveal_keyset is None:
                    with open(self.reveal_keyset_path) as f:
                        self._reveal_keyset = parse_keyset(f.read())
                    self._reveal_mtime = reveal_mtime

    def get_token_keyset(self) -> Keyset:
        self._maybe_reload()
        if self._token_keyset is None:
            raise RuntimeError(
                f"Failed to load token keyset from {self.token_keyset_path}"
            )
        return self._token_keyset

    def get_reveal_keyset(self) -> Keyset:
        if self.reveal_keyset_path is None:
            raise RuntimeError(
                "Reveal keyset not configured. This provider has tokenize-only access."
            )
        self._maybe_reload()
        if self._reveal_keyset is None:
            raise RuntimeError(
                f"Failed to load reveal keyset from {self.reveal_keyset_path}"
            )
        return self._reveal_keyset
