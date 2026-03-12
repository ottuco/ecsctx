"""Vault AppRole keyset provider.

Authenticates to HashiCorp Vault using AppRole and fetches PII keysets
from KV v2 secrets. Caches keysets in memory and refreshes on a timer.
Falls back to last-good keysets if Vault is temporarily unavailable
after initial startup.
"""

from __future__ import annotations

import json
import logging
import ssl
import threading
import time
import urllib.error
import urllib.request

from ecsctx.pii.keyset import Keyset, parse_keyset

logger = logging.getLogger(__name__)


class VaultKeysetProvider:
    """Fetches keysets from Vault KV v2 via AppRole authentication.

    Args:
        vault_addr: Vault server URL (e.g. "https://vault.example.com").
        role_id_path: File path containing the AppRole role_id.
        secret_id_path: File path containing the AppRole secret_id.
        token_keyset_mount_path: Vault KV path for token keyset
            (e.g. "secret/data/platform/pii/token-keyset").
        reveal_keyset_mount_path: Vault KV path for reveal keyset, or None
            for tokenize-only access.
        cacert_path: Path to CA certificate for Vault TLS, or None for
            system default trust store.
        env: Environment name for HMAC/AAD context.
        access_mode: "tokenize" or "full".
        refresh_seconds: How often to re-fetch keysets from Vault.
        timeout: HTTP request timeout in seconds for Vault calls.
    """

    def __init__(
        self,
        *,
        vault_addr: str,
        role_id_path: str,
        secret_id_path: str,
        token_keyset_mount_path: str,
        reveal_keyset_mount_path: str | None = None,
        cacert_path: str | None = None,
        env: str,
        access_mode: str = "tokenize",
        refresh_seconds: float = 300.0,
        timeout: float = 10.0,
    ) -> None:
        self._vault_addr = vault_addr.rstrip("/")
        self._role_id_path = role_id_path
        self._secret_id_path = secret_id_path
        self._token_keyset_mount_path = token_keyset_mount_path
        self._reveal_keyset_mount_path = reveal_keyset_mount_path
        self._env = env
        self._access_mode = access_mode
        self._refresh_seconds = refresh_seconds
        self._timeout = timeout

        # SSL context
        self._ssl_context: ssl.SSLContext | None = None
        if cacert_path:
            self._ssl_context = ssl.create_default_context(cafile=cacert_path)

        # Vault token state
        self._vault_token: str | None = None
        self._vault_token_expiry: float = 0.0

        # Cached keysets
        self._token_keyset: Keyset | None = None
        self._reveal_keyset: Keyset | None = None
        self._last_refresh: float = 0.0

        self._lock = threading.Lock()

    @property
    def env(self) -> str:
        return self._env

    @property
    def access_mode(self) -> str:
        return self._access_mode

    def _read_file(self, path: str) -> str:
        """Read and strip a credential file."""
        with open(path) as f:
            return f.read().strip()

    def _vault_request(
        self,
        method: str,
        path: str,
        data: dict | None = None,
        token: str | None = None,
    ) -> dict:
        """Make an HTTP request to Vault and return parsed JSON."""
        url = f"{self._vault_addr}/v1/{path}"
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(
            url,
            data=body,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        if token:
            req.add_header("X-Vault-Token", token)

        response = urllib.request.urlopen(
            req, timeout=self._timeout, context=self._ssl_context
        )
        return json.loads(response.read().decode())

    def _authenticate(self) -> None:
        """Authenticate to Vault via AppRole and cache the token."""
        role_id = self._read_file(self._role_id_path)
        secret_id = self._read_file(self._secret_id_path)

        result = self._vault_request(
            "POST",
            "auth/approle/login",
            data={"role_id": role_id, "secret_id": secret_id},
        )

        auth = result["auth"]
        self._vault_token = auth["client_token"]
        lease_duration = auth.get("lease_duration", 3600)
        # Renew 60s before expiry to avoid using an expired token
        self._vault_token_expiry = time.monotonic() + max(lease_duration - 60, 60)

    def _fetch_keyset(self, mount_path: str) -> Keyset:
        """Fetch a keyset from Vault KV v2."""
        result = self._vault_request("GET", mount_path, token=self._vault_token)
        keyset_json = result["data"]["data"]["keyset"]
        return parse_keyset(keyset_json)

    def _is_token_expired(self) -> bool:
        return (
            self._vault_token is None
            or time.monotonic() >= self._vault_token_expiry
        )

    def refresh_if_needed(self) -> None:
        """Re-authenticate and re-fetch keysets if stale.

        After initial startup, failures are logged and last-good keysets
        are kept. At startup (no keysets loaded yet), failures propagate.
        """
        now = time.monotonic()
        if (
            now - self._last_refresh < self._refresh_seconds
            and self._token_keyset is not None
        ):
            return

        with self._lock:
            # Double-check after acquiring lock
            if (
                now - self._last_refresh < self._refresh_seconds
                and self._token_keyset is not None
            ):
                return

            has_keysets = self._token_keyset is not None

            try:
                if self._is_token_expired():
                    self._authenticate()

                self._token_keyset = self._fetch_keyset(
                    self._token_keyset_mount_path
                )

                if (
                    self._access_mode == "full"
                    and self._reveal_keyset_mount_path
                ):
                    self._reveal_keyset = self._fetch_keyset(
                        self._reveal_keyset_mount_path
                    )

                self._last_refresh = time.monotonic()

            except Exception:
                if has_keysets:
                    # After startup: keep last-good keysets
                    logger.warning(
                        "Vault keyset refresh failed, using cached keysets",
                        exc_info=True,
                    )
                    self._last_refresh = time.monotonic()
                else:
                    # At startup: propagate the error
                    raise

    def get_token_keyset(self) -> Keyset:
        self.refresh_if_needed()
        if self._token_keyset is None:
            raise RuntimeError("Token keyset not loaded from Vault.")
        return self._token_keyset

    def get_reveal_keyset(self) -> Keyset:
        if self._access_mode == "tokenize":
            from ecsctx.pii import PIIAccessDeniedError  # noqa: PLC0415 - Delayed import to prevent circular dependency with ecsctx.pii.__init__

            raise PIIAccessDeniedError(
                "Reveal keyset not available. "
                "Set PII_ACCESS=full to enable reveal operations."
            )
        self.refresh_if_needed()
        if self._reveal_keyset is None:
            raise RuntimeError("Reveal keyset not loaded from Vault.")
        return self._reveal_keyset
