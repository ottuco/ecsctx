"""PII tokenization and encryption module.

Provides deterministic HMAC-based tokens for fraud correlation and
AES-256-GCM encryption for reversible PII protection.

Usage::

    from logctx.pii import configure_pii, tokenize, protect, reveal

    # Auto-configure from env vars (PII_PROVIDER, PII_ACCESS, PII_ENV)
    configure_pii_from_env()

    # Or explicit file-based configuration (backward compatible)
    configure_pii(token_keyset_path="/path/to/token-keyset.json")

    # Deterministic token for correlation
    token = tokenize("user@example.com", "email")

    # Reversible encryption (requires PII_ACCESS=full)
    ciphertext = protect("user@example.com", "email")
    plaintext = reveal(ciphertext, "email")
"""

from __future__ import annotations

import os

from logctx.pii.crypto import aes_protect, aes_reveal, hmac_tokenize, parse_penc_kid
from logctx.pii.keyset import FileKeysetProvider
from logctx.pii.normalize import normalize_value
from logctx.pii.provider import KeysetProvider

_provider: KeysetProvider | None = None
_auto_configure_attempted: bool = False


class PIINotConfiguredError(RuntimeError):
    """Raised when PII operations are attempted without a configured provider."""


class PIIAccessDeniedError(RuntimeError):
    """Raised when an operation is blocked by access mode restrictions."""


def configure_pii(
    *,
    token_keyset_path: str | None = None,
    reveal_keyset_path: str | None = None,
    env: str | None = None,
    stale_seconds: float = 10.0,
) -> None:
    """Configure the PII module with a file-based provider.

    If paths are not provided, reads from environment variables:
    - PII_TOKEN_KEYSET_PATH (required)
    - PII_REVEAL_KEYSET_PATH (optional, for full access)
    - PII_ENV (defaults to "unknown")

    This is the legacy configuration API. Prefer configure_pii_from_env()
    for new deployments.
    """
    global _provider

    token_path = token_keyset_path or os.environ.get("PII_TOKEN_KEYSET_PATH")
    if not token_path:
        raise PIINotConfiguredError(
            "PII_TOKEN_KEYSET_PATH not set and no token_keyset_path provided."
        )

    reveal_path = reveal_keyset_path or os.environ.get("PII_REVEAL_KEYSET_PATH")
    pii_env = env or os.environ.get("PII_ENV", "unknown")

    _provider = FileKeysetProvider(
        token_keyset_path=token_path,
        reveal_keyset_path=reveal_path,
        env=pii_env,
        stale_seconds=stale_seconds,
    )


def configure_pii_from_env() -> None:
    """Auto-configure PII from environment variables.

    Reads PII_PROVIDER (file|vault), PII_ACCESS (tokenize|full), PII_ENV
    and provider-specific variables. Idempotent: only runs once.

    For file provider:
        PII_TOKEN_KEYSET_PATH, PII_REVEAL_KEYSET_PATH

    For vault provider:
        PII_VAULT_ADDR, PII_VAULT_ROLE_ID_PATH, PII_VAULT_SECRET_ID_PATH,
        PII_VAULT_TOKEN_KEYSET_PATH, PII_VAULT_REVEAL_KEYSET_PATH,
        PII_VAULT_CACERT_PATH, PII_REFRESH_SECONDS
    """
    global _provider, _auto_configure_attempted
    if _auto_configure_attempted or _provider is not None:
        return
    _auto_configure_attempted = True

    provider_type = os.environ.get("PII_PROVIDER", "").lower()
    if not provider_type:
        # Backward compat: infer file provider from legacy env var
        if os.environ.get("PII_TOKEN_KEYSET_PATH"):
            provider_type = "file"
        else:
            return  # No PII config, stay unconfigured

    access_mode = os.environ.get("PII_ACCESS", "tokenize")
    pii_env = os.environ.get("PII_ENV", "unknown")

    if provider_type == "file":
        token_path = os.environ.get("PII_TOKEN_KEYSET_PATH")
        if not token_path:
            raise PIINotConfiguredError(
                "PII_PROVIDER=file requires PII_TOKEN_KEYSET_PATH."
            )
        reveal_path = (
            os.environ.get("PII_REVEAL_KEYSET_PATH")
            if access_mode == "full"
            else None
        )
        _provider = FileKeysetProvider(
            token_keyset_path=token_path,
            reveal_keyset_path=reveal_path,
            env=pii_env,
        )
    elif provider_type == "vault":
        from logctx.pii.vault import VaultKeysetProvider  # noqa: PLC0415 - Conditional import; vault deps are optional and only loaded when PII_PROVIDER=vault

        _provider = VaultKeysetProvider(
            vault_addr=os.environ["PII_VAULT_ADDR"],
            role_id_path=os.environ["PII_VAULT_ROLE_ID_PATH"],
            secret_id_path=os.environ["PII_VAULT_SECRET_ID_PATH"],
            token_keyset_mount_path=os.environ["PII_VAULT_TOKEN_KEYSET_PATH"],
            reveal_keyset_mount_path=(
                os.environ.get("PII_VAULT_REVEAL_KEYSET_PATH")
                if access_mode == "full"
                else None
            ),
            cacert_path=os.environ.get("PII_VAULT_CACERT_PATH"),
            env=pii_env,
            access_mode=access_mode,
            refresh_seconds=float(os.environ.get("PII_REFRESH_SECONDS", "300")),
            timeout=float(os.environ.get("PII_VAULT_TIMEOUT", "10")),
        )
    else:
        raise PIINotConfiguredError(f"Unknown PII_PROVIDER: {provider_type!r}")


def _ensure_configured() -> KeysetProvider:
    if _provider is None:
        configure_pii_from_env()
    if _provider is None:
        raise PIINotConfiguredError(
            "PII module not configured. "
            "Set PII_PROVIDER and related env vars, or call configure_pii()."
        )
    return _provider


def is_configured() -> bool:
    """Check if the PII module has been configured."""
    return _provider is not None


def tokenize(value: str, field_type: str = "generic") -> str:
    """Produce a deterministic HMAC token for fraud correlation.

    Same input + same key + same env = same token.
    """
    provider = _ensure_configured()
    normalized = normalize_value(value, field_type)
    keyset = provider.get_token_keyset()
    return hmac_tokenize(
        normalized,
        keyset.primary_key.key,
        field_type,
        provider.env,
    )


def protect(value: str, field_type: str = "generic") -> str:
    """Encrypt a value with AES-256-GCM. Requires PII_ACCESS=full."""
    provider = _ensure_configured()
    if provider.access_mode == "tokenize":
        raise PIIAccessDeniedError(
            "protect() requires PII_ACCESS=full. "
            "Current access mode is 'tokenize'."
        )
    keyset = provider.get_reveal_keyset()
    return aes_protect(
        value,
        keyset.primary_key.key,
        field_type,
        provider.env,
        kid=keyset.primary_kid,
    )


def reveal(ciphertext: str, field_type: str = "generic") -> str:
    """Decrypt a penc:vN:<kid>:<payload> value. Requires PII_ACCESS=full."""
    provider = _ensure_configured()
    if provider.access_mode == "tokenize":
        raise PIIAccessDeniedError(
            "reveal() requires PII_ACCESS=full. "
            "Current access mode is 'tokenize'."
        )
    keyset = provider.get_reveal_keyset()
    kid = parse_penc_kid(ciphertext)
    if kid not in keyset.keys:
        raise ValueError(
            f"Unknown key id '{kid}' in ciphertext. "
            f"Available: {list(keyset.keys)}"
        )
    key_entry = keyset.keys[kid]
    return aes_reveal(
        ciphertext,
        key_entry.key,
        field_type,
        provider.env,
    )


def _reset() -> None:
    """Reset module state. For testing only."""
    global _provider, _auto_configure_attempted
    _provider = None
    _auto_configure_attempted = False


__all__ = [
    "configure_pii",
    "configure_pii_from_env",
    "is_configured",
    "tokenize",
    "protect",
    "reveal",
    "PIINotConfiguredError",
    "PIIAccessDeniedError",
]
