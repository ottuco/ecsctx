"""PII tokenization and encryption module.

Provides deterministic HMAC-based tokens for fraud correlation and
AES-256-GCM encryption for reversible PII protection.

Usage::

    from logctx.pii import configure_pii, tokenize, protect, reveal

    # Auto-configure from env vars (PII_TOKEN_KEYSET_PATH, PII_REVEAL_KEYSET_PATH)
    configure_pii()

    # Deterministic token for correlation
    token = tokenize("user@example.com", "email")

    # Reversible encryption (requires reveal keyset)
    ciphertext = protect("user@example.com", "email")
    plaintext = reveal(ciphertext, "email")
"""

import os

from logctx.pii.crypto import aes_protect, aes_reveal, hmac_tokenize
from logctx.pii.keyset import FileKeysetProvider
from logctx.pii.normalize import normalize_value

_provider: FileKeysetProvider | None = None


class PIINotConfiguredError(RuntimeError):
    """Raised when PII operations are attempted without a configured provider."""


def configure_pii(
    *,
    token_keyset_path: str | None = None,
    reveal_keyset_path: str | None = None,
    env: str | None = None,
    stale_seconds: float = 10.0,
) -> None:
    """Configure the PII module.

    If paths are not provided, reads from environment variables:
    - PII_TOKEN_KEYSET_PATH (required)
    - PII_REVEAL_KEYSET_PATH (optional, for full access)
    - PII_ENV (defaults to "unknown")
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


def _ensure_configured() -> FileKeysetProvider:
    if _provider is None:
        raise PIINotConfiguredError(
            "PII module not configured. "
            "Call configure_pii() or set PII_TOKEN_KEYSET_PATH."
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
    """Encrypt a value with AES-256-GCM. Requires reveal keyset."""
    provider = _ensure_configured()
    keyset = provider.get_reveal_keyset()
    return aes_protect(
        value,
        keyset.primary_key.key,
        field_type,
        provider.env,
    )


def reveal(ciphertext: str, field_type: str = "generic") -> str:
    """Decrypt a penc:vN:... value. Requires reveal keyset."""
    provider = _ensure_configured()
    keyset = provider.get_reveal_keyset()
    return aes_reveal(
        ciphertext,
        keyset.primary_key.key,
        field_type,
        provider.env,
    )


__all__ = [
    "configure_pii",
    "is_configured",
    "tokenize",
    "protect",
    "reveal",
    "PIINotConfiguredError",
]
