"""Cryptographic primitives for PII tokenization and encryption.

- HMAC-SHA-256: deterministic tokens for fraud correlation
- AES-256-GCM: randomized ciphertext for reversible encryption
"""

import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Versioned output prefixes
TOKEN_PREFIX = "ptok"
CIPHER_PREFIX = "penc"
TOKEN_VERSION = 1
CIPHER_VERSION = 1


def _derive_hmac_key(master_key: bytes, context: str) -> bytes:
    """Derive a context-specific HMAC key from the master key.

    context is typically "env|field_type", ensuring tokens are scoped.
    """
    return hmac.new(master_key, context.encode(), hashlib.sha256).digest()


def hmac_tokenize(
    value: str,
    key: bytes,
    field_type: str,
    env: str,
) -> str:
    """Produce a deterministic token: ptok:v1:<base64url-hmac>.

    Same input + same key + same context = same output.
    """
    derived = _derive_hmac_key(key, f"{env}|{field_type}")
    mac = hmac.new(derived, value.encode(), hashlib.sha256).digest()
    encoded = base64.urlsafe_b64encode(mac).rstrip(b"=").decode()
    return f"{TOKEN_PREFIX}:v{TOKEN_VERSION}:{encoded}"


def aes_protect(
    value: str,
    key: bytes,
    field_type: str,
    env: str,
    *,
    kid: str,
) -> str:
    """Encrypt with AES-256-GCM: penc:v1:<kid>:<base64url(nonce+ct+tag)>.

    Each call produces different ciphertext (random nonce).
    AAD includes env and field_type for domain separation.
    kid is embedded so reveal() can find the right key after rotation.
    """
    aad = f"{env}|{field_type}".encode()
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, value.encode(), aad)
    # nonce (12) + ciphertext + tag (16) packed together
    payload = nonce + ct
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    return f"{CIPHER_PREFIX}:v{CIPHER_VERSION}:{kid}:{encoded}"


def _b64_pad(s: str) -> str:
    """Re-add base64 padding."""
    return s + "=" * (-len(s) % 4)


def parse_penc_kid(ciphertext: str) -> str:
    """Extract the kid from a penc:vN:<kid>:<payload> string."""
    parts = ciphertext.split(":", 3)
    if len(parts) != 4 or parts[0] != CIPHER_PREFIX:
        raise ValueError(f"Not a valid encrypted value: {ciphertext[:20]}...")
    return parts[2]


def aes_reveal(
    ciphertext: str,
    key: bytes,
    field_type: str,
    env: str,
) -> str:
    """Decrypt a penc:vN:<kid>:<payload> value back to plaintext."""
    parts = ciphertext.split(":", 3)
    if len(parts) != 4 or parts[0] != CIPHER_PREFIX:
        raise ValueError(f"Not a valid encrypted value: {ciphertext[:20]}...")

    payload = base64.urlsafe_b64decode(_b64_pad(parts[3]))
    nonce = payload[:12]
    ct = payload[12:]
    aad = f"{env}|{field_type}".encode()
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, aad).decode()
