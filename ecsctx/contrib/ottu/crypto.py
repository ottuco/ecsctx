"""Shared ``crypto.*`` domain: decryption, credentials, key events.

Transcribed from ticket #159487 (Event catalogue, ``crypto`` table).
``credential_resolved`` is ``debug``: it fires on every credential lookup,
cache hits included; a failed resolution logs at error.
"""

from ecsctx.events.spec import EventSpec

CRYPTO_PAYLOAD_DECRYPTED = EventSpec(
    action="crypto.payload_decrypted",
    terminal=True,
    type=("info",),
    required=("event.outcome", "labels.cipher"),
)

CRYPTO_CREDENTIAL_RESOLVED = EventSpec(
    action="crypto.credential_resolved",
    level="debug",
    terminal=True,
    type=("end",),
    required=("event.outcome", "labels.credential_kind", "labels.source"),
)

CRYPTO_CREDENTIAL_ROTATED = EventSpec(
    action="crypto.credential_rotated",
    terminal=True,
    type=("change",),
    required=("event.outcome", "labels.credential_kind", "labels.version"),
)

CRYPTO_TOKENIZATION_UNAVAILABLE = EventSpec(
    action="crypto.tokenization_unavailable",
    level="error",
    terminal=True,
    type=("error",),
    required=("event.outcome", "error.type", "labels.pii_provider"),
)

SPECS: tuple[EventSpec, ...] = (
    CRYPTO_PAYLOAD_DECRYPTED,
    CRYPTO_CREDENTIAL_RESOLVED,
    CRYPTO_CREDENTIAL_ROTATED,
    CRYPTO_TOKENIZATION_UNAVAILABLE,
)
