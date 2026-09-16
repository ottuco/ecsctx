"""Shared ``crypto.*`` domain: decryption, credentials, key events.

Transcribed from ticket #159487 (Event catalogue, ``crypto`` table).
``credential_resolved`` keeps base level ``info`` (the ticket's
otherwise-case); a cache hit overrides the level at the call site
(``emit(..., level="debug")``), because outcome alone cannot distinguish them.
"""

from ecsctx.events.spec import EventSpec

CRYPTO_PAYLOAD_DECRYPTED = EventSpec(
    action="crypto.payload_decrypted",
    terminal=True,
    required=("event.outcome", "labels.cipher"),
)

CRYPTO_CREDENTIAL_RESOLVED = EventSpec(
    action="crypto.credential_resolved",
    terminal=True,
    required=("event.outcome", "labels.credential_kind", "labels.source"),
)

CRYPTO_CREDENTIAL_ROTATED = EventSpec(
    action="crypto.credential_rotated",
    terminal=True,
    required=("event.outcome", "labels.credential_kind", "labels.version"),
)

CRYPTO_TOKENIZATION_UNAVAILABLE = EventSpec(
    action="crypto.tokenization_unavailable",
    level="error",
    terminal=True,
    required=("event.outcome", "error.type", "labels.pii_provider"),
)

SPECS: tuple[EventSpec, ...] = (
    CRYPTO_PAYLOAD_DECRYPTED,
    CRYPTO_CREDENTIAL_RESOLVED,
    CRYPTO_CREDENTIAL_ROTATED,
    CRYPTO_TOKENIZATION_UNAVAILABLE,
)
