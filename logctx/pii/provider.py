"""Abstract keyset provider interface for PII operations."""

from abc import ABC, abstractmethod

from logctx.pii.keyset import Keyset


class KeysetProvider(ABC):
    """Base class for keyset providers.

    Providers fetch and cache token/reveal keysets from a backing store
    (mounted files, Vault, etc.) and enforce access mode restrictions.
    """

    @property
    @abstractmethod
    def env(self) -> str:
        """Environment name (e.g. 'dev', 'prod') used in HMAC/AAD context."""
        ...

    @property
    @abstractmethod
    def access_mode(self) -> str:
        """Return 'tokenize' or 'full'."""
        ...

    @abstractmethod
    def get_token_keyset(self) -> Keyset:
        """Return the current token keyset, refreshing if stale."""
        ...

    @abstractmethod
    def get_reveal_keyset(self) -> Keyset:
        """Return the current reveal keyset, refreshing if stale.

        Raises PIIAccessDeniedError if access_mode is 'tokenize'.
        """
        ...

    @abstractmethod
    def refresh_if_needed(self) -> None:
        """Check and reload keysets if stale. Called lazily."""
        ...
