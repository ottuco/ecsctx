"""
Logging context management using contextvars for thread-safe, async-compatible context propagation.

This module provides:
- LoggingContext: Dataclass holding logging context (span_id, user_id, ip, etc.)
- Context variable management: get/set/reset functions
- logging_context: Context manager for setting context within a scope

ECS Field Mapping:
    Internal attributes are mapped to ECS-compliant output keys in to_dict():
    - span_id → span.id
    - user_id → user.id
    - ip → client.ip
    - session_id/orn/reference_number → payment.* namespace
    - pg_code → pg_code (flat)

    See: https://www.elastic.co/docs/reference/ecs/ecs-field-reference
"""

import contextlib
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from typing import Any

from cid.locals import get_cid


@dataclass(frozen=False)
class LoggingContext:
    """
    Logging context data aligned with ECS/OpenTelemetry standards.

    Internal attribute names are developer-friendly. The to_dict() method
    maps them to ECS-compliant output keys for Elasticsearch.

    Attributes:
        span_id: Unique ID for this request (UUID) → span.id
        user_id: Authenticated user ID → user.id
        ip: Client IP address → client.ip
        session_id: Payment session identifier → payment.session_id
        orn: Object Reference Number (audit log correlation) → payment.orn
        pg_code: Payment gateway code (e.g., "knet", "mpgs") → pg_code
        reference_number: Transaction reference number → payment.reference
        extra: Additional context data (merged into root)
    """

    # ECS Core Identity
    span_id: str | None = None
    user_id: int | None = None
    ip: str | None = None

    # Payment Domain (custom namespace)
    session_id: str | None = None
    orn: str | None = None
    pg_code: str | None = None
    reference_number: str | None = None

    # Extension point
    extra: dict = field(default_factory=dict)

    def merge(self, **kwargs) -> "LoggingContext":
        """
        Create a new context with merged values.

        Non-None kwargs override current values. This allows context stacking
        where inner contexts can override specific fields while inheriting others.

        Args:
            **kwargs: Fields to override in the new context

        Returns:
            New LoggingContext with merged values
        """
        new_extra = {**self.extra, **kwargs.pop("extra", {})}

        current_values = {
            "span_id": self.span_id,
            "user_id": self.user_id,
            "ip": self.ip,
            "session_id": self.session_id,
            "orn": self.orn,
            "pg_code": self.pg_code,
            "reference_number": self.reference_number,
            "extra": new_extra,
        }

        for key, value in kwargs.items():
            if value is not None and key in current_values:
                current_values[key] = value

        return LoggingContext(**current_values)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert context to ECS-compliant dictionary for logging.

        Maps internal attributes to ECS field names:
        - span.id
        - user.id
        - client.ip
        - payment.session_id, payment.orn, payment.reference
        - pg_code (flat)

        Returns:
            Dictionary with nested ECS-compliant keys
        """
        result: dict[str, Any] = {}

        # ECS standard fields
        if self.span_id is not None:
            result["span"] = {"id": self.span_id}

        if self.user_id is not None:
            result["user"] = {"id": self.user_id}

        if self.ip is not None:
            result["client"] = {"ip": self.ip}

        # Build payment.* namespace
        payment_obj: dict[str, Any] = {}
        if self.session_id is not None:
            payment_obj["session_id"] = self.session_id
        if self.orn is not None:
            payment_obj["orn"] = self.orn
        if self.reference_number is not None:
            payment_obj["reference"] = self.reference_number
        if payment_obj:
            result["payment"] = payment_obj

        # Flat fields
        if self.pg_code is not None:
            result["pg_code"] = self.pg_code

        # Merge extra into root
        if self.extra:
            result.update(self.extra)

        return result


# Context variable for the current logging context
_logging_context: ContextVar[LoggingContext | None] = ContextVar(
    "logging_context", default=None
)


def get_logging_context() -> LoggingContext:
    """Get the current logging context from contextvars."""
    ctx = _logging_context.get()
    return ctx if ctx is not None else LoggingContext()


def set_logging_context(ctx: LoggingContext) -> Token:
    """
    Set the logging context, returning a token for reset.

    Args:
        ctx: The new logging context to set

    Returns:
        Token that can be used with reset_logging_context() to restore previous state
    """
    return _logging_context.set(ctx)


def reset_logging_context(token: Token) -> None:
    """
    Reset the logging context to a previous state.

    Args:
        token: Token returned from set_logging_context()
    """
    # Token was created in a different context (async boundary crossed)
    # or token was already used (e.g., process_exception before process_response)
    # Context will "leak" but better than crashing
    with contextlib.suppress(ValueError, RuntimeError):
        _logging_context.reset(token)


class logging_context:  # noqa: N801 - lowercase for context manager consistency with stdlib (e.g., contextlib.suppress)
    """
    Context manager for setting logging context within a scope.

    The context is automatically restored when exiting the scope,
    enabling proper context stacking for nested operations.

    Usage:
        with logging_context(session_id="abc123", pg_code="knet"):
            # All logs within this block will have payment.session_id set
            logger.info("Processing payment")

        # After exiting, previous context is restored

    Example with nesting:
        # Outer context (e.g., from middleware with span_id, user_id)
        with logging_context(session_id="abc123"):
            logger.info("Request received")  # payment.session_id=abc123

            # Inner context (e.g., payment gateway call)
            with logging_context(pg_code="knet"):
                logger.info("Calling gateway")  # payment.session_id=abc123, pg_code=knet

            # Back to outer context
            logger.info("Continuing")  # payment.session_id=abc123
    """

    def __init__(self, **kwargs):
        """
        Initialize with context fields to set.

        Args:
            **kwargs: Any LoggingContext field (span_id, user_id, ip, session_id, etc.)
        """
        self._kwargs = kwargs
        self._token: Token | None = None

    def __enter__(self) -> LoggingContext:
        """Enter the context, stacking new values on current context."""
        current = get_logging_context()
        new_ctx = current.merge(**self._kwargs)
        self._token = set_logging_context(new_ctx)
        return new_ctx

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the context, restoring previous state."""
        if self._token is not None:
            reset_logging_context(self._token)
        return False


def bind_logging_context(**kwargs) -> Token:
    """
    Bind additional context values without creating a scope.

    This is useful when you want to add context that persists
    for the remainder of the current scope without using a with statement.

    Note: You must manually reset using the returned token to avoid context leaks.

    Args:
        **kwargs: Context fields to bind

    Returns:
        Token for resetting context

    Usage:
        token = bind_logging_context(session_id="abc123")
        try:
            # ... do work ...
        finally:
            reset_logging_context(token)
    """
    current = get_logging_context()
    new_ctx = current.merge(**kwargs)
    return set_logging_context(new_ctx)


# W3C traceparent format: {version}-{trace-id}-{parent-id}-{flags}
# trace_id is 32 hex chars, minimum 2 parts needed (version + trace_id)
_TRACEPARENT_TRACE_ID_LENGTH = 32
_TRACEPARENT_MIN_PARTS = 2


def get_trace_id() -> str | None:
    """
    Get parsed trace_id from CID middleware.

    Handles W3C traceparent format by extracting the trace_id segment.
    traceparent format: {version}-{trace-id}-{parent-id}-{flags}
    Example: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01

    Returns:
        32-char trace_id if traceparent format, otherwise raw CID value
    """
    cid = get_cid()
    if not cid:
        return None
    if "-" in cid:
        parts = cid.split("-")
        if (
            len(parts) >= _TRACEPARENT_MIN_PARTS
            and len(parts[1]) == _TRACEPARENT_TRACE_ID_LENGTH
        ):
            return parts[1]
    return cid


# W3C traceparent requires 16 hex chars for parent-id, 4 parts total
_TRACEPARENT_PARENT_ID_LENGTH = 16
_TRACEPARENT_FULL_PARTS = 4


def get_trace_flags() -> str:
    """
    Extract trace-flags from W3C traceparent header.

    traceparent format: {version}-{trace-id}-{parent-id}-{flags}
    Example: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01

    Returns:
        2-char hex flags (e.g., "01" for sampled), defaults to "01" if not available
    """
    cid = get_cid()
    if cid and "-" in cid:
        parts = cid.split("-")
        if len(parts) >= _TRACEPARENT_FULL_PARTS:
            return parts[3]
    return "01"  # Default: sampled


def get_span_id() -> str | None:
    """
    Get current request's span ID from logging context.

    Returns:
        The span_id (UUID) set by LoggingContextMiddleware, or None
    """
    ctx = get_logging_context()
    return ctx.span_id


def build_traceparent() -> str | None:
    """
    Build W3C traceparent header for outbound HTTP requests.

    Format: {version}-{trace-id}-{parent-id}-{flags}
    - version: Always "00"
    - trace-id: 32-char hex from incoming traceparent
    - parent-id: 16-char hex derived from current span_id
    - flags: 2-char hex from incoming traceparent (preserves sampling)

    Uses current request's span_id as parent-id for child spans,
    maintaining the distributed trace chain.

    Returns:
        W3C traceparent header string, or None if trace context unavailable
    """
    trace_id = get_trace_id()
    span_id = get_span_id()
    if not trace_id or not span_id:
        return None

    # Convert UUID span_id to 16-char hex (W3C requires 16 hex chars for parent-id)
    parent_id = span_id.replace("-", "")[:_TRACEPARENT_PARENT_ID_LENGTH]
    flags = get_trace_flags()

    return f"00-{trace_id}-{parent_id}-{flags}"
