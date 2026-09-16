"""Shared ``auth.*`` domain: authentication, sessions, tokens, identity.

Transcribed from ticket #159487 (Event catalogue, ``auth`` table). Shape
is shared; values differ per service (Connect user sessions vs PG merchant
API-key auth).
"""

from ecsctx.events.spec import EventSpec

AUTH_REQUEST_AUTHENTICATED = EventSpec(
    action="auth.request_authenticated",
    terminal=True,
    required=("event.outcome", "labels.auth_method", "user.id"),
)

AUTH_REQUEST_REJECTED = EventSpec(
    action="auth.request_rejected",
    level="warning",
    terminal=True,
    required=("event.reason", "labels.auth_method"),
)

AUTH_TOKEN_ISSUED = EventSpec(
    action="auth.token_issued",
    terminal=True,
    required=("event.outcome", "labels.grant_type", "labels.cache"),
)

AUTH_TOKEN_REVOKED = EventSpec(
    action="auth.token_revoked",
    terminal=True,
    required=("user.id",),
)

AUTH_SESSION_TERMINATED = EventSpec(
    action="auth.session_terminated",
    level="warning",
    terminal=True,
    required=("event.reason", "user.id"),
)

AUTH_SESSION_CHECK_SKIPPED = EventSpec(
    action="auth.session_check_skipped",
    level="warning",
    terminal=True,
    required=("event.reason", "labels.fail_mode"),
)

AUTH_IDENTITY_PROVISIONED = EventSpec(
    action="auth.identity_provisioned",
    terminal=True,
    required=("event.outcome", "user.name", "labels.direction"),
)

AUTH_ROLES_CHANGED = EventSpec(
    action="auth.roles_changed",
    terminal=True,
    required=("user.name", "labels.roles_added", "labels.roles_removed"),
)

AUTH_PRIVILEGE_GRANTED = EventSpec(
    action="auth.privilege_granted",
    level="warning",
    terminal=True,
    required=("user.name", "labels.privilege", "labels.source"),
)

AUTH_IDENTITY_SYNC_FAILED = EventSpec(
    action="auth.identity_sync_failed",
    level="error",
    terminal=True,
    required=("event.outcome", "event.reason", "error.type"),
)

SPECS: tuple[EventSpec, ...] = (
    AUTH_REQUEST_AUTHENTICATED,
    AUTH_REQUEST_REJECTED,
    AUTH_TOKEN_ISSUED,
    AUTH_TOKEN_REVOKED,
    AUTH_SESSION_TERMINATED,
    AUTH_SESSION_CHECK_SKIPPED,
    AUTH_IDENTITY_PROVISIONED,
    AUTH_ROLES_CHANGED,
    AUTH_PRIVILEGE_GRANTED,
    AUTH_IDENTITY_SYNC_FAILED,
)
