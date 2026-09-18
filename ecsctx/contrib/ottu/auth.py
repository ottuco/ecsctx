"""Shared ``auth.*`` domain: authentication, sessions, tokens, identity.

Transcribed from ticket #159487 (Event catalogue, ``auth`` table). Shape
is shared; values differ per service (Connect user sessions vs PG merchant
API-key auth). The ``user.id``/``user.name`` split is verbatim from the
ticket: auth/session flows identify by id, provisioning and role changes
by name.
"""

from ecsctx.events.spec import EventSpec, Reason

AUTH_REQUEST_AUTHENTICATED = EventSpec(
    action="auth.request_authenticated",
    description=(
        "A caller's credentials were accepted; user.id says who and labels.auth_method "
        "how."
    ),
    terminal=True,
    category=("authentication",),
    type=("allowed",),
    required=("event.outcome", "labels.auth_method", "user.id"),
)


class AuthRejection(Reason):
    """Why a request was refused before it was authenticated."""

    SERVICE_NOT_ALLOWED = "service_not_allowed"
    USER_DEACTIVATED = "user_deactivated"
    USER_DEACTIVATED_CACHE = "user_deactivated_cache"
    ACCOUNT_LOCKED = "account_locked"  # too many failed attempts; in cool-off
    INVALID_CREDENTIALS = "invalid_credentials"


AUTH_REQUEST_REJECTED = EventSpec(
    action="auth.request_rejected",
    description=(
        "A request was refused during authentication: wrong credentials, a locked or "
        "deactivated account, or a service that may not call."
    ),
    level="warning",
    terminal=True,
    category=("authentication",),
    type=("denied",),
    reasons=AuthRejection,
    failure_level="warning",
    required=("event.outcome", "event.reason", "labels.auth_method"),
)

class TokenIssueFailure(Reason):
    """Why this service could not get an access token."""

    CONNECTION_FAILED = "connection_failed"  # the identity provider was unreachable
    REJECTED = "rejected"  # it answered, and refused


AUTH_TOKEN_ISSUED = EventSpec(
    action="auth.token_issued",
    description=(
        "This service obtained or minted an access token; labels.grant_type says how "
        "and labels.cache whether it came from cache. A failure says why no token "
        "came back."
    ),
    terminal=True,
    category=("authentication",),
    type=("creation",),
    reasons=TokenIssueFailure,
    required=("event.outcome", "labels.grant_type", "labels.cache"),
)


class TokenRevocation(Reason):
    """Why a user's token was revoked."""

    USER_DEACTIVATED = "user_deactivated"


AUTH_TOKEN_REVOKED = EventSpec(
    action="auth.token_revoked",
    description=(
        "A user's token was revoked, e.g. on logout, a password change or the "
        "account being deactivated; the reason says why."
    ),
    terminal=True,
    category=("authentication",),
    type=("deletion",),
    reasons=TokenRevocation,
    required=("event.outcome", "user.id"),
)

AUTH_SESSION_TERMINATED = EventSpec(
    action="auth.session_terminated",
    description=(
        "A user session was ended by the system rather than by logout; the reason says "
        "why."
    ),
    level="warning",
    terminal=True,
    category=("authentication",),
    type=("info",),
    failure_level="warning",
    required=("event.outcome", "event.reason", "user.id"),
)

AUTH_SESSION_CHECK_SKIPPED = EventSpec(
    action="auth.session_check_skipped",
    description=(
        "The session check could not run, so the request was let through or refused "
        "according to labels.fail_mode. The outcome is unknown."
    ),
    level="warning",
    terminal=True,
    category=("authentication",),
    type=("denied",),
    failure_level="warning",
    required=("event.outcome", "event.reason", "labels.fail_mode"),
)

AUTH_IDENTITY_PROVISIONED = EventSpec(
    action="auth.identity_provisioned",
    description=(
        "A user identity was created in, or synced from, the identity provider; "
        "labels.direction says which way."
    ),
    terminal=True,
    category=("authentication",),
    type=("info",),
    required=("event.outcome", "user.name", "labels.direction"),
)

AUTH_ROLES_CHANGED = EventSpec(
    action="auth.roles_changed",
    description=(
        "A user's roles changed; labels.roles_added and labels.roles_removed carry the "
        "difference."
    ),
    terminal=True,
    category=("authentication",),
    type=("change",),
    required=("event.outcome", "user.name", "labels.roles_added", "labels.roles_removed"),
)

AUTH_PRIVILEGE_GRANTED = EventSpec(
    action="auth.privilege_granted",
    description=(
        "A user gained a privilege (labels.privilege) from labels.source. Logged at "
        "warning because it widens access."
    ),
    level="warning",
    terminal=True,
    category=("authentication",),
    type=("allowed",),
    failure_level="warning",
    required=("event.outcome", "user.name", "labels.privilege", "labels.source"),
)

AUTH_IDENTITY_SYNC_FAILED = EventSpec(
    action="auth.identity_sync_failed",
    description=(
        "Syncing a user with the identity provider failed, so the two records may now "
        "disagree."
    ),
    level="error",
    terminal=True,
    category=("authentication",),
    type=("error",),
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
