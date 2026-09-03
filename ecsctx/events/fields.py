"""Where a kwarg lands in the document.

Field placement was a per-developer decision, so the same fact arrived under
several names and none of them aggregated. This table makes it one decision,
made once.

Every path here resolves under a key already in `processors.ROOT_ALLOWLIST`.
Root namespaces a caller passes whole are checked against the *live* allowlist,
so a service's own `configure_root_fields()` namespaces pass through too.
That is the property `test_events_fields.py` asserts: a path outside it would be
swept into `extra` by `namespace_ecs_fields`, so routing would look correct at
the call site and be wrong in Elasticsearch.
"""

from typing import Any

from ecsctx.processors import _get_root_allowlist

# kwarg name -> dotted ECS path.
FIELD_PATHS: dict[str, str] = {
    # Correlation. Both stay flat at root: they are the two IDs a human types
    # into Kibana, and `session_id` is the spine that joins Ottu PG to Connect.
    "session_id": "session_id",
    "merchant_id": "merchant_id",
    # Payment domain — generic enough to live in the public package, and
    # already present in ROOT_ALLOWLIST before this module existed.
    "pg_code": "payment.pg_code",
    "order_id": "payment.order_id",
    "orn": "payment.orn",
    "reference": "payment.reference",
    "amount": "payment.amount",
    "currency": "payment.currency",
    # HTTP. Two of these in one call must merge into a single `http` object
    # rather than the second replacing the first.
    "method": "http.request.method",
    "status_code": "http.response.status_code",
    "request_bytes": "http.request.body.bytes",
    "response_bytes": "http.response.body.bytes",
    "path": "url.path",
    "query": "url.query",
    # Outgoing calls. ECS models the far side of a request as service.target.
    "target": "service.target.name",
    "target_type": "service.target.type",
    # Identity and failure.
    "user_id": "user.id",
    "error_type": "error.type",
    "error_message": "error.message",
}

_SCALARS = (str, int, float, bool, type(None))

# Keys `emit()` owns or that structlog sets. A caller passing these would be
# racing the spec for the same key, so they never pass through.
NOT_PASSTHROUGH = frozenset(
    {
        "event",
        "ecs_event",
        "level",
        "message",
        "timestamp",
        "extra",
    }
)


def _passthrough_keys() -> frozenset:
    """Root keys a caller may pass whole, e.g. `http={"response": {...}}`.

    Read at call time, not snapshotted at import: a service adds its own root
    namespace with `configure_root_fields(["wallet"])` or `ECSCTX_ROOT_FIELDS`,
    and `reshape_log_event` honours those dynamically. A frozen copy here would
    send `wallet={...}` to `extra.wallet` while the rest of the chain treated
    `wallet` as root — the same silent mismatch this module fixes for `http=`,
    and it would land on the first non-payment domain to adopt the package.
    """
    return _get_root_allowlist() - NOT_PASSTHROUGH


def _merge(document: dict[str, Any], path: str, value: Any) -> None:
    head, _, rest = path.partition(".")
    if not rest:
        document[head] = value
        return
    branch = document.get(head)
    if not isinstance(branch, dict):
        branch = {}
        document[head] = branch
    _merge(branch, rest, value)


def _deep_update(document: dict[str, Any], overlay: dict[str, Any]) -> None:
    """Overlay wins leaf by leaf, so an explicit `http={"request": ...}` does not
    wipe an `http.response` the table already placed."""
    for key, value in overlay.items():
        current = document.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            _deep_update(current, value)
        else:
            document[key] = value


def route(fields: dict[str, Any]) -> dict[str, Any]:
    """Place each kwarg at its ECS path.

    Unknown scalars become `labels.<name>` — ECS's sanctioned home for arbitrary
    keyword data, and aggregatable. Unknown non-scalars become `extra.<name>`,
    which is where `namespace_ecs_fields` would have put them anyway.

    Nothing warns here. Unknown-field warnings belong to the validator
    (#159491); keeping them out leaves this a pure lookup.
    """
    document: dict[str, Any] = {}
    passthrough: dict[str, Any] = {}
    passthrough_keys = _passthrough_keys()
    for name, value in fields.items():
        path = FIELD_PATHS.get(name)
        if path is not None:
            _merge(document, path, value)
        elif name in passthrough_keys:
            passthrough[name] = value
        elif isinstance(value, _SCALARS):
            document.setdefault("labels", {})[name] = value
        else:
            document.setdefault("extra", {})[name] = value
    # Applied last: a caller naming the ECS path outright is being more specific
    # than the table's shorthand, so it wins the leaf.
    _deep_update(document, passthrough)
    return document
