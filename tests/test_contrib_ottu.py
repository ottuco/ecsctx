"""Shared Ottu event catalogue (#159487), slice 1: pg + crypto.

Conventions mirror tests/test_events.py: the registry is process-global,
so an autouse fixture resets it around every test.
"""

import warnings

import pytest
from ecsctx.contrib.ottu import ALL_DOMAINS, aliases, yaml_render
from ecsctx.contrib.ottu import crypto as crypto_events
from ecsctx.contrib.ottu import pg as pg_events
from ecsctx.events import (
    UnknownEventError,
    emit,
    register_aliases,
    register_domain,
    registry,
    resolve,
)


@pytest.fixture(autouse=True)
def _clean_registry():
    """The registry is process-global."""
    registry.reset()
    yield
    registry.reset()


def _register_all():
    for prefix, specs in ALL_DOMAINS.items():
        register_domain(prefix, specs)
    register_aliases(aliases.ALIASES)


class _StubLogger:
    """Captures the call the way structlog would receive it."""

    def __init__(self):
        self.calls = []

    def __getattr__(self, level):
        def _call(message, *args, **kwargs):
            self.calls.append((level, message, kwargs))

        return _call


def test_no_duplicate_actions_across_domains() -> None:
    _register_all()
    actions = [spec.action for spec in registry.all_events()]
    assert len(actions) == len(set(actions))
    assert len(actions) == sum(len(specs) for specs in ALL_DOMAINS.values())


def test_every_spec_resolves_to_itself() -> None:
    _register_all()
    for specs in ALL_DOMAINS.values():
        for spec in specs:
            assert resolve(spec.action) is spec


def test_every_alias_target_is_registered() -> None:
    _register_all()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        for old, new in aliases.ALIASES.items():
            assert resolve(old) is not None, f"{old} points at unregistered {new}"
            assert resolve(old).action == new


def test_retired_name_warns_once_per_resolve() -> None:
    _register_all()
    with pytest.warns(DeprecationWarning, match="cs.request_sent"):
        resolve("cs.request_sent")


def test_typo_is_attribute_error_at_import() -> None:
    """Ticket rule 2: a typo fails at import, not as a new index value."""
    with pytest.raises(AttributeError):
        pg_events.PG_REQUEST_SENT_TYPO  # noqa: B018


def test_terminal_events_require_outcome() -> None:
    with pytest.raises(ValueError, match="needs an outcome"):
        pg_events.PG_RESPONSE_RECEIVED.ecs()
    assert pg_events.PG_RESPONSE_RECEIVED.ecs(outcome="success")["outcome"] == "success"
    assert pg_events.PG_REQUEST_SENT.ecs()["action"] == "pg.request_sent"


def test_failure_levels_match_ticket() -> None:
    assert pg_events.PG_REQUEST_FAILED.level == "warning"
    assert pg_events.PG_REQUEST_FAILED.level_on_failure == "error"
    assert pg_events.PG_CREDENTIALS_UNAVAILABLE.level == "error"
    assert crypto_events.CRYPTO_PAYLOAD_DECRYPTED.level_on_failure == "error"


def test_emit_routes_level_from_outcome() -> None:
    _register_all()
    logger = _StubLogger()
    emit(logger, pg_events.PG_REQUEST_FAILED, "PSP call broke", outcome="failure")
    assert logger.calls[0][0] == "error"
    emit(logger, pg_events.PG_REQUEST_SENT, "Calling PSP")
    assert logger.calls[1][0] == "info"


def test_emit_unknown_name_raises() -> None:
    _register_all()
    with pytest.raises(UnknownEventError):
        emit(_StubLogger(), "nope.nothing_happened", "Ghost")


def _parse_rendered(text: str) -> dict[str, dict[str, str]]:
    """Minimal parser for exactly what yaml_render emits (2-space mapping)."""
    documents: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        if not line.startswith(" "):
            current = documents[line.rstrip(":")] = {}
        else:
            key, _, value = line.strip().partition(": ")
            assert current is not None
            current[key] = value
    return documents


def test_yaml_round_trip_preserves_action_set() -> None:
    rendered = yaml_render.render(ALL_DOMAINS)
    parsed = _parse_rendered(rendered)
    expected = {spec.action for specs in ALL_DOMAINS.values() for spec in specs}
    assert set(parsed) == expected
    assert parsed["pg.request_sent"]["level"] == "info"
    assert parsed["pg.request_failed"]["level"] == "warning"
    assert "labels.operation" in parsed["pg.request_sent"]["required"]
    assert parsed["crypto.payload_decrypted"]["terminal"] == "true"
