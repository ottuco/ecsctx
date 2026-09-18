"""Shared Ottu event catalogue (#159487), slice 1: pg + crypto.

Conventions mirror tests/test_events.py: the registry is process-global,
so an autouse fixture resets it around every test.
"""

import pytest
from ecsctx.contrib.ottu import ALL_DOMAINS, yaml_render
from ecsctx.contrib.ottu import auth as auth_events
from ecsctx.contrib.ottu import cache as cache_events
from ecsctx.contrib.ottu import card as card_events
from ecsctx.contrib.ottu import crypto as crypto_events
from ecsctx.contrib.ottu import net as net_events
from ecsctx.contrib.ottu import payment as payment_events
from ecsctx.contrib.ottu import pg as pg_events
from ecsctx.events import (
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


def test_typo_is_attribute_error_at_import() -> None:
    """Ticket rule 2: a typo fails at import, not as a new index value."""
    with pytest.raises(AttributeError):
        pg_events.PG_REQUEST_SENT_TYPO  # noqa: B018


def test_terminal_events_require_outcome() -> None:
    with pytest.raises(ValueError, match="needs an outcome"):
        pg_events.PG_RESPONSE_RECEIVED.ecs()
    assert pg_events.PG_RESPONSE_RECEIVED.ecs(outcome="success")["outcome"] == "success"
    assert pg_events.PG_REQUEST_SENT.ecs()["action"] == "pg.request_sent"


def test_terminal_specs_list_outcome_in_required() -> None:
    """`required` mirrors the runtime invariant: terminal => outcome listed."""
    missing = [
        spec.action
        for specs in ALL_DOMAINS.values()
        for spec in specs
        if spec.terminal and "event.outcome" not in spec.required
    ]
    assert missing == []


def test_failure_levels_match_ticket() -> None:
    assert pg_events.PG_REQUEST_FAILED.level == "warning"
    assert pg_events.PG_REQUEST_FAILED.level_on_failure == "warning"
    assert pg_events.PG_CREDENTIALS_UNAVAILABLE.level == "error"
    assert crypto_events.CRYPTO_PAYLOAD_DECRYPTED.level_on_failure == "error"
    assert payment_events.PAYMENT_ELIGIBILITY_REJECTED.level == "warning"
    assert payment_events.PAYMENT_STATE_CHANGED.level == "info"
    assert card_events.CARD_TOKEN_LOOKUP_FAILED.level == "warning"
    assert auth_events.AUTH_REQUEST_REJECTED.level == "warning"
    assert auth_events.AUTH_IDENTITY_SYNC_FAILED.level == "error"
    assert cache_events.CACHE_READ.level == "debug"
    assert net_events.NET_REQUEST_FAILED.level == "error"


def _parse_list(value: str) -> list[str]:
    """Parse exactly what yaml_render._list emits: `[a, b]` or `[]`."""
    inner = value.strip()[1:-1].strip()
    return list(inner.split(", ")) if inner else []


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
    assert _parse_list(parsed["pg.request_sent"]["required"]) == list(
        pg_events.PG_REQUEST_SENT.required
    )


def test_every_shared_event_is_classified() -> None:
    """event.type comes from ECS's closed list; Connect's definitions are the
    reference the catalogue was aligned with."""
    unclassified = [spec.action for specs in ALL_DOMAINS.values() for spec in specs if not spec.type]
    assert unclassified == []


def test_a_warning_level_terminal_event_fails_at_warning() -> None:
    """A *_rejected/*_failed event declared at warning is logged at warning on
    failure; an unexpected failure passes level="error" at the call site."""
    wrong = [
        spec.action
        for specs in ALL_DOMAINS.values()
        for spec in specs
        if spec.terminal and spec.level == "warning" and spec.level_on_failure != "warning"
    ]
    assert wrong == []


def test_outbound_failures_share_one_reason_set() -> None:
    assert pg_events.PG_REQUEST_FAILED.reasons == net_events.NET_REQUEST_FAILED.reasons
    assert "http_client_error" in net_events.OUTBOUND_FAILURE_REASONS


def test_the_api_domain_is_the_one_api_logging_emits() -> None:
    from ecsctx.events.http import HTTP_EVENTS, register_http_events

    assert ALL_DOMAINS["api"] == HTTP_EVENTS
    _register_all()
    register_http_events()  # identical specs: not a second, conflicting claim


def test_register_ottu_merges_a_services_own_events() -> None:
    from ecsctx.contrib.ottu import register_ottu
    from ecsctx.events import EventSpec

    local = EventSpec(
        action="pg.payer_redirected", type=("info",), description="The payer left for the PSP."
    )
    debited = EventSpec(
        action="wallet.balance_debited", type=("change",), description="A wallet was debited."
    )
    register_ottu(local={"pg": (local,), "wallet": (debited,)})
    assert resolve("pg.payer_redirected") is local
    assert resolve("pg.request_sent") is pg_events.PG_REQUEST_SENT
    assert resolve("wallet.balance_debited") is debited
    assert registry.is_frozen()


def test_register_ottu_refuses_to_redefine_a_shared_event() -> None:
    from ecsctx.contrib.ottu import register_ottu
    from ecsctx.events import EventSpec

    with pytest.raises(ValueError):
        register_ottu(local={"pg": (EventSpec(action="pg.request_sent", level="debug"),)})


def test_register_ottu_registers_aliases_before_freezing() -> None:
    from ecsctx.contrib.ottu import register_ottu

    register_ottu(aliases={"token_blacklist": "auth.token_revoked"})
    with pytest.warns(DeprecationWarning):
        assert resolve("token_blacklist") is auth_events.AUTH_TOKEN_REVOKED


def test_a_retired_name_warns_once_not_on_every_line() -> None:
    import warnings

    from ecsctx.contrib.ottu import register_ottu

    register_ottu(aliases={"session_revoke": "auth.session_terminated"})
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        for _ in range(3):
            resolve("session_revoke")
    assert len([w for w in caught if issubclass(w.category, DeprecationWarning)]) == 1
