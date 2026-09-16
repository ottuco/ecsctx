"""Shared ``threeds.*`` domain: 3-D Secure stages, PSP-independent.

Transcribed from ticket #159487 (Event catalogue, ``threeds`` table).
``authentication_completed`` keeps base level ``info`` (the ticket's success
case); any other branch overrides the level at the call site.
"""

from ecsctx.events.spec import EventSpec

THREEDS_AUTHENTICATION_REQUESTED = EventSpec(
    action="threeds.authentication_requested",
    required=("payment.reference", "payment.pg_code"),
)

THREEDS_CHALLENGE_ISSUED = EventSpec(
    action="threeds.challenge_issued",
    required=("payment.reference", "session_id"),
)

THREEDS_AUTHENTICATION_COMPLETED = EventSpec(
    action="threeds.authentication_completed",
    terminal=True,
    required=("event.outcome", "labels.auth_status", "payment.reference"),
)

SPECS: tuple[EventSpec, ...] = (
    THREEDS_AUTHENTICATION_REQUESTED,
    THREEDS_CHALLENGE_ISSUED,
    THREEDS_AUTHENTICATION_COMPLETED,
)
