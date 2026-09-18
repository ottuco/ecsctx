"""Shared ``threeds.*`` domain: 3-D Secure stages, PSP-independent.

Transcribed from ticket #159487 (Event catalogue, ``threeds`` table).
``authentication_completed`` keeps base level ``info`` (the ticket's success
case); any other branch overrides the level at the call site.
"""

from ecsctx.events.spec import EventSpec

THREEDS_AUTHENTICATION_REQUESTED = EventSpec(
    action="threeds.authentication_requested",
    description="3-D Secure authentication started with the PSP for an attempt.",
    category=("authentication",),
    type=("start",),
    required=("payment.reference", "payment.pg_code"),
)

THREEDS_CHALLENGE_ISSUED = EventSpec(
    action="threeds.challenge_issued",
    description="The payer was sent a 3-D Secure challenge.",
    category=("authentication",),
    type=("creation",),
    required=("payment.reference", "session_id"),
)

THREEDS_AUTHENTICATION_COMPLETED = EventSpec(
    action="threeds.authentication_completed",
    description=(
        "3-D Secure finished; labels.auth_status carries the PSP's result. The call "
        "site logs warning unless it succeeded."
    ),
    terminal=True,
    category=("authentication",),
    type=("end",),
    required=("event.outcome", "labels.auth_status", "payment.reference"),
)

SPECS: tuple[EventSpec, ...] = (
    THREEDS_AUTHENTICATION_REQUESTED,
    THREEDS_CHALLENGE_ISSUED,
    THREEDS_AUTHENTICATION_COMPLETED,
)
