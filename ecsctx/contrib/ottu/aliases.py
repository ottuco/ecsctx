"""Retired names and where they went.

Only names whose target is registered in this package are listed: an alias
to a future domain would resolve to ``None`` silently, which is worse than
no alias. Everything else stays on its legacy name until its domain lands —
the pending list at the bottom is the transcription backlog, not a promise.

Sources: Ottu PG ``ecs_event=`` inventory (branch
``claude/migration-logs-secret-masking``) and the Connect legacy names from
ticket #159487's production audit.
"""

ALIASES: dict[str, str] = {
    # --- pg.request_sent: the call left this process toward a PSP. ---
    "cs.request_sent": "pg.request_sent",
    "pg.outbound": "pg.request_sent",
    "benefit.outbound": "pg.request_sent",
    # --- pg.response_received: the PSP answered. ---
    "cs.request_received": "pg.response_received",
    "pg.inbound": "pg.response_received",
    # --- pg.request_failed: the call itself broke (4xx/timeout/transport). ---
    "cs.api_error": "pg.request_failed",
    "cs.client_error": "pg.request_failed",
    "cs.unexpected_error": "pg.request_failed",
    "benefit.response_failed": "pg.request_failed",
    "benefit.flow_failed": "pg.request_failed",
    "tap.dispatch_failed": "pg.request_failed",
    # --- pg.checkout_created: a hosted-checkout artefact now exists. ---
    "mpgs.session_created": "pg.checkout_created",
    # --- crypto.payload_decrypted: a decrypt (or encrypt — direction rides
    # in outcome/reason, the catalogue has no encrypt twin) ran. ---
    "samsung_pay.decryption_succeeded": "crypto.payload_decrypted",
    "samsung_pay.aes_gcm_failed": "crypto.payload_decrypted",
    "samsung_pay.kms_decrypt_failed": "crypto.payload_decrypted",
    "enc.dp_decryption_succeeded": "crypto.payload_decrypted",
    "enc.fallback_key_decryption_succeeded": "crypto.payload_decrypted",
    "enc.dp_legacy_decryption_succeeded": "crypto.payload_decrypted",
    "enc.active_key_decryption_succeeded": "crypto.payload_decrypted",
    "enc.all_decryption_failed": "crypto.payload_decrypted",
    "card.encryption_failed": "crypto.payload_decrypted",
    "benefit.encryption_failed": "crypto.payload_decrypted",
    "benefit.decryption_failed": "crypto.payload_decrypted",
    # --- crypto.credential_resolved: a secret/key was fetched or missed. ---
    "db_secret.fetch_failed": "crypto.credential_resolved",
    "db_secret.field_missing": "crypto.credential_resolved",
    "db_secret.json_invalid": "crypto.credential_resolved",
    "db_secret.field_types_invalid": "crypto.credential_resolved",
    "aws.role_assumed": "crypto.credential_resolved",
    "aws.role_assumption_failed": "crypto.credential_resolved",
    "aws.session_client_created": "crypto.credential_resolved",
    "aws.session_client_creation_failed": "crypto.credential_resolved",
    "aws.client_created": "crypto.credential_resolved",
    "aws.client_creation_failed": "crypto.credential_resolved",
    "enc.no_keys_found": "crypto.credential_resolved",
    "enc.multiple_keys_found": "crypto.credential_resolved",
    "enc.active_key_failed": "crypto.credential_resolved",
    "enc.active_key_retrieved": "crypto.credential_resolved",
    "enc.created_key_retrieved": "crypto.credential_resolved",
    "card.key_load_failed": "crypto.credential_resolved",
}

# Transcription backlog — legacy names waiting on their domain slice.
# Do NOT alias these until the target registers: resolve() returns None
# (silently) for alias targets outside the registry.
PENDING = {
    # net.* slice: PG-to-Connect calls.
    "merchant.outbound": "net.request_sent",
    "merchant.inbound": "net.response_received",
    "merchant.api_call_failed": "net.request_failed",
    # threeds.* slice.
    "mpgs.threeds_callback_received": "threeds.challenge_issued",
    "mpgs.threeds_succeeded": "threeds.authentication_completed",
    "mpgs.threeds_failed": "threeds.authentication_completed",
    "cs.threeds_frictionless": "threeds.authentication_completed",
    "cs.threeds_challenge_required": "threeds.challenge_issued",
    "cs.threeds_callback_received": "threeds.challenge_issued",
    "cs.ddc_callback_received": "threeds.challenge_issued",
    "cs.ddc_callback_completed": "threeds.authentication_completed",
    "cs.challenge_callback_received": "threeds.challenge_issued",
    # pg.callback_* slice.
    "mpgs.payer_auth_initiated": "pg.callback_received",
    "mpgs.pay_attempted": "pg.request_sent",
    "cs.ddc_complete": "pg.callback_answered",
    "cs.tms_webhook_received": "pg.callback_received",
    "tap.notification_sent": "pg.callback_answered",
    "tap.invalid_signature": "pg.callback_rejected",
    "tap.invalid_json": "pg.callback_rejected",
    "tap.hashstring_missing": "pg.callback_rejected",
    "tap.webhook_field_missing": "pg.callback_rejected",
    # crypto/kms slice.
    "payment.data_decrypted": "crypto.payload_decrypted",
    "cip.pan_decryption_skipped": "crypto.payload_decrypted",
    # card.* slice (token vault).
    "cs.card_deactivated": "card.token_deleted",
    "cs.card_reactivated": "card.token_updated",
    # cache.* slice.
    "cip.cache_read": "cache.read",
    "cip.cache_write": "cache.written",
    "cip.cache_update": "cache.written",
    # ws.* slice.
    "ws.send_attempted": "ws.message_sent",
    "ws.send_succeeded": "ws.message_sent",
    "ws.send_failed": "ws.message_sent",
    "ws.message_send_failed": "ws.message_sent",
    # Connect legacy names (backend slices own these).
    "webhook.request": "webhook.request_sent",
    "webhook.response": "webhook.delivery_completed",
    "webhook.initiation": "webhook.delivery_enqueued",
    "webhook.failure": "webhook.delivery_completed",
    "webhook_notify_return": "webhook.delivery_completed",
    "webhook.legacy_job": "webhook.delivery_enqueued",
    "pay": "payment.charge_completed",
    "token_blacklist": "auth.token_revoked",
    "session_revoke": "auth.session_terminated",
    "eventbus_connect": "bus.connection_lost",
}
