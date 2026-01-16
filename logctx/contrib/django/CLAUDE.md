# /logctx/contrib/django

Django middleware and processors with lazy settings loading to avoid circular imports.

## Entry Points
- `middleware.py` - `LoggingContextMiddleware` (binds span_id, user_id, ip)
- `processors.py` - Django-aware `contextvars_injector`
- `logging.py` - `get_logging_config()`, `setup_logging()`, presets (`RQ_LOGGERS`, `CELERY_LOGGERS`)

## Critical Context
- `LogContextBinder` NOT in `__all__` - must import explicitly to avoid circular imports during Django setup
- Middleware stores context token on `request._logging_context_token` for cleanup
- `process_view` rebinds context (not merges) to add user_id after auth runs
- Sentry trace_id set synchronously in `process_request` - `before_send` runs in background thread without contextvar access
- `setup_logging()` calls `configure_structlog()` internally - don't call both

## Dependencies
- `django-ipware` for `get_client_ip()`
- `sentry-sdk` for trace correlation
- `django-auditlog` for `LogContextBinder` (optional)

## Footguns ⚠️
- Middleware must be AFTER auth middleware - `process_view` checks `request.user.is_authenticated`
- `LogContextBinder.resolve_source_instance()` has PaymentAttempt special-case: uses `attempt.transaction` instead
- `context_binder` pre-tokenizes PII to avoid triple-processing (already masked data hitting `mask_sensitive_data`)
