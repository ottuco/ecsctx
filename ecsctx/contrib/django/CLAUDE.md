# /ecsctx/contrib/django

Django middleware and processors; the `contextvars_injector` lazily imports the User model and, on first call, auto-configures PII (from env) and mask exemptions (from the `ECSCTX_MASK_EXEMPT_PATHS` setting) — avoiding circular imports during bootstrap. The settings bridge runs at log time (settings fully loaded), so it works regardless of whether `setup_logging()` was called.

## Entry Points
- `middleware.py` - `LoggingContextMiddleware` (binds span_id, user_id, ip)
- `processors.py` - Django-aware `contextvars_injector`
- `logging.py` - `get_logging_config()`, `setup_logging()`, presets (`RQ_LOGGERS`, `CELERY_LOGGERS`)
- `checks.py` - masking boot check, auto-registered as a Django system check on import

## Critical Context
- `LogContextBinder` NOT in `__all__` - must import explicitly to avoid circular imports during Django setup
- Middleware stores context token on `request._logging_context_token` for cleanup
- `process_view` rebinds context (not merges) to add user_id after auth runs
- Sentry trace_id set synchronously in `process_request` - `before_send` runs in background thread without contextvar access
- `setup_logging()` calls `configure_structlog()` internally - don't call both
- `get_logging_config()` calls `install_maskers_in_config(config)` before returning: adds `mask_pii_filter` to `LOGGING["filters"]` and appends it to every handler it builds, so a project never wires masking by hand. Dict-only and idempotent.
- `checks.py` fails boot when a shipping handler could emit unmasked logs. `find_masking_errors()` is the core — `find_masking_config_errors()` (the `LOGGING` dict) plus `find_unmasked_live_handlers()` (the live logging tree). Wrappers: `check_masking_configured()` (the system check), `validate_masking_config()` → `ValueError`, `assert_no_masking_errors()` → `AssertionError` for a project's own test suite.

## Dependencies
- `django-ipware` for `get_client_ip()`
- `sentry-sdk` for trace correlation
- `django-auditlog` for `LogContextBinder` (optional)

## Footguns ⚠️
- Middleware must be AFTER auth middleware - `process_view` checks `request.user.is_authenticated`
- `LogContextBinder.resolve_source_instance()` has PaymentAttempt special-case: uses `attempt.transaction` instead
- `context_binder` pre-tokenizes PII to avoid triple-processing (already masked data hitting `mask_sensitive_data`)
- Django applies `DEFAULT_LOGGING` and `settings.LOGGING` as two `dictConfig` passes (not a merge), before `apps.populate()`. So the `django` logger keeps its `AdminEmailHandler` — unmasked tracebacks by email — and handlers attached on package import never appear in `LOGGING` at all; hence `find_unmasked_live_handlers()`. `disable_existing_loggers` does not help: it disables loggers, their handlers stay attached
- The system check reads the `ENVIRONMENT` env var and silences itself in `local`/`test`/`dev`, so it never blocks development. Django settings override each part: `ECSCTX_MASKING_CHECK_ENV_VAR`, `ECSCTX_MASKING_CHECK_SKIP_ENVS`, `ECSCTX_SKIP_MASKING_CHECK` (off entirely). `assert_no_masking_errors()` is never skipped — that is why it exists for test suites
