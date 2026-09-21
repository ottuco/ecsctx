# /ecsctx/contrib/django

Django middleware and processors; the `contextvars_injector` lazily imports the User model and, on first call, auto-configures PII (from env) and mask exemptions (from the `ECSCTX_MASK_EXEMPT_PATHS` setting) — avoiding circular imports during bootstrap. The settings bridge runs at log time (settings fully loaded), so it works regardless of whether `setup_logging()` was called.

## Entry Points
- `middleware.py` - `LoggingContextMiddleware` (binds span_id, user_id, ip)
- `processors.py` - Django-aware `contextvars_injector`
- `logging.py` - `get_logging_config()`, `setup_logging()`, presets (`RQ_LOGGERS`, `CELERY_LOGGERS`)
- `checks.py` - masking boot check, auto-registered as a Django system check on import
- `testing.py` - `MaskingTestsMixin`: 22 pluggable tests (321 sample cases) for a project's own suite — the masking check passes, and every case in `ecsctx.masking.samples` is logged through the project and compared exactly against its label (token ignored; pytest's capture handler skipped). Output tests run through every route (`root` + each `LOGGING["loggers"]` entry) at the lowest level every handler on it accepts; non-stream handlers are read back through their own formatter with `emit()` swapped out, so test values never leave the process. Helpers `capture_log()` / `capture_stdlib_log()` / `capture_handler_texts()` / `masked_outputs()` are usable standalone. ecsctx's own `tests/test_shipped_masking_suite.py` inherits the mixin, so CI runs what ships

## Critical Context
- `LogContextBinder` NOT in `__all__` - must import explicitly to avoid circular imports during Django setup
- Middleware stores context token on `request._logging_context_token` for cleanup
- `process_view` rebinds context (not merges) to add user_id after auth runs
- Sentry trace_id set synchronously in `process_request` - `before_send` runs in background thread without contextvar access
- `setup_logging()` calls `configure_structlog()` internally - don't call both
- `get_logging_config()` calls `install_maskers_in_config(config)` before returning: adds `mask_pii_filter` to `LOGGING["filters"]` and appends it to every handler it builds, so a project never wires masking by hand. Dict-only and idempotent.
- `checks.py` fails boot when a shipping handler could emit unmasked logs. `find_masking_errors()` is the core — `find_masking_config_errors()` (the `LOGGING` dict) plus `find_unmasked_live_handlers()` (the live logging tree). Wrappers: `check_masking_configured()` (the system check), `validate_masking_config()` → `ValueError`, `assert_no_masking_errors()` → `AssertionError` for a project's own test suite (takes `ignore_pytest_handlers=True`, which drops the capture handlers pytest attaches mid-run — they carry no masker, belong to the runner, and no `install_maskers()` sweep can reach them).

## Dependencies
- `django-ipware` for `get_client_ip()`
- `sentry-sdk` for trace correlation
- `django-auditlog` for `LogContextBinder` (optional)

## Footguns ⚠️
- Middleware must be AFTER auth middleware - `process_view` checks `request.user.is_authenticated`
- `LogContextBinder.resolve_source_instance()` has PaymentAttempt special-case: uses `attempt.transaction` instead
- `context_binder` pre-tokenizes PII to avoid triple-processing (already masked data hitting `mask_sensitive_data`)
- Django applies `DEFAULT_LOGGING` and `settings.LOGGING` as two `dictConfig` passes (not a merge), before `apps.populate()`. So the `django` logger keeps its `AdminEmailHandler` — unmasked tracebacks by email — and handlers attached on package import never appear in `LOGGING` at all; hence `find_unmasked_live_handlers()`. `disable_existing_loggers` does not help: it disables loggers, their handlers stay attached
- The system check runs in every environment by default: `ECSCTX_MASKING_CHECK_SKIP_ENVS` is empty, so nothing is silenced unless a project opts in. It compares that list against the `ENVIRONMENT` env var (rename it with `ECSCTX_MASKING_CHECK_ENV_VAR`), or `ECSCTX_SKIP_MASKING_CHECK` turns it off entirely. `assert_no_masking_errors()` is never skipped by environment — that is why it exists for test suites
