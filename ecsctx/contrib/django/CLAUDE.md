# /ecsctx/contrib/django

Django middleware and processors; the `contextvars_injector` lazily imports the User model and, on first call, auto-configures PII (from env) and root fields (from the `ECSCTX_ROOT_FIELDS` setting) — avoiding circular imports during bootstrap. The settings bridge runs at log time (settings fully loaded), so it works regardless of whether `setup_logging()` was called. Mask exemptions need no bridge: `ecsctx.masking.exemptions` reads `ECSCTX_MASK_EXEMPT_PATHS` itself the first time anything masks.

## Entry Points
- `middleware.py` - `LoggingContextMiddleware` (binds span_id, user_id, ip)
- `processors.py` - Django-aware `contextvars_injector`
- `logging.py` - `get_logging_config()`, `setup_logging()`, presets (`RQ_LOGGERS`, `CELERY_LOGGERS`)
- `checks.py` - masking boot check, auto-registered as a Django system check on import
- `testing.py` - `MaskingTestsMixin`: 22 pluggable tests (327 sample cases) for a project's own suite — the masking check passes, and every case in `ecsctx.masking.samples` is logged through the project and compared exactly against its label. With PII tokenization on, a bare `ptok:v1:…` token matches any tokenizable label (`comparable()`); card/CVV/expiry labels still compare as-is. A case needing an opt-in pack (`samples.case_pack()`: `pci` or `financial_ids`, payment-id key names included) is skipped unless the project enables it; ecsctx's own run turns on every pack. `OVER_MASKED_BECAUSE_OF_CVV` (an open bug) is left out: a project cannot fix it. Our own record is picked out of each handler's buffer by `log.origin.function`, since anything else logging at the same moment lands there too. Every logging test — sample tables included — runs once per route: `root`, each `LOGGING["loggers"]` entry, and every live logger with handlers of its own that `LOGGING` never mentions (Django's `django`/`django.server`, import-time package handlers); routes whose logger filters drop every record (e.g. `sentry_sdk.errors`) are skipped. Each logs at the lowest level every handler on it accepts. Exact field checks read only handlers whose formatter ends in `ECSFormatter`; every other handler gets the format-agnostic leak check; non-stream handlers are read back through their own formatter with `emit()` swapped out, so test values never leave the process. Helpers `capture_log()` / `capture_stdlib_log()` / `capture_handler_texts()` / `masked_outputs()` are usable standalone. ecsctx's own `tests/test_shipped_masking_suite.py` inherits the mixin, so CI runs what ships

## Critical Context
- `LogContextBinder` NOT in `__all__` - must import explicitly to avoid circular imports during Django setup
- Middleware stores context token on `request._logging_context_token` for cleanup
- `process_view` rebinds context (not merges) to add user_id after auth runs
- Sentry trace_id set synchronously in `process_request` - `before_send` runs in background thread without contextvar access
- `setup_logging()` calls `configure_structlog()` internally - don't call both
- `get_logging_config()` calls `install_maskers_in_config(config)` before returning: adds `mask_pii_filter` to `LOGGING["filters"]` and appends it to every handler whose formatter does not run `mask_sensitive_data` — its own console handler is masked by its formatter, once. `masking_packs=("pci", "financial_ids")` turns on the opt-in content packs for PCI services. Dict-only and idempotent.
- `checks.py` fails boot when a shipping handler could emit unmasked logs; a handler is masked by `mask_pii_filter` (on it or its logger) or by a formatter that runs `mask_sensitive_data`. `find_masking_errors()` is the core — `find_masking_config_errors()` (the `LOGGING` dict) plus `find_unmasked_live_handlers()` (the live logging tree). Wrappers: `check_masking_configured()` (the system check), `validate_masking_config()` → `ValueError`, `assert_no_masking_errors()` → `AssertionError` for a project's own test suite (`ignore_pytest_handlers=True` drops the capture handlers pytest attaches mid-run — they belong to the runner and no `install_maskers()` sweep can reach them).

## Dependencies
- `django-ipware` for `get_client_ip()`
- `sentry-sdk` for trace correlation
- `django-auditlog` for `LogContextBinder` (optional)

## Footguns ⚠️
- Middleware must be AFTER auth middleware - `process_view` checks `request.user.is_authenticated`
- `LogContextBinder.resolve_source_instance()` has PaymentAttempt special-case: uses `attempt.transaction` instead
- `context_binder` pre-tokenizes PII to avoid triple-processing (already masked data hitting `mask_sensitive_data`)
- Django applies `DEFAULT_LOGGING` and `settings.LOGGING` as two `dictConfig` passes (not a merge), before `apps.populate()`. So the `django` logger keeps its `AdminEmailHandler` — unmasked tracebacks by email, reported only when `ADMINS` is set since it sends nothing otherwise — and handlers attached on package import never appear in `LOGGING` at all; hence `find_unmasked_live_handlers()`. `disable_existing_loggers` does not help: it disables loggers, their handlers stay attached
- The system check reads the `ENVIRONMENT` env var and silences itself in `local`/`test`/`dev`, so it never blocks development. Django settings override each part: `ECSCTX_MASKING_CHECK_ENV_VAR`, `ECSCTX_MASKING_CHECK_SKIP_ENVS`, `ECSCTX_SKIP_MASKING_CHECK` (off entirely). `assert_no_masking_errors()` is never skipped — that is why it exists for test suites
