# ecsctx

ECS-compliant structured logging with W3C Trace Context support. Framework-agnostic core with Django integration.

## Entry Points
- `ecsctx/__init__.py` - All public exports
- `ecsctx/contrib/django/` - Django middleware and processors

## Critical Context
- `LoggingContext.to_dict()` maps internal attrs to ECS fields (span_id→span.id, user_id→user.id, ip→client.ip)
- Processor injection order: explicit kwargs > LoggingContext > structlog contextvars > CID trace_id > service metadata
- Masking is `ecsctx.masking.MaskPIIFilter` (a stdlib `logging.Filter` — catches structlog, stdlib, third-party libs, and `%s`-style args). `mask_sensitive_data` (structlog processor) delegates to the same engine; `get_logging_config()` wires the filter itself onto every handler it builds too, by calling `install_maskers_in_config()` on the config dict before returning it (adds `mask_pii` to `LOGGING["filters"]` and appends it to each handler's `filters`), so no manual `install_maskers()` call is needed for handlers it builds — both on by default. Every masked value is `[LABEL]` or `[LABEL:token]` (e.g. `[EMAIL-MASKED:ptok:v1:…]`) — never a bare `ptok:…`. Tokenizes PII with HMAC-SHA-256; reversible encryption via `protect()`/`reveal()` uses AES-256-GCM (`penc:v1:<kid>:…`). Configured via `PII_PROVIDER` (file|vault) + `PII_TOKEN_KEYSET_PATH`/`PII_ACCESS`/`PII_ENV` — there is no `LOG_TOKENIZE_SECRET`.
- Django `contextvars_injector` lazily imports the User model (`get_user_model()`) and auto-configures PII from env on first call to avoid circular imports / `AppRegistryNotReady` during bootstrap (it does not read `django.conf.settings`)

## Submodules
- `ecsctx/` - Core module (context, processors, formatters)
- `ecsctx/masking/` - Unified PII/PCI masking engine (`MaskPIIFilter`, `install_maskers()`, content + key-name rules)
- `ecsctx/contrib/django/` - Django middleware, lazy-loading processors, auditlog binder, masking boot-check

## Footguns ⚠️
- ECS reserved fields (`client`, `user`, `host`, `span`, `trace`) must be nested objects, never flat strings
- Django's `LogContextBinder` must be imported explicitly (not in `__init__.py`) to avoid circular imports
- `LoggingContextMiddleware` must be placed AFTER auth middleware to capture user_id
- CVV never carries a token, even when PII is configured — PCI forbids storing CVV in any form, so `[CVV-MASKED]` is always the literal, final output
- `install_maskers()` only sweeps handlers that exist at call time (no stdlib patching) — a handler built after the call needs another call
