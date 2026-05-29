# ecsctx

ECS-compliant structured logging with W3C Trace Context support. Framework-agnostic core with Django integration.

## Entry Points
- `ecsctx/__init__.py` - All public exports
- `ecsctx/contrib/django/` - Django middleware and processors

## Critical Context
- `LoggingContext.to_dict()` maps internal attrs to ECS fields (span_id→span.id, user_id→user.id, ip→client.ip)
- Processor injection order: explicit kwargs > LoggingContext > structlog contextvars > CID trace_id > service metadata
- `mask_sensitive_data` tokenizes PII with HMAC-SHA-256 (`ptok:v1:…`); reversible encryption via `protect()`/`reveal()` uses AES-256-GCM (`penc:v1:<kid>:…`). Configured via `PII_PROVIDER` (file|vault) + `PII_TOKEN_KEYSET_PATH`/`PII_ACCESS`/`PII_ENV` — there is no `LOG_TOKENIZE_SECRET`.
- Django `contextvars_injector` lazily imports the User model (`get_user_model()`) and auto-configures PII from env on first call to avoid circular imports / `AppRegistryNotReady` during bootstrap (it does not read `django.conf.settings`)

## Submodules
- `ecsctx/` - Core module (context, processors, formatters)
- `ecsctx/contrib/django/` - Django middleware, lazy-loading processors, auditlog binder

## Footguns ⚠️
- ECS reserved fields (`client`, `user`, `host`, `span`, `trace`) must be nested objects, never flat strings
- Django's `LogContextBinder` must be imported explicitly (not in `__init__.py`) to avoid circular imports
- `LoggingContextMiddleware` must be placed AFTER auth middleware to capture user_id
