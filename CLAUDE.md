# logctx

ECS-compliant structured logging with W3C Trace Context support. Framework-agnostic core with Django integration.

## Entry Points
- `logctx/__init__.py` - All public exports
- `logctx/contrib/django/` - Django middleware and processors

## Critical Context
- `LoggingContext.to_dict()` maps internal attrs to ECS fields (request_id→span.id, user_id→user.id, ip→client.ip)
- Processor injection order: explicit kwargs > LoggingContext > structlog contextvars > CID trace_id > service metadata
- `mask_sensitive_data` uses reversible Fernet encryption (not hashing) - requires `LOG_TOKENIZE_SECRET`
- Django `contextvars_injector` reads settings lazily to avoid circular imports during bootstrap

## Submodules
- `logctx/` - Core module (context, processors, formatters)
- `logctx/contrib/django/` - Django middleware, lazy-loading processors, auditlog binder

## Footguns ⚠️
- ECS reserved fields (`source`, `target`, `client`, `user`, `host`) must be nested objects, never flat strings
- Django's `LogContextBinder` must be imported explicitly (not in `__init__.py`) to avoid circular imports
- `LoggingContextMiddleware` must be placed AFTER auth middleware to capture user_id
