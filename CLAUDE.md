# ecsctx

ECS-compliant structured logging with W3C Trace Context support. Framework-agnostic core with Django integration.

## Entry Points
- `ecsctx/__init__.py` - All public exports
- `ecsctx/contrib/django/` - Django middleware and processors

## Critical Context
- `LoggingContext.to_dict()` maps internal attrs to ECS fields (span_id→span.id, user_id→user.id, ip→client.ip)
- Processor injection order: explicit kwargs > LoggingContext > structlog contextvars > CID trace_id > service metadata
- Masking is `ecsctx.masking.MaskPIIFilter` (a stdlib `logging.Filter` — catches structlog, stdlib, third-party libs, and `%s`-style args). `mask_sensitive_data` (structlog processor) delegates to the same engine. `get_logging_config()` calls `install_maskers_in_config()` on the config dict before returning it, which puts `mask_pii_filter` on every handler it builds, so no manual `install_maskers()` call is needed. The filter masks the record in place (Sentry's logging integration and `handleError` read the record, not the formatter's copy); the formatter's second pass skips strings already known clean. Every masked value is `[LABEL]` or `[LABEL:token]` (e.g. `[EMAIL-MASKED:ptok:v1:…]`) — never a bare `ptok:…`. Tokenizes PII with HMAC-SHA-256; reversible encryption via `protect()`/`reveal()` uses AES-256-GCM (`penc:v1:<kid>:…`). Configured via `PII_PROVIDER` (file|vault) + `PII_TOKEN_KEYSET_PATH`/`PII_ACCESS`/`PII_ENV` — there is no `LOG_TOKENIZE_SECRET`.
- Django `contextvars_injector` lazily imports the User model (`get_user_model()`) and auto-configures PII from env on first call to avoid circular imports / `AppRegistryNotReady` during bootstrap (it does not read `django.conf.settings`). What must be avoided is an **eager model or app-registry import at module-import time** — not settings access as such: `ecsctx.identity` reads `ECSCTX_PROJECT_NAME` / `ECSCTX_SERVICE_TYPE` / `ECSCTX_APP_VERSION` from `django.conf.settings` lazily at log time, cached, and guarded for both `ImportError` (Django is an optional extra) and `ImproperlyConfigured` (#159489)

## Submodules
- `ecsctx/` - Core module (context, processors, formatters)
- `ecsctx/masking/` - Unified PII/PCI masking engine (`MaskPIIFilter`, `install_maskers()`, content + key-name rules)
- `ecsctx/contrib/django/` - Django middleware, lazy-loading processors, auditlog binder, masking boot-check
- `ecsctx/events/` - `EventSpec`, `Outcome`, `Reason`, registry, contract validator; services log with `logger.<level>(msg, ecs_event=SPEC.ecs(...))` — there is no wrapper
- `ecsctx/contrib/ottu/` - The shared Ottu event catalogue, its naming `rules`, and `render_docs` (→ `docs/events.md`). Changes are API changes for every service: see `.claude/rules/catalogue.md`

## Footguns ⚠️
- ECS reserved fields (`client`, `user`, `host`, `span`, `trace`) must be nested objects, never flat strings
- Django's `LogContextBinder` must be imported explicitly (not in `__init__.py`) to avoid circular imports
- `LoggingContextMiddleware` must be placed AFTER auth middleware to capture user_id
- CVV never carries a token, even when PII is configured — PCI forbids storing CVV in any form, so `[CVV-MASKED]` is always the literal, final output
- Card number and CVV **content** rules are the opt-in `pci` pack (`get_logging_config(masking_packs=("pci", "financial_ids"))` or `ECSCTX_MASKING_PACKS`): a PCI service that does not enable it gets no PAN/CVV content scanning. Key names (`card`, `pan`, `cvv`, `expiry`, …) are masked in every service
- Card numbers truncate to first 6 + last 4 for 15–19 digits and last 4 only below 15 (`[CARD-MASKED:411111******1111]`, PCI DSS 3.5.1, FAQ 1091) — no token alongside, independent of PII configuration, and a second masking pass is a noop
- `install_maskers()` only sweeps handlers that exist at call time (no stdlib patching) — a handler built after the call needs another call
