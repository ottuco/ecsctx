# /logctx

Core structured logging module with ECS field mapping and PII masking.

## Entry Points
- `context.py` - `LoggingContext`, `logging_context` context manager, `get_trace_id()`
- `processors.py` - `contextvars_injector`, `mask_sensitive_data`
- `pii/` - PII tokenization (HMAC-SHA-256) and encryption (AES-256-GCM) via keyset files

## Critical Context
- `logging_context` supports nesting - inner contexts merge with outer, auto-restored on exit
- `get_trace_id()` parses W3C traceparent format: extracts 32-char trace-id from `{version}-{trace-id}-{parent-id}-{flags}`
- `PRIMARY_KEYS` in processors.py defines which fields stay at root vs get pushed to `extra`
- PII masking is regex-based on JSON-serialized strings, not recursive dict walking (performance optimization)
- PII tokenization uses HMAC-SHA-256 with keyset files mounted at `/var/run/ottu/pii/`. Configure via `PII_TOKEN_KEYSET_PATH` env var.
- When PII is not configured, `_tokenize()` returns `[PII_REDACTED]` — never raw PII in logs.

## Submodules
- `pii/` - Keyset-based PII module: `crypto.py` (HMAC + AES-GCM), `keyset.py` (FileKeysetProvider with hot-reload), `normalize.py` (email/phone normalization)
- `contrib/django/` - Django-specific middleware and lazy-loading processors
- `contrib/rq/` - RQ job context propagation (decorator-based: `@with_log_context`)
- `contrib/celery/` - Celery task context propagation (signal-based: `install_celery_hooks()`)

## Footguns
- `SAFE_NAME_KEYS` whitelist prevents masking of non-PII fields containing "name" (e.g., `gateway_name`)
- `penc` format includes `kid` for key rotation: `penc:v1:<kid>:<payload>`. All keys in the keyset must be retained for decryption until re-encryption is complete.
