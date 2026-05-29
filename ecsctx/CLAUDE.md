# /ecsctx

Core structured logging module with ECS field mapping and PII masking.

## Entry Points
- `context.py` - `LoggingContext`, `logging_context` context manager, `get_trace_id()`
- `processors.py` - `contextvars_injector`, `mask_sensitive_data`, `namespace_ecs_fields`
- `pii/` - PII tokenization (HMAC-SHA-256) and encryption (AES-256-GCM) via keyset files

## Critical Context
- `logging_context` supports nesting - inner contexts merge with outer, auto-restored on exit
- `get_trace_id()` parses W3C traceparent format: extracts 32-char trace-id from `{version}-{trace-id}-{parent-id}-{flags}`
- `PRIMARY_KEYS` in processors.py defines which fields stay at root vs get pushed to `extra`
- PII masking walks the structure recursively (path-aware): sensitive string values are tokenized unless their JSON path is exempted via `configure_masking()`, Django `ECSCTX_MASK_EXEMPT_PATHS`, or env `PII_MASK_EXEMPT_PATHS` (matched relative to the masked container, e.g. `payment_methods[*].name`; a prefix exempts the whole subtree). Emails/phones are still scrubbed on every string leaf.
- PII tokenization supports two providers (`PII_PROVIDER=file|vault`). File provider reads mounted keysets; Vault provider authenticates via AppRole and fetches from KV v2. Access mode (`PII_ACCESS=tokenize|full`) enforces least privilege. Auto-configures lazily from env vars.
- When PII is not configured, `_tokenize()` returns `[PII_REDACTED]` — never raw PII in logs.

## Submodules
- `pii/` - Keyset-based PII module: `provider.py` (KeysetProvider ABC), `keyset.py` (FileKeysetProvider with hot-reload), `vault.py` (VaultKeysetProvider with AppRole auth), `crypto.py` (HMAC + AES-GCM), `normalize.py` (email/phone normalization)
- `contrib/django/` - Django-specific middleware and lazy-loading processors
- `contrib/rq/` - RQ job context propagation (decorator-based: `@with_log_context`)
- `contrib/celery/` - Celery task context propagation (signal-based: `install_celery_hooks()`)

## Footguns
- `SAFE_NAME_KEYS` whitelist prevents masking of non-PII fields containing "name" (e.g., `gateway_name`)
- `penc` format includes `kid` for key rotation: `penc:v1:<kid>:<payload>`. All keys in the keyset must be retained for decryption until re-encryption is complete.
