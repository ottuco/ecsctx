# /ecsctx

Core structured logging module with ECS field mapping and PII/PCI masking.

## Entry Points
- `context.py` - `LoggingContext`, `logging_context` context manager, `get_trace_id()`
- `processors.py` - `contextvars_injector`, `mask_sensitive_data` (delegates to `masking.MaskPIIFilter`), `namespace_ecs_fields`
- `masking/` - Unified PII/PCI masking engine: `MaskPIIFilter` (stdlib `logging.Filter`), `install_maskers()`
- `pii/` - PII tokenization (HMAC-SHA-256) and encryption (AES-256-GCM) via keyset files

## Critical Context
- `logging_context` supports nesting - inner contexts merge with outer, auto-restored on exit
- `get_trace_id()` parses W3C traceparent format: extracts 32-char trace-id from `{version}-{trace-id}-{parent-id}-{flags}`
- `PRIMARY_KEYS` in processors.py defines which fields stay at root vs get pushed to `extra`
- Masking has two entry points, both driving the same `MaskPIIFilter`: the filter on log handlers (sees everything — structlog, stdlib, third-party, `%s`-style `record.args`) and `mask_sensitive_data` (structlog processor, in the formatter's own chain). Records built by `get_logging_config()` pass both, so they are masked twice — safe, see Footguns. `mask_sensitive_data` skips the top-level `service`/`project`/`log` keys (`skip_keys=STRUCTURAL_ECS_KEYS`, `masking/filters.py`): ecsctx's own injected metadata, not user payload, and each holds a literal `name`-style child key the PII rules would otherwise hit.
- Two independent detection strategies inside `MaskPIIFilter`: 17 ordered content regexes (`masking/patterns.py::REGEX_MASKER` — order is load-bearing, see the comments above the tuple) and key-name matching (`check_if_sensitive_keyword()`). Any matching key — PII category or secret — blanket-masks its whole value regardless of type or nesting: a dict/list under a sensitive key is stringified and masked as one unit, never recursed into.
- Every masked value is `[LABEL]` or `[LABEL:token]` (e.g. `[EMAIL-MASKED:ptok:v1:…]`) — never a bare `ptok:…`. Path exemptions via `configure_masking()`, Django `ECSCTX_MASK_EXEMPT_PATHS`, or env `PII_MASK_EXEMPT_PATHS` (`masking/exemptions.py`, matched relative to the whole log record) apply only to the exemptable field types (email/phone/address/name/generic) and only skip the key-based match — content rules still run on the value (defense in depth). Secrets (cvv/secret/payment_id/card/pem_key/iban/jwt/ssn) are never exemptable.
- PII tokenization supports two providers (`PII_PROVIDER=file|vault`). File provider reads mounted keysets; Vault provider authenticates via AppRole and fetches from KV v2. Access mode (`PII_ACCESS=tokenize|full`) enforces least privilege. Auto-configures lazily from env vars.
- When PII is not configured, `safe_tokenize()` (`masking/tokens.py`, re-exported from `processors`/`ecsctx`; the log-safe wrapper over `pii.tokenize`) returns `[PII_REDACTED]` — `mask_by_field_type()` catches that and falls back to the bare `[LABEL]` rather than embedding it.

## Submodules
- `masking/` - `filters.py` (`MaskPIIFilter`, the engine), `patterns.py` (`REGEX_MASKER` content rules, `check_if_sensitive_keyword()`, `SAFE_KEYS`), `tokens.py` (`safe_tokenize`, `mask_by_field_type`, `already_masked`), `fields_rules.py` (`FieldRule`: tokenizable/exemptable per field type), `exemptions.py` (`configure_masking()` path-exemption state, path-prefix matching)
- `pii/` - Keyset-based PII module: `provider.py` (KeysetProvider ABC), `keyset.py` (FileKeysetProvider with hot-reload), `vault.py` (VaultKeysetProvider with AppRole auth), `crypto.py` (HMAC + AES-GCM), `normalize.py` (email/phone normalization; strips wrapping quotes + whitespace before AND after the type-specific normalizer)
- `contrib/django/` - Django-specific middleware and lazy-loading processors, masking boot-check (`checks.py`)
- `contrib/rq/` - RQ job context propagation (decorator-based: `@with_log_context`)
- `contrib/celery/` - Celery task context propagation (signal-based: `install_celery_hooks()`)

## Footguns
- `SAFE_KEYS` whitelist (`masking/patterns.py`) prevents masking of non-PII fields containing "name" etc. (e.g., `gateway_name`, `pathname`); checked before every other key rule
- CVV never goes through tokenization at all, even when PII is configured — the CVV rules return the literal `[CVV-MASKED]` directly. PCI forbids storing CVV in any form, not even as an HMAC digest.
- Card/SSN/PEM tokens are computed over a normalized value (digits-only for cards and SSNs, base64-body-only for PEM), not the raw matched text — otherwise the same card or key in a different grouping/wrapping would produce a different token and break correlation. Card numbers are always **fully** masked — no partial BIN/last4 reveal.
- No dict-level "already masked" marker: a dict re-passed to `_mask_dict()` (e.g. `mask_sensitive_data` running twice in one chain) is fully re-traversed. Idempotency lives in the leaf checks instead — `already_masked()` (in `_mask_string` and `mask_by_field_type`) leaves an already-`[LABEL…]` value untouched. Only `filter()` marks anything, and only on the `LogRecord` (`mark_object_as_masked`/`is_masked_object`, a plain attribute that never ships as output), so a record reaching two handlers skips masking on the second pass.
- `penc` format includes `kid` for key rotation: `penc:v1:<kid>:<payload>`. All keys in the keyset must be retained for decryption until re-encryption is complete.
