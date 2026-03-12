# /logctx

Core structured logging module with ECS field mapping and PII masking.

## Entry Points
- `context.py` - `LoggingContext`, `logging_context` context manager, `get_trace_id()`
- `processors.py` - `contextvars_injector`, `mask_sensitive_data`

## Critical Context
- `logging_context` supports nesting - inner contexts merge with outer, auto-restored on exit
- `get_trace_id()` parses W3C traceparent format: extracts 32-char trace-id from `{version}-{trace-id}-{parent-id}-{flags}`
- `PRIMARY_KEYS` in processors.py defines which fields stay at root vs get pushed to `extra`
- PII masking is regex-based on JSON-serialized strings, not recursive dict walking (performance optimization)

## Submodules
- `contrib/django/` - Django-specific middleware and lazy-loading processors
- `contrib/rq/` - RQ job context propagation (decorator-based: `@with_log_context`)
- `contrib/celery/` - Celery task context propagation (signal-based: `install_celery_hooks()`)

## Footguns ⚠️
- `_tokenize()` is LRU-cached (2048) - same input always produces same encrypted output within process
- `SAFE_NAME_KEYS` whitelist prevents masking of non-PII fields containing "name" (e.g., `gateway_name`)
