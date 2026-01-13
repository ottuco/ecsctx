# CLAUDE.md - Logging Module Context

## Module Purpose

Structured logging with automatic ECS-compliant context injection via middleware and processors. Request/response logging is handled by `@api_logging` decorator in `api/decorators.py`.

## Key Files

| File | Purpose |
|------|---------|
| `context.py` | `LoggingContext` dataclass, `get_trace_id()` for W3C traceparent parsing, `bind_logging_context()` |
| `middleware.py` | `LoggingContextMiddleware` - binds request_id, user_id, ip to context |
| `enums.py` | `Entity` enum (for backward compatibility) |
| `structlog/processors.py` | `contextvars_injector` - injects context + trace.id into log events, `mask_sensitive_data` - PII tokenization |
| `structlog/loggers.py` | `ottu_logger` - backward-compatible logger proxy |
| `structlog/formatters.py` | `OttuECSFormatter` - ECS 1.12.0 compliant output |

## @api_logging Decorator

Located in `api/decorators.py`, this is the main request/response logging mechanism.

### Usage

```python
from api.decorators import api_logging

@api_logging
class MyAPIView(APIView):
    def post(self, request):
        return Response({"status": "ok"})
```

### What It Does

1. **INBOUND log** (in `initial()`): Request method, path, headers, body, client IP, user agent
2. **OUTBOUND log** (in `dispatch()`): Response status, headers, body

### Excluding Response Keys

```python
@api_logging
class MyView(APIView):
    logging_ignore_response_keys = ["blob", "pdf_data"]  # Won't be logged
```

## ECS Field Mapping

LoggingContext attributes mapped to ECS-compliant output:

| Internal Attribute | Output Key | ECS Notes |
|--------------------|------------|-----------|
| `request_id` | `span.id` | Per-request span ID |
| `user_id` | `user.id` | ECS standard |
| `ip` | `client.ip` | ECS standard |
| (from CID) | `trace.id` | Correlation ID |

## W3C Trace Context (trace_id)

`trace_id` flows through the system:

```
nginx → traceparent header → CidMiddleware → get_trace_id() → trace.id in logs
                                                            → auditlog correlation
```

**W3C traceparent format:**
```
{version}-{trace-id}-{parent-id}-{flags}
00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01
    └── 32 hex chars (this is extracted as trace_id)
```

**Settings:**
```python
CID_HEADER = "HTTP_TRACEPARENT"
CID_RESPONSE_HEADER = None
AUDITLOG_CID_GETTER = "logctx.context.get_trace_id"
```

## ECS Field Restrictions

**NEVER use these ECS reserved fields as flat strings:**
- `source`, `target` - Reserved for network connection objects
- `host`, `server`, `client` - Reserved for host/connection objects
- `user`, `process`, `container` - Reserved for structured objects

**Always check ECS field reference before adding new log fields:**
https://www.elastic.co/docs/reference/ecs/ecs-field-reference

## Processor Injection Order

In `contextvars_injector` (processors.py):
1. Explicit log kwargs (highest priority, never overwritten)
2. LoggingContext from middleware (nested ECS format)
3. Structlog contextvars
4. `trace.id` from CID (correlation ID)
5. Service metadata (always injected)

## Backward Compatibility

- `ottu_logger.entities.PG.value` still works (proxy to `Entity` enum)
- `ottu_logger.info()` still works (proxy to structlog logger)

## When to Use @api_logging

Apply to DRF views that need request/response logging:

```python
from api.decorators import api_logging

@api_logging
class CheckoutCreateView(APIView):
    pass

@api_logging
class PaymentStatusView(APIView):
    pass
```

**Don't use for:**
- Internal views not exposed to merchants
- Health check endpoints
- Static file serving