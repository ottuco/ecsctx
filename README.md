# logctx

Context-aware structured logging for Django with ECS compliance and distributed tracing.

## Installation

```bash
pip install git+https://github.com/ottuco/logctx.git
```

## Overview

This package provides:
- **Automatic context injection** via middleware (request_id, user_id, ip, trace_id)
- **ECS-compliant output** for Elasticsearch compatibility
- **Structured logging** via structlog processors
- **PII masking** via tokenization processor
- **W3C Trace Context** support for distributed tracing
- **Backward compatibility** with existing `ottu_logger` usage

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         REQUEST FLOW                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. nginx adds traceparent header (W3C Trace Context)           │
│                          ↓                                       │
│  2. CidMiddleware reads traceparent, stores in contextvar       │
│                          ↓                                       │
│  3. LoggingContextMiddleware binds request_id, user_id, ip      │
│                          ↓                                       │
│  4. View executes, calls logger.info()                          │
│                          ↓                                       │
│  5. Processor injects context + trace.id                        │
│                          ↓                                       │
│  6. Log emitted with full context → filebeat → ELK              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Basic Usage

```python
import structlog

logger = structlog.get_logger(__name__)

# Context is auto-injected by middleware and processors
logger.info("Payment processed", amount=100, currency="KWD")
```

### For Backward Compatibility

```python
from logctx import ottu_logger

ottu_logger.info("Payment processed", amount=100, currency="KWD")
```

## Django Configuration

### 1. Add Middleware

```python
MIDDLEWARE = [
    # ... early middleware ...
    "cid.middleware.CidMiddleware",  # Must be early
    # ... other middleware ...
    "logctx.LoggingContextMiddleware",  # After auth middleware
]
```

### 2. Configure CID (Trace Context)

```python
CID_HEADER = "HTTP_TRACEPARENT"
CID_RESPONSE_HEADER = None
CID_GENERATE = True
CID_CONCATENATE_IDS = False
AUDITLOG_CID_GETTER = "logctx.get_trace_id"
```

### 3. Configure Structlog

```python
import structlog
from logctx import (
    contextvars_injector,
    mask_sensitive_data,
    namespace_ecs_fields,
    ecs_validator,
    OttuECSFormatter,
)

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.filter_by_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        contextvars_injector,
        namespace_ecs_fields,
        mask_sensitive_data,
        ecs_validator,
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)
```

## ECS Field Mapping

| Context Field | Output Field | Description |
|---------------|--------------|-------------|
| request_id | `span.id` | Unique request ID (UUID) |
| user_id | `user.id` | Authenticated user |
| ip | `client.ip` | Client IP address |
| (from CID) | `trace.id` | Correlation ID from traceparent |

## W3C Trace Context

### traceparent Header Format

```
{version}-{trace-id}-{parent-id}-{flags}
00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01
```

### Using get_trace_id()

```python
from logctx import get_trace_id

trace_id = get_trace_id()  # e.g., "0af7651916cd43dd8448eb211c80319c"
```

## Log Output Example

```json
{
  "message": "Payment processed",
  "amount": 100,
  "currency": "KWD",
  "trace": {"id": "abc-123-def"},
  "span": {"id": "req-456-ghi"},
  "user": {"id": 42},
  "client": {"ip": "192.168.1.1"},
  "service": {"name": "app", "version": "1.0.0"},
  "timestamp": "2025-01-15T10:30:00Z"
}
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `LOG_TOKENIZE_SECRET` | Fernet key for PII encryption |
| `APP_VERSION` | Application version for logs |
| `PROJECT_NAME` | Project name for logs |

## Package Structure

```
logctx/
├── __init__.py         # Main exports
├── context.py          # LoggingContext, get_trace_id(), bind_logging_context()
├── enums.py            # Entity, Event, RequestDirection, APIType
├── middleware.py       # LoggingContextMiddleware
└── structlog/
    ├── context_binder.py   # Auditlog context binding
    ├── ecs_validator.py    # ECS field validation
    ├── formatters.py       # OttuECSFormatter (ECS 1.12.0)
    ├── loggers.py          # ottu_logger (backward compatibility)
    └── processors.py       # contextvars_injector, mask_sensitive_data
```