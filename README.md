# logctx

Context-aware structured logging with ECS compliance and distributed tracing.

Framework-agnostic core with Django integration via `logctx.contrib.django`.

## Overview

This package provides:

- **Automatic context injection** via middleware (request_id, user_id, ip, trace_id)
- **ECS 1.12.0 compliant output** for Elasticsearch/Kibana compatibility
- **Structured logging** via structlog processors
- **PII masking & tokenization** - Encrypt sensitive data (emails, phones, names) for ISO 27001 compliance
- **W3C Trace Context support** for distributed tracing across services

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         REQUEST FLOW                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. nginx forwards/generates traceparent header (W3C Trace)     │
│     → Forward from client if present, generate if missing       │
│                          ↓                                       │
│  2. CidMiddleware reads traceparent, stores in contextvar       │
│                          ↓                                       │
│  3. LoggingContextMiddleware binds request_id, user_id, ip      │
│                          ↓                                       │
│  4. View executes, calls logger.info()                          │
│                          ↓                                       │
│  5. Processors inject context + mask PII (tokenization)         │
│                          ↓                                       │
│  6. ECS-formatted JSON → stdout → filebeat → Elasticsearch      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### nginx Configuration (Recommended)

Configure nginx to forward the `traceparent` header from clients (for distributed tracing) or generate one if not present:

```nginx
# Forward client's traceparent if present, otherwise generate one
map $http_traceparent $trace_id {
    ""      "00-$request_id-$connection-01";  # Generate if missing
    default $http_traceparent;                 # Forward if present
}

server {
    location / {
        proxy_set_header traceparent $trace_id;
        proxy_pass http://upstream;
    }
}
```

## PII Masking & Tokenization

logctx automatically detects and encrypts sensitive data in logs for **ISO 27001 compliance**:

- **Emails** - Detected via regex pattern
- **Phone numbers** - Detected via regex pattern
- **Names** - Keys containing `name`, `customer`, `payer`, `billing`, etc.
- **Auth headers** - Authorization, API keys (masked, not tokenized)

Tokenized values use **Fernet encryption (AES-128)** and can be decrypted with your secret key for authorized access:

```json
{
  "customer_name": "enc_gAAAAABl...",
  "email": "enc_gAAAAABl...",
  "amount": 100
}
```

Set `LOG_TOKENIZE_SECRET` environment variable to a secure key in production.

## Quick Start (Django)

### 1. Install

```bash
uv add "logctx[django] @ git+https://github.com/ottuco/logctx.git"
```

### 2. Configure settings.py

```python
from logctx.contrib.django import get_logging_config, setup_logging, RQ_LOGGERS

# Logging - that's it!
LOGGING = get_logging_config(loggers=RQ_LOGGERS)
setup_logging()

# Middleware
MIDDLEWARE = [
    # ... other middleware
    "cid.middleware.CidMiddleware",  # Must be early for trace context
    # ... other middleware
    "logctx.contrib.django.LoggingContextMiddleware",  # After auth
]

# django-cid for trace correlation
INSTALLED_APPS = [
    "cid.apps.CidAppConfig",
    # ... your apps
]
CID_GENERATE = True
CID_HEADER = "HTTP_TRACEPARENT"
```

### 3. Use in your code

```python
import structlog

logger = structlog.get_logger(__name__)

def my_view(request):
    logger.info("Processing request", user_id=request.user.id)
    # Output includes: trace.id, span.id, client.ip, service.name, etc.
```

## Installation Options

```bash
# Core only (framework-agnostic)
uv add "logctx @ git+https://github.com/ottuco/logctx.git"

# With Django support
uv add "logctx[django] @ git+https://github.com/ottuco/logctx.git"

# With Django + auditlog integration
uv add "logctx[django,auditlog] @ git+https://github.com/ottuco/logctx.git"
```

## Django Configuration

### get_logging_config()

Returns a complete Django `LOGGING` dict with sensible defaults.

```python
from logctx.contrib.django import get_logging_config

LOGGING = get_logging_config(
    root_level="INFO",       # Root logger level (default: INFO)
    handler_level="DEBUG",   # Console handler level (default: DEBUG)
    use_cid_filter=True,     # Add CID correlation filter (default: True)
    loggers=None,            # Additional loggers to merge
)
```

### Logger Presets

Import and merge presets for common task queues:

```python
from logctx.contrib.django import (
    get_logging_config,
    RQ_LOGGERS,           # RQ at WARNING level
    RQ_LOGGERS_DEBUG,     # RQ at INFO level
    CELERY_LOGGERS,       # Celery at WARNING level
    CELERY_LOGGERS_DEBUG, # Celery at INFO level
)

# Production with RQ
LOGGING = get_logging_config(loggers=RQ_LOGGERS)

# Development with Celery
LOGGING = get_logging_config(loggers=CELERY_LOGGERS_DEBUG)

# Multiple presets + custom
LOGGING = get_logging_config(loggers={
    **RQ_LOGGERS,
    "myapp": {"level": "DEBUG", "propagate": True},
})
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LOG_TOKENIZE_SECRET` | Fernet key for PII encryption | Warning value |
| `APP_VERSION` | Application version | "0.0.0" |
| `SERVICE_TYPE` | Service type (app, rq, celery) | Auto-detected |
| `PROJECT_NAME` | Project name in logs | "connect" |

## Dynamic merchant_id

Bind `merchant_id` dynamically per request in your middleware:

```python
from logctx import bind_logging_context

# In your middleware, after identifying the tenant/merchant
merchant_id = get_merchant_from_request(request)
if merchant_id:
    bind_logging_context(extra={"merchant_id": merchant_id})

# All subsequent logs include this merchant_id
logger.info("Processing payment")  # → {"merchant_id": "tenant-123", ...}
```

You can also pass it explicitly: `logger.info("msg", merchant_id="x")`

## Log Output Example

```json
{
  "@timestamp": "2025-01-13T10:30:00.000Z",
  "ecs.version": "1.12.0",
  "message": "Payment processed",
  "log.level": "info",
  "log.logger": "core.payment.views",
  "trace": {"id": "abc123def456"},
  "span": {"id": "req-789-ghi"},
  "user": {"id": 42},
  "client": {"ip": "192.168.1.1"},
  "service": {"name": "app", "version": "1.0.0"},
  "merchant_id": "merchant-123",
  "amount": 100,
  "currency": "KWD"
}
```

## Package Structure

```
logctx/
├── __init__.py             # Core exports (framework-agnostic)
├── context.py              # LoggingContext, get_trace_id, bind_logging_context
├── enums.py                # Entity, Event, RequestDirection, APIType
├── formatters.py           # ECSFormatter
├── ecs_validator.py        # ECS field validator
├── processors.py           # contextvars_injector, mask_sensitive_data
└── contrib/
    └── django/
        ├── __init__.py     # Django exports
        ├── middleware.py   # LoggingContextMiddleware
        ├── processors.py   # Django-aware contextvars_injector
        ├── logging.py      # get_logging_config, setup_logging, presets
        └── context_binder.py  # LogContextBinder (auditlog)
```

## API Reference

### Core (`logctx`)

```python
from logctx import (
    # Context management
    LoggingContext,
    get_logging_context,
    bind_logging_context,
    reset_logging_context,
    logging_context,        # Context manager
    get_trace_id,
    build_traceparent,

    # Enums
    Entity,
    Event,
    RequestDirection,
    APIType,

    # Formatters & Processors
    ECSFormatter,
    ecs_validator,
    contextvars_injector,
    mask_sensitive_data,
    namespace_ecs_fields,
    make_contextvars_injector,
)
```

### Django (`logctx.contrib.django`)

```python
from logctx.contrib.django import (
    # Middleware
    LoggingContextMiddleware,

    # Logging setup
    get_logging_config,
    setup_logging,
    configure_structlog,

    # Logger presets
    RQ_LOGGERS,
    RQ_LOGGERS_DEBUG,
    CELERY_LOGGERS,
    CELERY_LOGGERS_DEBUG,

    # Processors
    contextvars_injector,  # Django-aware version
)

# Auditlog integration (import explicitly)
from logctx.contrib.django.context_binder import LogContextBinder
```

## Framework-Agnostic Usage

For non-Django projects, use the core processors directly:

```python
import structlog
from logctx import (
    ECSFormatter,
    ecs_validator,
    mask_sensitive_data,
    namespace_ecs_fields,
    make_contextvars_injector,
)

# Create processor with your config
contextvars_injector = make_contextvars_injector(merchant_id="my-merchant")

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
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

## License

Proprietary - Ottu