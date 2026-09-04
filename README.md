# ecsctx

Context-aware structured logging with [ECS](https://www.elastic.co/docs/reference/ecs/ecs-field-reference) compliance and [W3C Trace Context](https://www.w3.org/TR/trace-context/) distributed tracing.

Framework-agnostic core with Django, Celery, and RQ integrations.

---

## Table of Contents

1. [What is ECS & Why It Matters](#1-what-is-ecs--why-it-matters)
2. [The Observability Pipeline](#2-the-observability-pipeline)
3. [Architecture: Request Flow](#3-architecture-request-flow)
4. [Core Rules (Field Placement Reference)](#4-core-rules-field-placement-reference)
5. [Quick Start (Django)](#5-quick-start-django)
6. [Quick Start (FastAPI)](#6-quick-start-fastapi)
7. [Full Django Configuration](#7-full-django-configuration)
8. [Context Binding — The Core Concept](#8-context-binding--the-core-concept)
9. [Service Namespace Pattern](#9-service-namespace-pattern)
10. [Celery Integration](#10-celery-integration)
11. [RQ Integration](#11-rq-integration)
12. [Distributed Tracing (W3C Trace Context)](#12-distributed-tracing-w3c-trace-context)
13. [PII Masking & Tokenization](#13-pii-masking--tokenization)
14. [ECS Reserved Fields — The #1 Source of Bugs](#14-ecs-reserved-fields--the-1-source-of-bugs)
15. [Good vs Bad Practices (Hall of Mistake)](#15-good-vs-bad-practices-hall-of-mistake)
16. [Log Levels — Decision Tree](#16-log-levels--decision-tree)
17. [Dry Run: Verifying Your Setup](#17-dry-run-verifying-your-setup)
18. [Vector Configuration](#18-vector-configuration)
19. [Environment Variables Reference](#19-environment-variables-reference)
20. [API Reference](#20-api-reference)
21. [Log Output Example](#21-log-output-example)
22. [Package Structure](#22-package-structure)
23. [Declared Events (`ecsctx.events`)](#23-declared-events-ecsctxevents)

---

## 1. What is ECS & Why It Matters

**ECS (Elastic Common Schema)** is a standard field naming convention for Elasticsearch. Instead of every team inventing their own field names (`user_name` vs `username` vs `user.name`), ECS defines a shared vocabulary: `user.id`, `client.ip`, `trace.id`, `error.message`, etc. ecsctx outputs ECS 1.12.0 compliant JSON.

**Why you should care:** Elasticsearch creates index mappings from the first document it sees. If one service sends `error` as a string and another sends `error` as an object (`{"message": "..."}"`), Elasticsearch gets a **mapping conflict** — it can't store both in the same index. Mapping conflicts silently drop fields. Your logs look fine locally but are missing data in Kibana.

**Data streams** organize logs using the naming pattern `logs-{dataset}-{namespace}` (e.g., `logs-myproject-production`). Elasticsearch automatically manages index lifecycle (rollover, retention, deletion) through data streams. The `dataset` comes from `PROJECT_NAME` and `namespace` from `ENVIRONMENT` — both set as environment variables in your deployment.

> **Reference**: [ECS Field Reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference) — bookmark this. You'll need it when adding custom structured fields.

---

## 2. The Observability Pipeline

```
┌─────────────────────────────────────────────────────────────┐
│                    Your Application                          │
│                                                              │
│   structlog → ecsctx processors → ECS JSON → stdout         │
│   (context injection, PII masking, ECS validation)          │
└──────────────────────┬──────────────────────────────────────┘
                       │  stdout (JSON lines)
┌──────────────────────▼──────────────────────────────────────┐
│                      Docker                                  │
│   Container labels: collect_logs=true, project=X, env=Y     │
└──────────────────────┬──────────────────────────────────────┘
                       │  docker_logs source
┌──────────────────────▼──────────────────────────────────────┐
│                      Vector                                  │
│   1. Collect from labeled containers                        │
│   2. Parse JSON (or keep raw if unparseable)                │
│   3. Ship to Elasticsearch via data stream API              │
│      → logs-{PROJECT_NAME}-{ENVIRONMENT}                    │
│      → pipeline: common-logs                                │
└──────────────────────┬──────────────────────────────────────┘
                       │  HTTPS + gzip + API key auth
┌──────────────────────▼──────────────────────────────────────┐
│               Elasticsearch                                   │
│   https://your-elasticsearch-host/                           │
│                                                              │
│   Data stream: logs-myproject-production                    │
│   Ingest pipeline: common-logs (ECS type enforcement)       │
│   → Kibana dashboards, alerts, search                       │
└─────────────────────────────────────────────────────────────┘
```

**Key takeaway**: Your app writes JSON to stdout. Vector picks it up, ships it to Elasticsearch. The field structure of that JSON determines whether it's searchable in Kibana or silently dropped due to mapping conflicts. That's why ECS compliance matters.

---

## 3. Architecture: Request Flow

```
1. nginx forwards/generates traceparent header (W3C Trace Context)
   → Forward from client if present, generate if missing
                      ↓
2. CidMiddleware reads traceparent, stores in contextvar
                      ↓
3. LoggingContextMiddleware clears stale structlog contextvars
   (left over from the worker's previous request), binds span_id (UUID), client IP
                      ↓
4. Auth middleware authenticates user
                      ↓
5. LoggingContextMiddleware.process_view() re-binds with user_id for authenticated requests
                      ↓
6. Your middleware/views bind domain context (merchant_id, session_id, etc.)
                      ↓
7. View executes, calls logger.info("event_name", field=value)
                      ↓
8. Processor chain:
   contextvars_injector → namespace_ecs_fields → mask_sensitive_data → ecs_validator
                      ↓
9. ECS-formatted JSON → stdout → Vector → Elasticsearch
```

### Processor Chain (Execution Order)

```python
# In StructlogFormatter.foreign_pre_chain:
1. structlog.contextvars.merge_contextvars     # Merge structlog contextvars
2. structlog.processors.TimeStamper(fmt="iso") # ISO 8601 timestamps
3. structlog.stdlib.add_logger_name            # Logger name (module path)
4. structlog.stdlib.PositionalArgumentsFormatter()
5. structlog.processors.CallsiteParameterAdder # func_name, lineno, pathname
6. callsite_ecs_fields                         # ← logger/func_name/pathname/lineno -> log.logger + log.origin.*
7. error_ecs_fields                            # ← Consumes exc_info -> error.{type,message,stack_trace}
8. contextvars_injector                        # ← Injects LoggingContext + trace + service
9. namespace_ecs_fields                        # ← Reshape fields + clean up flat 'level' key
10. mask_sensitive_data                        # ← PII tokenization (HMAC-SHA-256)
11. ecs_validator                              # ← Warn on ECS field violations
12. ECSFormatter                               # ← Format to ECS 1.12.0 JSON
```

### Chain integrations (opt-in, since 0.6.0)

`configure_structlog(integrations=[...])` / `setup_logging(integrations=[...])`
accept objects with an `install(processors) -> list` method, applied in order
to the default chain (exposed as `default_processors()`). The core stays
vendor-neutral: it never names any vendor, and each integration owns its
placement rule and validation. Without integrations the chain is unchanged.

#### Sentry events (`ecsctx[sentry]` extra)

```python
from ecsctx.contrib.django.logging import get_logging_config, setup_logging
from ecsctx.contrib.sentry import SentryIntegration

LOGGING = get_logging_config()
setup_logging(integrations=[SentryIntegration()])  # event_level=ERROR default
```

| Arg | Default | Effect |
| --- | --- | --- |
| `event_level` | `ERROR` | Minimum level that becomes a Sentry **event** |
| `level` | `INFO` | Minimum level recorded as a Sentry **breadcrumb** |
| `ignore_loggers` | `DEFAULT_IGNORE_LOGGERS` | Logger names dropped entirely |

`DEFAULT_IGNORE_LOGGERS` holds `ecsctx.contrib.django.middleware`, whose
`process_exception` logs every unhandled exception for the log pipeline. Sentry
already gets that exception natively off `got_request_exception`, so capturing
the log line too would file one 500 as two issues. Pass an explicit
`ignore_loggers` (`()` for none) to override.

`SentryIntegration` installs `mask_sensitive_data` + `structlog_sentry.SentryProcessor`
as an adjacent pair directly before `error_ecs_fields`: the last spot where
`exc_info` is still present (so the Sentry event carries the real exception)
and masking runs first (so Sentry never sees unmasked containers). Installing
it twice, or into a chain without `error_ecs_fields`, raises at setup time.

Why not sentry-sdk's stdlib `LoggingIntegration`? It hooks
`logging.Logger.callHandlers` and reads the *pre-formatter* `record.msg` — for
structlog records that is the whole event dict, so events arrive as an
unreadable dict repr, group badly, and (because the formatter masks a shallow
copy) top-level `payload` / `args` / `kwargs` / `headers` reach Sentry
**unmasked**. That is also why disabling the stdlib event path in the
consuming project is REQUIRED when using `SentryIntegration` — otherwise the
raw record still ships alongside the masked one:

```python
LoggingIntegration(level=None, event_level=None)  # stop both raw-record paths
```

Turn off both: `event_level` stops the duplicate event, `level` stops the
breadcrumb, which carries the same unmasked dict. `SentryIntegration` supplies
both from inside the chain, masked.

Native exception capture (`DjangoIntegration` etc.) is unaffected either way.

**Scope: native chain only.** `SentryIntegration` runs in the chain used by
`structlog.get_logger(__name__)` calls. Records from plain stdlib loggers
(`logging.getLogger(...)` — third-party libraries, `django.request`) are
formatted through `get_logging_config()`'s separate `foreign_pre_chain` and
are NOT captured by `SentryIntegration`. With
`LoggingIntegration(event_level=None)`, deliberate `logger.error()` calls from
stdlib loggers stop becoming Sentry events (unhandled exceptions still arrive
via `DjangoIntegration`). If you need stdlib-logger events, keep
`LoggingIntegration(event_level=ERROR)` and suppress every namespace you log
through structlog with `sentry_sdk.integrations.logging.ignore_logger`
(fnmatch globs are supported, e.g. `ignore_logger("myapp.*")`) — any structlog
namespace you miss will double-send, one copy being the raw unmasked record.

Since 0.5.6, `configure_structlog()` (the native chain — every plain
`structlog.get_logger(__name__)` call) runs `add_logger_name`,
`CallsiteParameterAdder` and `callsite_ecs_fields` too, so **every** log line
carries `log.logger` and `log.origin.{function,file.name,file.line}` — parity
with the pre-structlog stdlib loggers. An explicit caller-provided
`log={"origin": ...}` (e.g. a decorator recording its decoration site) wins
over the frame-derived values. Note: `logger`, `func_name`, `pathname` and
`lineno` are now consumed keys — a bare kwarg with one of those names is
reshaped into `log.*` instead of landing in `extra.*`.

### Injection Priority

Later sources don't override earlier ones:

1. **Explicit log kwargs** — `logger.info("event", amount=100)` — highest priority
2. **LoggingContext** — bound via middleware, views, tasks
3. **structlog contextvars** — `structlog.contextvars.bind_contextvars()`
4. **CID trace_id** — W3C traceparent parsed from header
5. **Service metadata** — auto-detected `service.name`, `service.version`, `project.name`

### nginx Configuration

Configure nginx to forward the `traceparent` header from clients or generate one if not present:

```nginx
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

---

## 4. Core Rules (Field Placement Reference)

This is the single source of truth for where fields end up in the final log output. The `namespace_ecs_fields` processor enforces these rules.

| Category | Keys | Placement | Notes |
|----------|------|-----------|-------|
| **ECS field-sets** | `http`, `url`, `event`, `span`, `user`, `user_agent`, `client`, `trace`, `service`, `error`, `log` | Root (nested objects) | Must be dicts, never flat strings |
| **Custom namespaces** | `payment`, `project` | Root (nested objects) | `payment.orn`, `project.name` |
| **Sanctioned flat scalars** | `merchant_id`, `session_id`, `view` | Root | Kept flat at root level |
| **Labels** | `labels` | Root (flat dict) | Values should be `str`/`int`/`float`/`bool`; non-scalars are coerced to strings |
| **Payload containers** | `payload`, `headers` | Root | Used in PII masking path |
| **structlog internals** | `message`, `timestamp` | Root | Set by structlog processors |
| **ECS event staging** | `ecs_event` | Root → renamed to `event` | Use `ecs_event` in log calls to avoid structlog's `event` message key conflict |
| **Service-configured root fields** | Keys named in `configure_root_fields()` / `ECSCTX_ROOT_FIELDS` | Root | Service-chosen additions to the allowlist (see below) |
| **Everything else** | Any non-allowlisted key | `extra.*` | Auto-wrapped by `namespace_ecs_fields` |

### Configurable root fields

A consuming service can promote additional keys to root (instead of `extra.*`) without
ecsctx hardcoding its domain schema. Configure in any of three ways (precedence:
explicit call > Django setting > env var):

```python
# 1. Django settings.py — a list of keys
ECSCTX_ROOT_FIELDS = ["customer", "booking"]

# 2. Framework-agnostic env var — comma-separated
#    ECSCTX_ROOT_FIELDS="customer,booking"

# 3. Programmatic, at startup
from ecsctx import configure_root_fields
configure_root_fields(extra_fields=["customer", "booking"])
```

The built-in `ROOT_ALLOWLIST` is never reduced — configured fields only extend it.

**PII handling** (see [section 13](#13-pii-masking--tokenization) for full details):
- **Automatic log masking**: `mask_sensitive_data` processor applies HMAC-SHA-256 tokenization (`ptok:v1:...`) and key-based redaction
- **Explicit encryption API**: `protect()` encrypts (AES-256-GCM), `reveal()` decrypts, `tokenize()` produces deterministic HMAC tokens

---

## 5. Quick Start (Django)

### 1. Install

```bash
pip install ecsctx                       # Core only (framework-agnostic, e.g., FastAPI)
pip install ecsctx[django]               # With Django support
pip install ecsctx[django,celery]        # With Django + Celery
pip install ecsctx[django,rq]            # With Django + RQ
pip install ecsctx[django,auditlog]      # With Django + auditlog integration
pip install ecsctx[django,sentry]        # With Django + in-chain Sentry events
```

Requires Python >= 3.10.

### 2. Configure settings.py

```python
from ecsctx.contrib.django import get_logging_config, setup_logging, CELERY_LOGGERS

# Logging — that's it!
LOGGING = get_logging_config(
    root_level="INFO",
    handler_level="DEBUG",
    use_cid_filter=True,
    loggers=CELERY_LOGGERS,
)
setup_logging()

# Middleware — ORDER MATTERS
MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "cid.middleware.CidMiddleware",              # ← Early: reads traceparent
    # ... security, session, auth middleware ...
    "ecsctx.contrib.django.LoggingContextMiddleware",  # ← AFTER auth middleware
    # ... your app middleware (can bind_logging_context here too) ...
]

# django-cid for trace correlation
INSTALLED_APPS = [
    "cid.apps.CidAppConfig",
    # ... your apps
]
CID_GENERATE = True
CID_HEADER = "HTTP_TRACEPARENT"

# PII is auto-configured from PII_TOKEN_KEYSET_PATH env var
```

### 3. Use in your code

```python
import structlog

logger = structlog.get_logger(__name__)

def my_view(request):
    logger.info("payment_processed", amount=100, currency="KWD")
    # Output includes: trace.id, span.id, user.id, client.ip, service.name, etc.
```

---

## 6. Quick Start (FastAPI)

For non-Django projects, use the core processors directly:

```python
import structlog
from ecsctx import (
    ECSFormatter,
    callsite_ecs_fields,
    error_ecs_fields,
    ecs_validator,
    contextvars_injector,
    mask_sensitive_data,
    namespace_ecs_fields,
)

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.CallsiteParameterAdder(
            parameters=[
                structlog.processors.CallsiteParameter.FUNC_NAME,
                structlog.processors.CallsiteParameter.LINENO,
                structlog.processors.CallsiteParameter.PATHNAME,
            ]
        ),
        callsite_ecs_fields,  # logger/callsite -> log.logger + log.origin.*
        error_ecs_fields,     # exc_info -> error.{type,message,stack_trace}
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

For FastAPI, you'll need to manage `LoggingContext` yourself (no middleware auto-injection):

```python
from ecsctx import bind_logging_context, logging_context, LoggingContext
import uuid

# Option 1: FastAPI middleware
@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    bind_logging_context(
        span_id=str(uuid.uuid4()),
        ip=request.client.host,
    )
    response = await call_next(request)
    return response

# Option 2: Dependency injection
async def inject_logging_context(request: Request):
    bind_logging_context(
        span_id=str(uuid.uuid4()),
        ip=request.client.host,
    )

@app.post("/payments", dependencies=[Depends(inject_logging_context)])
async def create_payment():
    logger.info("payment_created")
```

---

## 7. Full Django Configuration

### get_logging_config()

Returns a complete Django `LOGGING` dict with structlog integration, ECS formatting, and all processors wired up.

```python
from ecsctx.contrib.django import get_logging_config

LOGGING = get_logging_config(
    root_level="INFO",       # Root logger level (default: INFO)
    handler_level="DEBUG",   # Console handler level (default: DEBUG)
    use_cid_filter=True,     # Add CID correlation filter (default: True)
    loggers=None,            # Additional loggers to merge (dict)
)
```

### Logger Presets

```python
from ecsctx.contrib.django import (
    RQ_LOGGERS,           # RQ at WARNING level
    RQ_LOGGERS_DEBUG,     # RQ at INFO level (development)
    CELERY_LOGGERS,       # Celery at WARNING level
    CELERY_LOGGERS_DEBUG, # Celery at INFO level (development)
)

# Production with Celery
LOGGING = get_logging_config(loggers=CELERY_LOGGERS)

# Development with RQ (verbose)
LOGGING = get_logging_config(loggers=RQ_LOGGERS_DEBUG)

# Multiple presets + custom loggers
LOGGING = get_logging_config(loggers={
    **CELERY_LOGGERS,
    "myapp": {"level": "DEBUG", "propagate": True},
})
```

### Middleware Ordering

**This is critical.** Get the order wrong and you'll have missing context in logs.

```python
MIDDLEWARE = [
    # 1. CidMiddleware — EARLY (reads W3C traceparent header)
    "cid.middleware.CidMiddleware",

    # 2. Auth middleware — BEFORE LoggingContextMiddleware
    "django.contrib.auth.middleware.AuthenticationMiddleware",

    # 3. LoggingContextMiddleware — AFTER auth (needs request.user)
    "ecsctx.contrib.django.LoggingContextMiddleware",

    # 4. Your app middleware — CAN use bind_logging_context() here
    "utils.middleware.TenantMiddleware",  # e.g., bind merchant_id
]
```

**Why this order?**
- `CidMiddleware` must run first to extract `trace.id` from the traceparent header
- Auth middleware must run before `LoggingContextMiddleware` because `process_view()` reads `request.user.is_authenticated` to bind `user_id`
- Your app middleware runs after and can add domain context (merchant_id, tenant info)

> **Note:** The middleware binds `user_id` (integer) only. To log full User details (username, email), pass the User object directly in log kwargs: `logger.info("event", user=request.user)` — the Django-aware processor will serialize it to ECS format.

### @api_logging Decorator

For Public DRF/Django views, automatically logs inbound requests and outbound responses:

```python
from ecsctx.contrib.django.decorators import api_logging

@api_logging
class PaymentViewSet(ViewSet):
    # Logs: INBOUND POST /api/v1/payments/ (with headers, body, client IP)
    # Logs: OUTBOUND POST /api/v1/payments/ (201) (with response body, headers)

    logging_ignore_response_keys = ["sensitive_field"]  # Exclude from response logs
```

---

## 8. Context Binding — The Core Concept

Context binding is the mechanism that attaches structured metadata to every log statement within a request's journey. **It can happen at any layer** — middleware, views, serializers, tasks, utility functions — wherever important debug information becomes available.

The key insight: you `bind_logging_context()` once, and every subsequent `log.*` call in that request automatically includes those fields. No need to pass them around or repeat them.

### Where Context Gets Bound (Real Examples)

```python
# Layer 1: Middleware — merchant identified from request host/headers
# (e.g., TenantMiddleware identifies which merchant this request belongs to)
class TenantMiddleware:
    def process_request(self, request):
        merchant = get_merchant_from_request(request)
        bind_logging_context(extra={"merchant_id": merchant.name})
        # Every log from here onwards has merchant_id

# Layer 2: View — domain-specific IDs from the request payload
class WebhookView(APIView):
    def post(self, request):
        bind_logging_context(
            session_id=request.data.get("session_id"),
            extra={
                settings.APP_NAME: {
                    "enterprise_id": request.data["enterprise_id"],
                    "store_id": request.data["store_id"],
                }
            }
        )
        log.info("webhook_received")  # Has: merchant_id + session_id + app-specific IDs

# Layer 3: Task — additional info discovered during processing
@app.task
def process_webhook(self, enterprise_id, store_id):
    # Context from view is auto-propagated (Celery hooks)
    merchant = Merchant.objects.filter(...).first()
    bind_logging_context(extra={"merchant_id": merchant.name})  # NEW info
    log.info("task_started")  # Has everything from view + merchant_id
```

### Two Binding Mechanisms

```python
from ecsctx import bind_logging_context, logging_context

# 1. Direct bind (most common) — middleware handles cleanup at request end
bind_logging_context(session_id="abc123", extra={"merchant_id": "acme"})

# 2. Context manager — auto-restores previous context on exit (scoped)
with logging_context(session_id="abc123"):
    log.info("scoped_event")   # has session_id
log.info("outer_event")        # session_id gone
```

### The `extra` Parameter

`extra={}` contents from `LoggingContext` get **merged to root** before the processor chain runs. The `namespace_ecs_fields` processor then reshapes the event: allowlisted keys stay at root, while all non-allowlisted keys (scalars, lists, and dicts) are wrapped into an `extra` object in the final output.

See the [Core Rules](#4-core-rules-field-placement-reference) table for the complete allowlist.

```python
bind_logging_context(extra={"merchant_id": "acme"})
# "merchant_id" stays at root (allowlisted flat ID)
```

### Deep Merge Behavior

Successive calls **merge** into existing context, not replace:

```python
bind_logging_context(extra={"merchant_id": "acme"})
bind_logging_context(extra={"myapp": {"store_id": "s1"}})
# Context now has both: merchant_id stays at root (allowlisted), myapp goes to extra.myapp
```

### Three Iron Rules

1. **`bind_logging_context()` BEFORE the first `log.*` call.** Always. If you log before binding, that log line won't have context.
2. **Event name is a static string** (`"payment_created"`), never an f-string. Static names are searchable and aggregatable in Kibana.
3. **Dynamic data goes in kwargs or context**, never in the message string.

```python
# WRONG — first log has no context
log.info("webhook_received")
bind_logging_context(session_id=session_id)

# CORRECT — bind first, then log
bind_logging_context(session_id=session_id)
log.info("webhook_received")
```

### Don't Re-state Context in Log Calls

If a field is already bound, don't pass it again:

```python
bind_logging_context(extra={"merchant_id": "acme"})

# WRONG — merchant_id already in context, this is redundant noise
log.info("payment_created", merchant_id="acme")

# CORRECT — it's already there
log.info("payment_created")
```

---

## 9. Service Namespace Pattern

Each service (keyloop, amadeus, shopify, opera) has its own domain-specific IDs (`store_id`, `enterprise_id`, `shop`, `reference`). To avoid cross-service field collisions in Elasticsearch, **namespace service-specific fields under the app name**.

### The Pattern

```python
# Use a settings constant as the namespace key
bind_logging_context(extra={
    settings.KEYLOOP_APP_NAME: {
        "enterprise_id": enterprise_id,
        "store_id": store_id,
        "payment_id": payment_id,
    }
})
```

### What Goes Where

See the [Core Rules](#4-core-rules-field-placement-reference) table for the complete root allowlist. Service-specific fields should be namespaced under the app name to avoid ES mapping conflicts:

| Location | Fields | Why |
|----------|--------|-----|
| **Service namespace** | `enterprise_id`, `store_id` (keyloop), `shop`, `reference` (shopify) | Avoids ES mapping conflicts between services |

### In Log Kwargs (Dynamic Key)

```python
# Use ** unpacking when the namespace key is a variable
log.info("event_started", **{
    settings.SHOPIFY_APP_NAME: {
        "shop": shop_domain,
        "reference": reference,
    }
})
```

---

## 10. Celery Integration

Signal-based context propagation — no decorators needed on individual tasks.

### Setup (Two Lines)

```python
# In your celery app config or a utils/celery.py module
from ecsctx.contrib.celery import install_celery_hooks

install_celery_hooks()
```

### How It Works

`install_celery_hooks()` registers three Celery signals:

| Signal | When | What |
|--------|------|------|
| `before_task_publish` | View calls `task.apply_async()` | Snapshots current `LoggingContext` into task headers |
| `task_prerun` | Worker picks up task | Restores context + generates **new** `span_id` + adds `celery_task` metadata |
| `task_postrun` | Task finishes | Resets context (prevents leakage to next task) |

**Key insight**: `trace.id` is preserved across the entire chain (same distributed trace). `span_id` is unique per task execution (different process boundary).

### View-Dispatched Tasks: Context is FREE

When a view calls `task.apply_async()`, the view's context is automatically propagated. **Don't re-bind fields the view already bound.**

```python
@app.task(bind=True, max_retries=3)
def process_webhook(self, enterprise_id, store_id):
    # ✅ Context from view (session_id, app namespace) is already here
    # DON'T re-bind fields the view already set

    merchant = Merchant.objects.filter(...).first()
    if not merchant:
        log.info("merchant_not_found")  # App namespace IDs come from context
        self.retry(countdown=30)

    # ✅ Bind merchant_id AFTER lookup — this is NEW info the view didn't have
    bind_logging_context(extra={"merchant_id": merchant.name})
    log.info("task_started")
```

### Beat-Dispatched Tasks: Start from ZERO

Celery Beat has no `LoggingContext` to propagate. **You MUST bind everything at line 1.**

```python
@app.task(bind=True, max_retries=3)
def process_payment_inquiry(self, merchant_id, session_id):
    # ✅ Beat task — MUST bind everything, nothing is propagated
    bind_logging_context(session_id=session_id, extra={"merchant_id": merchant_id})
    log.info("inquiry_started")
```

### Quick Reference

| Trigger | Context status | Action |
|---------|---------------|--------|
| `task.apply_async()` from view/task | Auto-propagated | Only bind NEW fields |
| Celery Beat schedule | Empty | Bind ALL fields at line 1 |
| `self.retry()` | Preserved across retries | No re-binding needed |

---

## 11. RQ Integration

Decorator-based context propagation for RQ background jobs.

### Setup

```python
from ecsctx.contrib.rq import with_log_context

@with_log_context
def my_background_task(user_id, amount):
    logger.info("processing_payment")  # Automatically has request context
```

### Manual Context Capture (Custom Enqueue)

If you have a custom job enqueue wrapper:

```python
from ecsctx.contrib.rq import capture_log_context, LOG_CONTEXT_KEY

class RQHandler:
    @classmethod
    def enqueue(cls, func, **kwargs):
        # Capture logging context before enqueuing
        log_context_data = capture_log_context()
        if log_context_data:
            kwargs[LOG_CONTEXT_KEY] = log_context_data

        queue = django_rq.get_queue("default")
        return queue.enqueue(func, **kwargs)
```

### Context Propagation Details

- **Captures**: `LoggingContext` + `trace_id`
- **Restores**: `LoggingContext` + new `span_id` + `rq_job.id` in extra
- **Passed via**: `kwargs[LOG_CONTEXT_KEY]`

---

## 12. Distributed Tracing (W3C Trace Context)

ecsctx implements W3C Trace Context for correlating logs across service boundaries.

### Traceparent Format

```
{version}-{trace-id}-{parent-id}-{flags}
Example: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01

trace-id:  32 hex chars (links all logs in a distributed trace)
parent-id: 16 hex chars (identifies the calling span)
```

### Inbound: Reading Trace Context

Handled automatically by `CidMiddleware` + `LoggingContextMiddleware`:

```python
# settings.py
CID_GENERATE = True
CID_HEADER = "HTTP_TRACEPARENT"
```

### Outbound: Propagating Trace Context

When making HTTP calls to other services, propagate the traceparent:

```python
from ecsctx import build_traceparent

def call_external_api(url, payload):
    headers = {}
    traceparent = build_traceparent()
    if traceparent:
        headers["traceparent"] = traceparent

    response = requests.post(url, json=payload, headers=headers)
    return response
```

This ensures the receiving service can correlate its logs with yours under the same `trace.id`.

---

## 13. PII Masking & Tokenization

ecsctx automatically detects and protects sensitive data in logs. The `mask_sensitive_data` processor walks payload structures recursively (path-aware) to find and tokenize PII, and scans every string value for email/phone patterns.

**Log processor path** (automatic via `mask_sensitive_data`):
- When PII is configured (`PII_PROVIDER=file|vault`): detected values become deterministic **HMAC-SHA-256** tokens (`ptok:v1:...`) for fraud correlation. Same input always produces the same token.
- When PII is not configured: detected values are replaced with `[PII_REDACTED]` — raw PII never appears in logs.

**Explicit encryption API** (standalone, NOT part of the log processor pipeline):
- `protect()` / `reveal()` use **AES-256-GCM** for randomized ciphertext (`penc:v1:<kid>:...`) when reversible encryption is needed. Requires `PII_ACCESS=full`.

Keys are delivered via mounted keyset files or fetched from Vault.

### What Gets Detected

| Type | Detection | Output |
|------|-----------|--------|
| **Emails** | Regex: `user@domain.com` patterns | `"ptok:v1:KeND..."` |
| **Phone numbers** | Regex: 10-15 digits with +/spaces/dashes | `"ptok:v1:x8Fp..."` |
| **Names** | Keys containing: `name`, `customer`, `payer`, `billing`, `shipping`, `cardholder`, `email`, `phone`, `mobile`, `contact`, `recipient`, `beneficiary`, `address`, `udf` | `"ptok:v1:..."` |
| **Auth headers** | `authorization`, `api-key`, `x-api-key` keys | `"Bearer <first4>****<last4>"` (masked, not tokenized; `"Bearer ****"` when the secret is ≤8 chars) |

### Whitelist (NOT Masked)

These keys are safe even though they contain "name":

```
gateway_name, vendor_name, module_name, func_name, task_name, service_name,
app_name, project_name, class_name, method_name, view_name, username,
site_name, domain_name, bank_name, display_name, install_name,
installation_name, event_name, customer_id, id, pk
```

### Path exemptions

Some non-PII fields share a name with a sensitive key — e.g. a payment catalog's `payment_methods[*].name` ("KNET") would otherwise be tokenized. The whitelist above is key-name based and global; for finer control, exempt specific **JSON paths** from key-based tokenization. (Email/phone scrubbing still runs on exempted paths, so a real email never slips through.)

Configure exemptions in any of three ways (precedence: explicit call > Django setting > env var):

```python
# 1. Django settings.py — a list of paths
ECSCTX_MASK_EXEMPT_PATHS = ["payment_methods[*].name", "audit"]

# 2. Framework-agnostic env var — comma-separated
#    PII_MASK_EXEMPT_PATHS="payment_methods[*].name,audit"

# 3. Programmatic, at startup
from ecsctx import configure_masking
configure_masking(exempt_paths=["payment_methods[*].name", "audit"])
```

**Path syntax** (matched relative to the masked container, e.g. inside `payload`):

| Segment | Meaning |
|---------|---------|
| `key`   | a dict key |
| `[*]`   | any array element |
| `*`     | any single dict key (wildcard) |

Matching is a **prefix match**, so a pattern also exempts everything nested below it:

- `payment_methods[*].name` — exempts just that field in every array element
- `payment_methods` — exempts the entire `payment_methods` subtree
- `order.customer.name`, `items[*].tags[*].name` — arbitrary nesting works

### Configuration

PII supports two keyset providers: **file** (for Kubernetes with mounted secrets) and **vault** (for hosts that authenticate directly via AppRole).

All services auto-configure lazily from env vars on first PII operation. No explicit startup call is needed.

**Common env vars (all providers):**

```bash
PII_PROVIDER=file          # "file" or "vault"
PII_ACCESS=tokenize        # "tokenize" (HMAC only) or "full" (HMAC + AES encrypt/decrypt)
PII_ENV=prod               # Environment name for domain separation (tokens differ across envs)
```

**File provider** — keysets are mounted by infrastructure (Vault → ESO → K8s Secret):

```bash
PII_PROVIDER=file
PII_TOKEN_KEYSET_PATH=/var/run/pii/token-keyset.json
PII_REVEAL_KEYSET_PATH=/var/run/pii/reveal-keyset.json   # only if PII_ACCESS=full
```

**Vault provider** — authenticates via AppRole and fetches keysets from KV v2:

```bash
PII_PROVIDER=vault
PII_VAULT_ADDR=https://vault.example.com
PII_VAULT_ROLE_ID_PATH=/etc/pii/vault-role-id
PII_VAULT_SECRET_ID_PATH=/etc/pii/vault-secret-id
PII_VAULT_TOKEN_KEYSET_PATH=secret/data/platform/pii/token-keyset
PII_VAULT_REVEAL_KEYSET_PATH=secret/data/platform/pii/reveal-keyset  # only if PII_ACCESS=full
PII_VAULT_CACERT_PATH=/etc/pii/vault-ca.crt   # optional, for private CA
PII_REFRESH_SECONDS=300                              # keyset refresh interval
PII_VAULT_TIMEOUT=10                                 # HTTP timeout for Vault calls
```

`PII_ACCESS=tokenize` enforces least privilege: only the token keyset is loaded, and `protect()`/`reveal()` raise `PIIAccessDeniedError`.

### How It Works

1. Each masked container (`payload`, `args`, `kwargs`, request/response bodies) is normalized via a JSON round-trip (`default=str` handles UUIDs, Decimals, model instances)
2. The structure is walked recursively, tracking each value's JSON path
3. A sensitive-key string value is tokenized (HMAC-SHA-256) — unless its key is whitelisted or its path is exempted (see [Path exemptions](#path-exemptions))
4. Every string value is also scanned for email/phone patterns and tokenized (defense in depth, even on exempted paths)
5. Auth header values are masked (truncated, not encrypted)
6. Values are normalized before tokenization (emails lowercased, phones to E.164)

### Example Output

```json
{
  "customer_name": "ptok:v1:KeNDkDCY0cXCg3VJU4xf...",
  "email": "ptok:v1:x8FpQm2kL9nR7vBwYzA3...",
  "amount": 100,
  "gateway_name": "knet"
}
```

`amount` is untouched (not a sensitive key). `gateway_name` is whitelisted. `customer_name` and `email` are tokenized.

---

## 14. ECS Reserved Fields — The #1 Source of Bugs

ECS reserves certain field names as **objects with specific sub-fields**. Passing them as flat strings/ints causes Elasticsearch mapping conflicts — fields get silently dropped.

### The Rules

| Field | Correct | Wrong | Why |
|-------|---------|-------|-----|
| `error` | `error={"message": str(e)}` | `error=str(e)` | ECS expects `error.message`, `error.type` |
| `url` | `url={"full": url}` | `url=url` | ECS expects `url.full`, `url.domain` |
| `http` | `http={"request": {"method": "POST"}, "response": {"status_code": 200}}` | `method="POST"` | ECS expects nested `http.request.*` |
| `user` | `user={"name": "john"}` | `user="john"` | ECS expects `user.name`, `user.id` |
| `host` | `host={"name": "web-1"}` | `host="web-1"` | ECS expects `host.name`, `host.ip` |
| `event` | `ecs_event={"action": "login"}` | `event="login"` | structlog uses `event` as message key; use `ecs_event` staging (renamed to `event` in output) |
| `source` | `source={"ip": "1.2.3.4"}` | `source="1.2.3.4"` | ECS expects `source.ip`, `source.address` |
| `server` | `server={"address": "api.example.com"}` | `server="api.example.com"` | ECS expects `server.address` |

### Full List of ECS Reserved Fields

These must always be dicts, never flat values:

```
client, user, host, span, trace, source, destination, server,
event, error, log, http, url, service, file, process, network,
observer, organization, cloud, container, agent, ecs, rule, threat
```

> **Reference**: [ECS Field Reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference)

### Common Trap: The `error` Field

This is the most frequently broken field. Every `except` block tempts you:

```python
# WRONG — will cause ES mapping conflict
except Exception as e:
    log.error("something_failed", error=str(e))

# CORRECT — ECS-compliant dict
except Exception as e:
    log.error("something_failed", error={"message": str(e)})

# EVEN BETTER — include exception type
except requests.HTTPError as e:
    log.error("api_call_failed", error={
        "message": str(e),
        "type": type(e).__name__,
    })
```

### Custom Fields and the Root Allowlist

Only ECS reserved names need the dict treatment. The `namespace_ecs_fields` processor enforces a **root allowlist** — all non-allowlisted keys (scalars, lists, and dicts) get automatically wrapped into an `extra` object. See the [Core Rules](#4-core-rules-field-placement-reference) table for the complete allowlist.

```python
# "merchant_id" stays at root (allowlisted)
log.info("payment_started", merchant_id="acme")

# "disclosure_pk" is not allowlisted — goes into extra.disclosure_pk
log.info("disclosure_created", disclosure_pk=42)
```

### Elasticsearch Indexing: `labels` vs `extra`

- **`labels.*`**: Use for intentionally filterable, low-cardinality keywords (e.g., `labels.env`, `labels.region`). Elasticsearch indexes these as `keyword` by default under the ECS `labels` field.
- **`extra.*`**: Non-filterable detail data. If your Elasticsearch index should not index `extra` children, map it as `flattened` or `enabled: false` in your index template.

```python
# Good: filterable metadata in labels
bind_logging_context(labels={"env": "prod", "region": "us-east-1"})

# Good: non-filterable details as bare kwargs (auto-wrapped into extra)
log.info("payment_processed", amount=100, currency="KWD")
# Output: {..., "extra": {"amount": 100, "currency": "KWD"}}
```

The `ecs_validator` processor will **warn** (not block) if ECS reserved fields are used as flat values. Watch your console during development.

---

## 15. Good vs Bad Practices (Hall of Mistake)

Common mistakes and how to avoid them.

### Mistake #1: Using stdlib `logging` Instead of `structlog`

```python
# ❌ WRONG — stdlib logger, no structlog processors, no ECS compliance
import logging
log = logging.getLogger(__name__)

# ✅ CORRECT
import structlog
log = structlog.get_logger(__name__)
```

stdlib logs bypass the entire structlog processor chain (context injection, ECS formatting, PII masking). They still get captured by `ProcessorFormatter.foreign_pre_chain`, but lose all `LoggingContext` data.

---

### Mistake #2: f-string Log Messages

```python
# ❌ WRONG — dynamic data in message, unsearchable, unaggregatable
log.info(f"Payment processed for merchant {merchant} amount {amount}")

# ❌ ALSO WRONG — printf-style formatting
log.error("OAuth token exchange failed: shop=%s response=%r", shop, response)

# ✅ CORRECT — static event name + structured kwargs
log.info("payment_processed", merchant=merchant, amount=amount)
```

**Why it matters:** In Kibana, you search by `message: "payment_processed"`. With f-strings, every log line has a different message — you can't aggregate, alert, or build dashboards.

---

### Mistake #3: `error=str(e)` — The ECS Violation

```python
# ❌ WRONG — flat string breaks ECS error field mapping
log.exception("invalid_data", error=str(error))

# ✅ CORRECT — ECS-compliant dict
log.exception("invalid_data", error={"message": str(error)})
```

---

### Mistake #4: `log.exception(e)` — Exception as Message

```python
# ❌ WRONG — exception object as first arg, not a structured event name
except Exception as e:
    log.exception(e)

# ✅ CORRECT — static event name, structlog auto-captures exception info
except Exception as e:
    log.exception("payment_processing_failed")
```

---

### Mistake #5: Logging Before Binding Context

```python
# ❌ WRONG — first log has no merchant_id or payment context
def post(self, request, merchant_id, client_payment_id):
    log.info("acknowledgement_received",
        merchant_id=merchant_id,
        client_payment_id=client_payment_id,
    )
    bind_logging_context(...)  # too late for the log above

# ✅ CORRECT — bind first, then log
def post(self, request, merchant_id, client_payment_id):
    bind_logging_context(extra={
        "merchant_id": merchant_id,
        settings.APP_NAME: {"client_payment_id": client_payment_id},
    })
    log.info("acknowledgement_received")
```

---

### Mistake #6: Redundant kwargs Duplicating Context

```python
# ❌ WRONG — session_id already in context, passed again as kwarg
bind_logging_context(session_id=session_id)
log.info("notification_received", session_id=session_id)  # redundant!

# ✅ CORRECT — it's already in context
bind_logging_context(session_id=session_id)
log.info("notification_received")
```

---

### Mistake #7: Service-Specific IDs at Root Instead of Namespaced

When multiple services share the same Elasticsearch index, putting service-specific fields at root level causes naming collisions. For example, two services might both use `store_id` but mean completely different things.

```python
# ❌ WRONG — flat root fields collide across services in the same ES index
bind_logging_context(extra={
    "store_id": store_id,
    "enterprise_id": enterprise_id,
    "external_ref": external_ref,
})

# ✅ CORRECT — namespace under your app/service name
APP_NAME = "my_service"  # or settings.MY_APP_NAME

bind_logging_context(extra={
    APP_NAME: {
        "store_id": store_id,
        "enterprise_id": enterprise_id,
        "external_ref": external_ref,
    }
})
# Output: {"my_service": {"store_id": "s1", "enterprise_id": "e1", ...}}
```

See the [Core Rules](#4-core-rules-field-placement-reference) table for the complete field placement reference.

---

### Mistake #8: `log.error` for Customer Config Issues

```python
# ❌ WRONG — Sentry alert for missing pg_codes (customer config problem)
log.error("pg_codes_not_found")

# ✅ CORRECT — not our fault, not worth waking someone up
log.info("pg_codes_not_found")
```

---

### Mistake #9: Re-binding Context That Was Auto-Propagated

```python
# ❌ WRONG — view already bound these fields, Celery hooks propagated them
@app.task
def process_webhook(self, enterprise_id, store_id):
    bind_logging_context(extra={
        settings.APP_NAME: {
            "enterprise_id": enterprise_id,  # already in context!
            "store_id": store_id,            # already in context!
        }
    })

# ✅ CORRECT — only bind NEW info the view didn't have
@app.task
def process_webhook(self, enterprise_id, store_id):
    merchant = Merchant.objects.filter(...).first()
    bind_logging_context(extra={"merchant_id": merchant.name})  # NEW info
```

---

## 16. Log Levels — Decision Tree

This isn't just style — it directly affects Sentry alert volume and on-call fatigue.

```
Is this a system failure that needs human attention?
├── YES → log.error (triggers Sentry alert)
└── NO
    ├── Is this a customer config problem? → log.info
    ├── Will the task retry? → log.info (alert after retries exhausted)
    ├── Is this expected? (auth fail, 404) → log.info
    └── Debug/development info? → log.debug
```

> **The golden rule: `log.error` = "Wake someone up."** If it's not worth waking someone up, it's not `log.error`.

| Situation | Level | Reasoning |
|-----------|-------|-----------|
| System/infra failure (DB down, API 500) | `log.error` | Needs Sentry alert + on-call |
| Business logic failure (max retries exceeded) | `log.error` | System failed its job |
| Customer config error (merchant not found) | `log.info` | Not our fault |
| Retry-able failure (temporary network blip) | `log.info` | Task will retry |
| Auth failure (invalid token, bad HMAC) | `log.info` | Expected, handled |
| Normal operations (webhook received) | `log.info` | Operational visibility |
| Verbose debugging (raw payloads) | `log.debug` | Filtered in production |

---

## 17. Dry Run: Verifying Your Setup

Before deploying, verify the full pipeline locally.

### Step 1: Check JSON Output Locally

Run your Django app and make a request. Check stdout for valid ECS JSON:

```bash
# Run the dev server
python manage.py runserver

# In another terminal, hit an endpoint
curl -H "traceparent: 00-abcdef1234567890abcdef1234567890-1234567890abcdef-01" \
     http://localhost:8000/api/v1/health/
```

You should see JSON on stdout like:

```json
{
  "@timestamp": "2025-01-13T10:30:00.000Z",
  "ecs.version": "1.12.0",
  "message": "health_check",
  "log.level": "info",
  "log.logger": "core.views",
  "trace": {"id": "abcdef1234567890abcdef1234567890"},
  "span": {"id": "some-uuid-here"},
  "service": {"name": "app", "version": "1.0.0"},
  "project": {"name": "my-project"}
}
```

### Step 2: Verify ECS Field Structure

Check these fields in your JSON output:

| Check | Expected | If Wrong |
|-------|----------|----------|
| `trace.id` present? | 32-char hex string | Check `CID_HEADER = "HTTP_TRACEPARENT"` and `CID_GENERATE = True` |
| `span.id` present? | UUID string | Check `LoggingContextMiddleware` is in MIDDLEWARE |
| `user.id` present? (authenticated requests) | Integer or string | Check middleware is AFTER auth middleware |
| `client.ip` present? | IP address string | Check `django-ipware` is installed |
| `service.name` present? | `"app"`, `"rq"`, or `"celery"` | Check `SERVICE_TYPE` env var or auto-detection |
| `ecs.version` = `"1.12.0"`? | Exactly `"1.12.0"` | Check `ECSFormatter` is in processor chain |
| No flat `error`, `user`, `client` strings? | Always dicts | Read [ECS Reserved Fields](#14-ecs-reserved-fields--the-1-source-of-bugs) |

### Step 3: Verify PII Masking

```python
# In a Django shell or view
import structlog
log = structlog.get_logger(__name__)

log.info("test_pii", customer_name="John Doe", email="john@example.com", amount=100)
```

Expected stdout:

```json
{
  "message": "test_pii",
  "customer_name": "ptok:v1:...",
  "email": "ptok:v1:...",
  "amount": 100
}
```

If `customer_name` shows `"John Doe"` in plain text, check that `mask_sensitive_data` is in the processor chain.

### Step 4: Verify Context Propagation (Celery/RQ)

```python
# In a view, dispatch a task and check worker stdout
log.info("dispatching_task")
my_task.apply_async(args=[...])

# In the Celery worker output, the task log should have:
# - Same trace.id as the view
# - Different span.id (new span for the task)
# - celery_task.id and celery_task.name in the output
```

### Step 5: Verify Vector Pipeline (Docker)

```bash
# Start your stack with Vector
docker compose -f docker-compose.yml -f docker-compose-vector.yml up

# Check Vector is collecting logs
docker compose logs vector

# Uncomment the console sink in vector.toml for debugging:
# [sinks.console]
# type = "console"
# inputs = ["parse_container_logs"]
# encoding.codec = "json"
```

### Step 6: Verify in Kibana

1. Go to Kibana → Discover
2. Select the data stream: `logs-{PROJECT_NAME}-{ENVIRONMENT}`
3. Search: `message: "test_pii"`
4. Verify fields are nested correctly (`trace.id`, not flat `trace_id`)
5. Verify PII is tokenized (`ptok:v1:...`, not plain text)

---

## 18. Vector Configuration

### vector.toml Template

```toml
# Collect logs from labeled Docker containers
[sources.docker_logs]
type = "docker_logs"
include_labels = ["collect_logs=true"]
exclude_containers = ["vector", "nginx", "certbot", "redis", "postgres", "db"]
auto_partial_merge = true

# Parse JSON output from structlog/ecsctx
[transforms.parse_container_logs]
type = "remap"
inputs = ["docker_logs"]
source = '''
parsed, err = parse_json(.message)
if err == null {
    . = parsed
} else {
    .raw_message = .message
    .parse_error = err
}
'''

# Ship to Elasticsearch
[sinks.elasticsearch]
type = "elasticsearch"
inputs = ["parse_container_logs"]
endpoints = ["${ES_URL:-https://your-elasticsearch-host/}"]
api_version = "v8"
mode = "data_stream"
compression = "gzip"
pipeline = "common-logs"

[sinks.elasticsearch.data_stream]
type = "logs"
dataset = "${PROJECT_NAME}"
namespace = "${ENVIRONMENT}"

[sinks.elasticsearch.request.headers]
Authorization = "ApiKey ${ES_API_KEY}"

[sinks.elasticsearch.tls]
verify_certificate = true

[sinks.elasticsearch.buffer]
type = "memory"
max_events = 4096

[sinks.elasticsearch.batch]
max_events = 2048
timeout_secs = 1

[sinks.elasticsearch.request]
retry_attempts = 5
retry_initial_backoff_secs = 1
retry_max_duration_secs = 300

# Uncomment for local debugging
# [sinks.console]
# type = "console"
# inputs = ["parse_container_logs"]
# encoding.codec = "json"
```

### Docker Compose Labels

Add these labels to every container that should have its logs collected:

```yaml
services:
  web:
    labels:
      collect_logs: "true"
      project: "${PROJECT_NAME}"
      service_type: "api"
      env: "${ENVIRONMENT:-dev}"

  celery_worker:
    labels:
      collect_logs: "true"
      project: "${PROJECT_NAME}"
      service_type: "celery"
      env: "${ENVIRONMENT:-dev}"

  rq_worker:
    labels:
      collect_logs: "true"
      project: "${PROJECT_NAME}"
      service_type: "rq"
      env: "${ENVIRONMENT:-dev}"
```

### docker-compose-vector.yml

```yaml
services:
  vector:
    image: timberio/vector:0.43.1-debian
    volumes:
      - ./vector.toml:/etc/vector/vector.toml:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - ES_API_KEY=${ES_API_KEY}
      - ES_URL=${ES_URL:-https://your-elasticsearch-host/}
      - ENVIRONMENT=${ENVIRONMENT:-dev}
      - PROJECT_NAME=${PROJECT_NAME}
    restart: unless-stopped
```

### Data Stream Naming

Your logs land in Elasticsearch under:

```
logs-{PROJECT_NAME}-{ENVIRONMENT}
```

Examples:
- `logs-keyloop-production`
- `logs-event-backend-staging`
- `logs-checkout-dev`

If you use a `common-logs` ingest pipeline, it can enforce ECS field types so malformed fields (e.g., flat `error` string) get flagged at ingest time.

---

## 19. Environment Variables Reference

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `PII_PROVIDER` | Keyset provider: `file` or `vault` | — | **Yes (production)** |
| `PII_ACCESS` | Access mode: `tokenize` (HMAC only) or `full` (HMAC + AES) | `"tokenize"` | Recommended |
| `PII_ENV` | Environment name for token domain separation | `"unknown"` | Recommended |
| `PII_TOKEN_KEYSET_PATH` | Path to HMAC token keyset file (file provider) | — | **Yes** for `file` |
| `PII_REVEAL_KEYSET_PATH` | Path to AES-GCM reveal keyset file (file provider) | — | Only if `PII_ACCESS=full` |
| `PII_VAULT_ADDR` | Vault server URL (vault provider) | — | **Yes** for `vault` |
| `PII_VAULT_ROLE_ID_PATH` | File containing AppRole role_id (vault provider) | — | **Yes** for `vault` |
| `PII_VAULT_SECRET_ID_PATH` | File containing AppRole secret_id (vault provider) | — | **Yes** for `vault` |
| `PII_VAULT_TOKEN_KEYSET_PATH` | Vault KV path for token keyset (vault provider) | — | **Yes** for `vault` |
| `PII_VAULT_REVEAL_KEYSET_PATH` | Vault KV path for reveal keyset (vault provider) | — | Only if `PII_ACCESS=full` |
| `PII_VAULT_CACERT_PATH` | CA cert for Vault TLS (vault provider) | System CA | No |
| `PII_REFRESH_SECONDS` | Keyset refresh interval in seconds (vault provider) | `300` | No |
| `PII_VAULT_TIMEOUT` | HTTP timeout for Vault requests in seconds | `10` | No |
| `APP_VERSION` | Application version in `service.version`. Prefer `ECSCTX_APP_VERSION` in Django settings | `"0.0.0"` + one-time `RuntimeWarning` | No |
| `ECSCTX_ROOT_FIELDS` | Extra root-level log fields (CSV), extends `ROOT_ALLOWLIST` | — | No |
| `SERVICE_TYPE` | Service type: `app`, `rq`, `celery`. Prefer `ECSCTX_SERVICE_TYPE` in Django settings. A declared value beats argv detection | Auto-detected from argv | No |
| `PROJECT_NAME` | Project name in `project.name` + Vector data stream. Prefer `ECSCTX_PROJECT_NAME` in Django settings | `"unknown"` + one-time `RuntimeWarning` | **Yes** |
| `ENVIRONMENT` | Environment name for Vector data stream namespace | - | **Yes** |
| `ES_URL` | Elasticsearch endpoint | `https://your-elasticsearch-host/` | **Yes (production)** |
| `ES_API_KEY` | Elasticsearch API key for Vector auth | - | **Yes (production)** |

#### Service identity: settings first

`project.name`, `service.type` and `service.version` resolve in this order:

1. **Django settings** — `ECSCTX_PROJECT_NAME`, `ECSCTX_SERVICE_TYPE`, `ECSCTX_APP_VERSION`.
   Preferred: settings are versioned code, per service, and reviewed like anything else.
2. **Environment** — `PROJECT_NAME`, `SERVICE_TYPE`, `APP_VERSION`. Still supported, and the
   only route for non-Django consumers.
3. **A default**, with a `RuntimeWarning` emitted once per process.

The unresolved `project.name` default is `"unknown"`. It used to be the literal `"connect"`,
which meant every unconfigured service claimed to be Connect and two services could not be told
apart in a shared index — the warning exists so that is loud rather than silent.

`service_type` does **not** warn when unset: argv detection is a real answer for an RQ worker,
unlike an unnamed project. `app_version` does warn, because `service.version: "0.0.0"` means a
log line cannot be tied to a release.

Settings are read lazily at log time and cached, never at import, so ecsctx still imports
cleanly without Django and before the app registry is ready.

### .env Example

```bash
PII_PROVIDER=file
PII_ACCESS=tokenize
PII_TOKEN_KEYSET_PATH=/var/run/pii/token-keyset.json
PII_ENV=prod
APP_VERSION=1.2.3
PROJECT_NAME=keyloop
ENVIRONMENT=production
ES_URL=https://your-elasticsearch-host/
ES_API_KEY=your-api-key-here
```

---

## 20. API Reference

### Core (`ecsctx`)

```python
from ecsctx import (
    # Context management
    LoggingContext,          # Dataclass holding logging context
    get_logging_context,    # Get current context from contextvar
    bind_logging_context,   # Bind context (non-scoped)
    reset_logging_context,  # Reset to previous token state
    logging_context,        # Context manager for scoped binding

    # Distributed tracing
    get_trace_id,           # Extract trace_id from W3C traceparent
    build_traceparent,      # Build W3C traceparent for outbound requests

    # Formatters
    ECSFormatter,           # ECS 1.12.0 formatter

    # Processors
    contextvars_injector,   # Injects context into log events
    mask_sensitive_data,    # PII tokenization (HMAC-SHA-256)
    namespace_ecs_fields,   # Reshape fields + clean up flat ECS fields
    ecs_validator,          # Warn on ECS field violations

    # PII
    configure_pii,          # Configure PII keyset provider
    pii_configured,         # Check if PII is configured
    tokenize,               # HMAC-SHA-256 deterministic token
    protect,                # AES-256-GCM reversible encryption
    reveal,                 # Decrypt penc:vN:... values
)
```

### Django (`ecsctx.contrib.django`)

```python
from ecsctx.contrib.django import (
    # Middleware
    LoggingContextMiddleware,

    # Logging setup
    get_logging_config,     # Returns complete Django LOGGING dict
    setup_logging,          # Configures structlog + captures warnings
    configure_structlog,    # Configures structlog processor chain

    # Logger presets
    RQ_LOGGERS,             # RQ at WARNING
    RQ_LOGGERS_DEBUG,       # RQ at INFO
    CELERY_LOGGERS,         # Celery at WARNING
    CELERY_LOGGERS_DEBUG,   # Celery at INFO

    # Processors
    contextvars_injector,   # Django-aware version (serializes User objects passed in log kwargs)
)

# Decorators
from ecsctx.contrib.django.decorators import api_logging

# Auditlog (import explicitly to avoid circular imports)
from ecsctx.contrib.django.context_binder import LogContextBinder
```

### Celery (`ecsctx.contrib.celery`)

```python
from ecsctx.contrib.celery import install_celery_hooks
```

### RQ (`ecsctx.contrib.rq`)

```python
from ecsctx.contrib.rq import (
    with_log_context,       # Decorator for RQ job functions
    capture_log_context,    # Capture context for manual enqueue
    LOG_CONTEXT_KEY,        # Key used in kwargs for context data
)
```

### LoggingContext Fields

```python
@dataclass
class LoggingContext:
    span_id: str | None          # → span.id (UUID per request/task)
    user_id: int | None          # → user.id
    ip: str | None               # → client.ip
    session_id: str | None       # → session_id (flat)
    orn: str | None              # → payment.orn
    pg_code: str | None          # → payment.pg_code
    reference_number: str | None # → payment.reference
    extra: dict                  # → merged to root, then reshaped by namespace_ecs_fields
    labels: dict                 # → labels (flat values only: str/int/float/bool)
```

---

## 21. Log Output Example

```json
{
  "@timestamp": "2025-01-13T10:30:00.000Z",
  "ecs.version": "1.12.0",
  "message": "payment_processed",
  "log.level": "info",
  "log.logger": "core.payment.views",
  "trace": {
    "id": "0af7651916cd43dd8448eb211c80319c"
  },
  "span": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  },
  "user": {
    "id": 42
  },
  "client": {
    "ip": "192.168.1.1"
  },
  "service": {
    "name": "app",
    "version": "1.2.3"
  },
  "project": {
    "name": "keyloop"
  },
  "payment": {
    "orn": "ref-123",
    "pg_code": "knet"
  },
  "session_id": "sess-456",
  "merchant_id": "acme-corp",
  "labels": {
    "env": "production",
    "region": "us-east-1"
  },
  "extra": {
    "amount": 100,
    "currency": "KWD",
    "keyloop": {
      "enterprise_id": "ent-789",
      "store_id": "store-001"
    }
  }
}
```

**Field annotations:**
- `trace.id` — from W3C traceparent, links across services
- `span.id` — unique per request/task boundary
- `payment.*` — mapped from `LoggingContext` fields (`pg_code`, `orn`, `reference`)
- `session_id` — flat root field (sanctioned custom ID)
- `labels.*` — low-cardinality keyword metadata for Elasticsearch filtering
- `extra.*` — non-allowlisted keys auto-wrapped by `namespace_ecs_fields`, including service-namespaced fields (`keyloop.*`) and bare scalar kwargs

---

## 22. Package Structure

```
ecsctx/
├── __init__.py                # All public exports
├── context.py                 # LoggingContext, bind/reset/get, trace functions
├── processors.py              # contextvars_injector, mask_sensitive_data, namespace_ecs_fields
├── formatters.py              # ECSFormatter (v1.12.0)
├── ecs_validator.py           # ECS field validation (warn on violations)
├── pii/
│   ├── __init__.py            # configure_pii, tokenize, protect, reveal
│   ├── provider.py            # KeysetProvider ABC
│   ├── crypto.py              # HMAC-SHA-256 + AES-256-GCM primitives
│   ├── keyset.py              # FileKeysetProvider (mtime-based hot-reload)
│   ├── vault.py               # VaultKeysetProvider (AppRole auth)
│   └── normalize.py           # Email/phone normalization for deterministic tokens
├── events/
│   ├── __init__.py            # Public API: EventSpec, register_domain, emit
│   ├── spec.py                # EventSpec — what an event declares
│   ├── registry.py            # Domain prefixes, aliases, freeze()
│   ├── fields.py              # kwarg -> ECS path table
│   └── emit.py                # emit() — build, route, choose level, log
└── contrib/
    ├── django/
    │   ├── __init__.py        # Django exports
    │   ├── middleware.py      # LoggingContextMiddleware
    │   ├── processors.py     # Django-aware contextvars_injector
    │   ├── logging.py        # get_logging_config, setup_logging, presets
    │   ├── decorators.py     # @api_logging
    │   └── context_binder.py # LogContextBinder (auditlog, import explicitly)
    ├── celery/
    │   ├── __init__.py        # Celery exports
    │   └── log_context.py     # install_celery_hooks, signal handlers
    └── rq/
        ├── __init__.py        # RQ exports
        └── log_context.py     # @with_log_context, capture_log_context
```

---

## 23. Declared Events (`ecsctx.events`)

`event.action` is the field a reader looks at first to know what happened, and it
is the easiest one to get wrong — writing a log line takes a string, and a string
is always valid. Before this module, one service carried 34 hand-rolled names:
88% with no namespace, two containing a literal space, one in SCREAMING_CASE.

`ecsctx.events` ships the **mechanism** — how an event is declared, how a domain
claims a prefix, where a field lands. It deliberately ships **no vocabulary**:
your business events stay in your own codebase and register at startup.

### Declaring and registering

```python
from ecsctx.events import EventSpec, register_domain

PG_REQUEST_SENT = EventSpec(
    action="pg.request_sent",
    category=("network",),          # ECS closed set
    type=("connection",),           # ECS closed set
    required=("pg_code", "session_id"),
)
PG_RESPONSE_RECEIVED = EventSpec(
    action="pg.response_received",
    terminal=True,                  # must report an outcome
    category=("network",),
    type=("connection",),
)

register_domain("pg", [PG_REQUEST_SENT, PG_RESPONSE_RECEIVED])
```

Register from your Django `AppConfig.ready()`, then call `freeze()` once app
loading is done — a domain registered after that is invisible to anything that
already read the registry.

`register_domain` rejects a prefix claimed twice, a prefix that is an ECS
field-set name (`log`, `event`, `service`, `trace`, …), and any event whose action
does not live under the prefix it registers with.

### Emitting

```python
from ecsctx.events import emit

emit(logger, PG_RESPONSE_RECEIVED, "Gateway replied in %s ms", elapsed_ms,
     outcome="success", duration_ns=elapsed_ns,
     pg_code="mpgs", session_id=sid, status_code=200)
```

`emit()` builds the `ecs_event=` payload, routes each field to its ECS path,
picks the level, and calls the logger. Positional args pass through untouched, so
lazy `%s` formatting still works.

**Level** comes from the spec: `level` on the success path, `level_on_failure`
when `outcome="failure"` (defaulting to `error` for terminal events). Pass
`level=` to override.

### Field placement

`emit()` routes kwargs so placement stops being a per-developer decision:

| kwarg | lands at |
|---|---|
| `session_id`, `merchant_id` | root (flat) |
| `pg_code`, `order_id`, `orn`, `reference`, `amount`, `currency` | `payment.*` |
| `method`, `status_code`, `request_bytes`, `response_bytes` | `http.request.*` / `http.response.*` |
| `path`, `query` | `url.*` |
| `target`, `target_type` | `service.target.*` |
| `user_id` | `user.id` |
| `error_type`, `error_message` | `error.*` |
| any other scalar | `labels.<name>` |
| any other structure | `extra.<name>` |

An ECS namespace passed whole (`http={"response": {...}}`) still passes through
at root and deep-merges with anything the table placed. The check reads the
**live** allowlist, so a namespace your service claimed with
`configure_root_fields(["wallet"])` or `ECSCTX_ROOT_FIELDS` passes through too —
`wallet={...}` reaches root rather than `extra.wallet`.

### Migrating existing names

```python
from ecsctx.events import register_aliases

register_aliases({"PG_CALL": "pg.request_sent"})
```

`emit(logger, "PG_CALL", ...)` then resolves to the current spec and raises a
`DeprecationWarning`, so old call sites migrate rather than break.

## License

MIT. See [LICENSE](LICENSE).
