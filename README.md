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

> **At Ottu** the source and the destination differ; the JSON is the same. Services write their JSON lines to log files (a rotating file handler) that Vector tails, and ship to daily `logs-YYYY.MM.DD` indices; a PCI service (Ottu PG) ships to `logs-pci-<env>`. The docker-and-data-stream setup here is the generic one.

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
7. View executes, calls logger.info("payment created", field=value)
                      ↓
8. Processor chain:
   contextvars_injector → namespace_ecs_fields → mask_sensitive_data → ecs_validator
                      ↓
9. ECS-formatted JSON → stdout (at Ottu, a log file) → Vector → Elasticsearch
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
- **Automatic log masking**: `mask_sensitive_data` processor applies HMAC-SHA-256 tokenization (`ptok:v1:...`), key-based redaction, and first6/last4 PAN display-masking (see [section 13](#13-pii-masking--tokenization))
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
    logger.info("payment processed", amount=100, currency="KWD")
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
    logger.info("payment created")
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

For Public DRF/Django views, automatically logs the request received and the response sent:

```python
from ecsctx.contrib.django.decorators import api_logging

# path("v1/cards/<str:token>/", CardView.as_view())
@api_logging
class CardView(APIView):
    # Logs: api request received: DELETE /v1/cards/<str:token>/ (with headers, body, client IP)
    # Logs: api response sent: DELETE /v1/cards/<str:token>/ (204) (with response body, headers)

    logging_ignore_response_keys = ["sensitive_field"]  # Exclude from response logs
```

The message names the route the request matched, not its path, so every
request to a view groups under one message and none carries what the URL did.
A regex route (`re_path()`, DRF's routers) reads as its pattern:
`/api/payments/(?P<pk>[^/.]+)/$`. A view called without URL resolution
(`APIRequestFactory` in a test) has no route and names its path.

`url.path` is the path, with each segment a route parameter fills masked by
`mask_by_field_type(value, key_field_type(name))` when the masking engine
classifies the parameter's name: `/v1/cards/[SECRET-MASKED]/` above (the bare
`ptok:` token where PII tokenization is configured — but `[SECRET-MASKED]`
either way for a token shaped like a card number, such as MPGS's sixteen
digits, since a keyed hash of what may be a PAN is what PCI DSS FAQ 1117
forbids). A parameter it leaves alone (`pk`, `uid`) stays readable. A value
that shares its segment with other text (a regex route's
`(?P<token>[^/.]+)\.pdf`) is masked wherever it appears.
`LoggingContextMiddleware`'s `unhandled_exception` line masks its `url.path`
the same way. Django's own `django.request` lines ("Internal Server Error:
<path>") are not ecsctx's, and still carry the path.

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
        log.info("webhook received")  # Has: merchant_id + session_id + app-specific IDs

# Layer 3: Task — additional info discovered during processing
@app.task
def process_webhook(self, enterprise_id, store_id):
    # Context from view is auto-propagated (Celery hooks)
    merchant = Merchant.objects.filter(...).first()
    bind_logging_context(extra={"merchant_id": merchant.name})  # NEW info
    log.info("task started")  # Has everything from view + merchant_id
```

### Two Binding Mechanisms

```python
from ecsctx import bind_logging_context, logging_context

# 1. Direct bind (most common) — middleware handles cleanup at request end
bind_logging_context(session_id="abc123", extra={"merchant_id": "acme"})

# 2. Context manager — auto-restores previous context on exit (scoped)
with logging_context(session_id="abc123"):
    log.info("scoped event")   # has session_id
log.info("outer event")        # session_id gone
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
log.info("webhook received")
bind_logging_context(session_id=session_id)

# CORRECT — bind first, then log
bind_logging_context(session_id=session_id)
log.info("webhook received")
```

### Don't Re-state Context in Log Calls

If a field is already bound, don't pass it again:

```python
bind_logging_context(extra={"merchant_id": "acme"})

# WRONG — merchant_id already in context, this is redundant noise
log.info("payment created", merchant_id="acme")

# CORRECT — it's already there
log.info("payment created")
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
log.info("event started", **{
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
        log.info("merchant not found")  # App namespace IDs come from context
        self.retry(countdown=30)

    # ✅ Bind merchant_id AFTER lookup — this is NEW info the view didn't have
    bind_logging_context(extra={"merchant_id": merchant.name})
    log.info("task started")
```

### Beat-Dispatched Tasks: Start from ZERO

Celery Beat has no `LoggingContext` to propagate. **You MUST bind everything at line 1.**

```python
@app.task(bind=True, max_retries=3)
def process_payment_inquiry(self, merchant_id, session_id):
    # ✅ Beat task — MUST bind everything, nothing is propagated
    bind_logging_context(session_id=session_id, extra={"merchant_id": merchant_id})
    log.info("inquiry started")
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
    logger.info("processing payment")  # Automatically has request context
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

ecsctx detects and protects sensitive data in logs. `MaskPIIFilter` walks each
record (path-aware), masks values by their key name, and scans string values
with content rules. `get_logging_config()` puts it on every handler, where it
masks the record in place — so Sentry's logging integration, `handleError` and
handlers that never call `format()` see masked data too — and the formatter's
`mask_sensitive_data` masks the shaped event again. The second pass is cheap:
strings already known clean are not scanned twice. A record that would not
format once masked — a %-style template masking itself changes (in
`password=%s` the credential rule reads the placeholder as the credential), a
lazy translation or an exception as the message, a number masking turned into
text under `%d` (every conversion CPython's `%` reads, `%.f` included), arguments
that never fit — is rendered from the masked arguments and masked whole, or is
`[MASKING-FAILED: …]`: no line is dropped, and no argument reaches stderr. So
is a record whose line masks differently from its masked arguments: a value
split between the template and an argument (`logger.info("cvv=%s", "123")`)
renders `cvv=[CVV-MASKED]`, for the formatter and for everything that reads the
record. The one exception is a dict or list message with arguments, which
logging cannot format at all: as in stdlib, the line is dropped and
`handleError` prints the arguments, masked. A record whose template masking
leaves as it is, and whose masked arguments render a line with nothing more to
mask, keeps its arguments.

**Log processor path** (automatic via `mask_sensitive_data`):
- When PII is configured (`PII_PROVIDER=file|vault`): detected values become deterministic **HMAC-SHA-256** tokens (`ptok:v1:...`), for fraud correlation. Same input always produces the same token. Where no token can be made (PII not configured, or tokenization failing) the value becomes its type's label, `[EMAIL-MASKED]`; CVV is never tokenized and carries nothing, so it keeps a bracketed label (`[CVV-MASKED]`); a card number is never tokenized either, but its truncation IS carried, so it is bare (`411111******1111`) — under a card key, and with the `pci` pack under any key, including a name or email field. Expiry is not masked at all. A null stays null, and an empty value stays empty.
- When PII is not configured: detected values become the bare label (`[EMAIL-MASKED]`) — raw PII never appears in logs.
- Cardholder data is never tokenized: PANs are truncated to `411111******1111` whatever key they sit under — including, with the `pci` pack (the filter's own or the process's), a name or email field, because a keyed hash beside a truncation of the same PAN is the correlation PCI DSS FAQ 1117 warns about. With `pci`, a value that a PII, secret or id key would tokenize becomes its label instead when it holds a run of 12 or more digits among other text: a PAN typed beside a name, and also a long reference number or hex id, since the check fails closed. A value that is a canonical UUID (8-4-4-4-12 hex digits with a hex letter) holds none and keeps its token. In a phone field, a number written after `+` with at most 15 digits (E.164) is the phone number and keeps its token. An email or phone number found in text is judged the same way: with `pci`, `4111111111111111@example.com` is `[EMAIL-MASKED]` and `+4111111111111111` `[PHONE-MASKED]`, not a keyed hash. CVV is always `[CVV-MASKED]`. **Expiry is not masked**: it is Cardholder Data rather than Sensitive Authentication Data, so PCI permits storing it, and masking it only cost the ability to read an expired-card decline. The rule to remember: **brackets mean nothing survived**.

**Explicit encryption API** (standalone, NOT part of the log processor pipeline):
- `protect()` / `reveal()` use **AES-256-GCM** for randomized ciphertext (`penc:v1:<kid>:...`) when reversible encryption is needed. Requires `PII_ACCESS=full`.

Keys are delivered via mounted keyset files or fetched from Vault.

### Masking packs — PCI services must opt in

Content rules come in packs. Only a service that handles card data needs the
card rules, and running them on every string of every line costs CPU and
mangles numeric ids (a hex `session_id` starting with ten digits reads as a
phone number to a careless rule). A CVV named by its key in text is another
matter: it must not ship from any service, and a default-pack one (Connect)
receives the CVV a saved-card payment sends, so the keyed CVV rules are
`default`.

| Pack | Content rules | On by default |
|------|---------------|---------------|
| `default` | PEM keys, a JSON object a service's [value rule](#value-rules-a-services-own-shapes) matches (a label rule's label; what a [keep rule](#keep-rules) ships is set aside before every rule and put back as written), credentials (`token=…`, `"secret": …`, `Bearer …`, `API-Key …`, `<password>…</password>`, `password=['a', 'b']`), keyed CVV (`cvv=123`, `"securityCode": "123"`, `CVV 123`, `vpc_CardSecurityCode=123`, `paymentCvv=123`), an XML element named as a card, CVV or SAD key (`<cvv>123</cvv>`, `<pin>1234</pin>`, `<cardNumber>…</cardNumber>` truncated), a URL's userinfo, phone numbers, emails, JWTs | always |
| `pci` | PANs (truncated), a bare 3–4 digit CVV beside a card number or its truncation (`4111111111111111 123`, `411111******1111\|12/27\|123`) or after a CVV word (`the cvv is 123`) | no |
| `financial_ids` | IBANs, SSNs, payment/transaction/auth ids (content and key names) | no |

A PCI-scoped service enables them in its logging config:

```python
LOGGING = get_logging_config(masking_packs=("pci", "financial_ids"))
```

or with `ECSCTX_MASKING_PACKS = ["pci", "financial_ids"]` in Django settings,
or `ECSCTX_MASKING_PACKS=pci,financial_ids` in the environment (precedence:
the argument, then the setting, then the env var). `default` is always on. An
unknown pack name in the setting or env var fails closed — every pack is on,
with a warning, and the boot check reports it.
Upgrading from 0.7.x without opting in turns PAN content scanning (and the
bare-digit CVV rule) **off**.

The bare-digit CVV rule reads only the fields written after a card number or
its truncation — up to three, joined by whitespace, `|`, `,`, `;` or `:` — and
masks each that is three or four digits alone: which of `1227` and `123` after
a card is its CVV no rule can tell, so neither ships. A date (`12/27`), a field
after an expiry word (`exp 1227`), a month or year of one or two digits, and
digits that run on into a date, a time or an amount (`2026-09-30`, `10:30`,
`100.000`) stay. Before 0.15.6 it masked any 3–4 digit group in a line that
mentioned a card: `card list returned 200 in 350 ms` lost its status and its
duration, `declined with code 051` its code.

Key names are checked in every service regardless of packs: a key named
`card`, `pan`, `card_number`, `cvv`, `securityCode`, … masks its value wherever
it appears, and so does an XML element of that name in text. Expiry keys (`expiry`, `exp_month`, `expiry_year`, …) do not: they
are safe keys, and read through.

### PAN truncation (`mask_pan`)

Logs are stored data, so PCI DSS 3.5.1 truncation applies. PANs of 15–19
digits keep the first 6 and last 4 (`411111******1111`), the format every
brand accepts (PCI SSC FAQ 1091); shorter PANs keep only the last 4
(`*********6789`), because FAQ 1091 covers them only for Discover. No token
or hash is emitted beside a truncated PAN (FAQ 1117). `mask_pan` returns the
same bare core for call sites that must mask a PAN before logging:
`from ecsctx import mask_pan`.

### Masking a value with no key beside it (`mask_card_value`, `mask_secret`)

A value that reaches a log outside a mapping — a URL segment, a body a service
builds itself — is masked as the key it would sit under masks it:

- `mask_card_value(value)` — a card key's value: a PAN truncated
  (`411111******1111`), anything that is not one left readable, and a value
  that could still hide one refused as `[CARD-MASKED]`. Masking its output
  again changes nothing. A group of digits and stars long enough to be a
  card number is shown only in a truncation's shape — the first six digits at
  most, four stars or more, the last four at most — and a card number's
  groups (4-4-4-4, Amex 4-6-5, Diners 4-6-4; a space, dash or invisible
  separator apart) are read as one, so another masker's `45087****001019`
  (the last six of fifteen), `4508-750*-****-1019` (the first seven of
  sixteen) and `3782 822*** *0005` are refused, while `4111********1111`,
  `3782 82**** *0005` and `**** **** **** 1111` are shown. In a value with
  twelve digits or more, every group of digits and stars must be one the card
  rule writes (`4508750****001019` is refused).
- `mask_secret(value)` — a credential key's value: the bare token
  (`ptok:v1:…`) where PII tokenization is configured, `[SECRET-MASKED]` where
  it is not. It is `[SECRET-MASKED]` either way for a value shaped like a card
  number (a saved card's sixteen-digit gateway token: FAQ 1117 again), for
  a placeholder another masker left (`[REDACTED]`, `[PII_REDACTED]`, `***`,
  `Bearer ****`), which would otherwise hash to one token shared by every
  record that carries it, for a value in a token's exact shape with a card
  number in it (`ptok:v1:` typed before one), and for a card number's
  truncation (`411111******1111`: ten digits of a saved card's gateway
  token), after an auth scheme too (`Bearer 411111******1111`: never a token
  of the scheme and the truncation) — each judged as written and as a
  URL or form encoding decodes it (`%224111…%22`, `4111+1111+…`). With
  `pci` among the call's packs, and the process's — a `MaskPIIFilter`'s own
  `packs=` while it masks, with the process's — it is `[SECRET-MASKED]` too
  for any value that holds a card-number run (`abc4111111111111111xyz`), as
  under a credential key: in a pci-configured process every filter labels
  it, and a filter built with pci labels it in any process. Without `pci`
  in either such a value is hashed, since a default-pack service receives
  no card numbers. An empty value stays empty;
  `None` and booleans come back as they are.

Both are `from ecsctx import mask_card_value, mask_secret`.

### Network-boundary redaction (`ecsctx.contrib.net`)

`mask_sensitive_data` masks a credential its rules name wherever it appears in a
record — `password=…` in a URL's query, `"access_token": "…"` in body text, a
URL's userinfo, `cvv=123` — but these helpers know their input: a query param
whose name only hints at a credential (`username`, `P`, `sign`), a card number
under its key in a query or form body, a literal secret in a URL's path, a
body masked by its keys before it is serialised and capped.
Import them instead of copying them per service:

```python
from ecsctx.contrib.net import (
    loggable_body, loggable_request_body, redact_body, redact_url, url_host,
)
```

- `redact_url(url)` — masks a URL's userinfo (`https://<user>:<password>@host`,
  each part as it decodes, the host and port kept) and credential-looking
  query and fragment params (`password`, `api_key`, `access_code`,
  `#access_token=…`, … incl. single-letter legacy keys) before logging, and a
  param whose key the key rules call a card, CVV or other SAD
  (`card_number=411111******1111`, `vpc_CardSecurityCode=[CVV-MASKED]`,
  `pin=[SAD-MASKED]`). A masked param's value is replaced in place, unencoded;
  every other param is left exactly as written, an empty value stays empty, a label in the
  userinfo is percent-encoded (`%5BSECRET-MASKED%5D`) so the URL still parses,
  and a URL that cannot be parsed is masked whole. `ecs_url(full_url)` calls
  it for you; call it yourself for a URL logged anywhere else, or to name a
  literal secret (`ecs_url(redact_url(full_url, secrets=[token]))` — masking
  twice masks once).
- `redact_body(text)` — masks credential values (`access_token`,
  `client_secret`, …) in JSON, form-encoded and XML bodies. A value is masked
  as what it decodes to (a JSON escape, a form encoding, XML entities or a
  CDATA section), and one already masked passes through. A form value runs to
  the next `&`, whitespace or end tag; the quotes and closing brackets at its
  ends stay as written (`<Auth password="[SECRET-MASKED]"/>`). A value, JSON,
  form or XML, holding a card-number run is `[SECRET-MASKED]` either way. A
  form field whose key the key rules call a card, CVV or other SAD is masked
  by that type, as in a URL (`cvv=[CVV-MASKED]&card_number=411111******1111`).
  A bare `token` key is masked as the key walk masks it: a saved card's
  sixteen-digit gateway token is `[SECRET-MASKED]`, and any other value its
  token (with a keyset, so a gateway's payment or session id still
  correlates) or label.

  An XML element is read as a key (KNET's KPay takes XML): its local name,
  whatever its namespace prefix and attributes, case-insensitively. A card,
  CVV or SAD name masks its text by that type, as the text rules do
  (`<cvv>[CVV-MASKED]</cvv>`, `<cardNumber>411111******1111</cardNumber>`),
  and a card element holding elements — a card object, CyberSource's
  `<card>` — is read field by field: a CVV or SAD field is its label and
  any other field's text a card value, so `<accountNumber>` is truncated
  and an expiry reads through. Then a credential name — one `redact_url`
  reads as a credential param (`password`, `pwd`, `auth`, `user`, `sign`,
  `key`, …) or one of the secret keys — masks its text as a credential
  (`<password>ptok:v1:…</password>`), to its end tag, children and all, a
  CVV inside it already its label. So `<auth>`, `<user>`, `<signature>` and
  `<key>` are credentials, as the same names are in a URL's query: one
  reading of a name across a URL and a body, rather than an exception for
  one gateway's elements. A name is matched by substring, as a param's is,
  so `<author>`, `<design>`, `<monkey>`, `<userType>` and `<keyword>` are
  masked as credentials too: the accepted cost of failing closed. A start tag with no end tag is no element: a
  route (`/v1/cards/<str:token>/`) has that shape. JSON or XML in an
  element's text, written with entities, goes through these rules as it
  decodes and is written back escaped.

  A value a service's [value rule](#value-rules-a-services-own-shapes)
  matches is its label before anything else reads it, as JSON anywhere in
  the body — an XML element's text included — or as JSON in a JSON
  string. What a [keep rule](#keep-rules) ships is then set aside, and put
  back as it was sent once the body rules have read the rest: a
  credential's JSON value (`"token": "{\"version\"…}"`), an extra secret
  key such as `signature` and a form value never read into it. An
  element's entity-encoded JSON is read as it decodes, and an element
  whose text keeps a value is set aside as it was written.
- `redact_url(url, secrets=[token])` also masks literal values anywhere in
  the URL, longest first — a saved-card token in a path such as
  `/card/<token>/`.
- `url_host(url)` — the host to name in a log *message*; the full URL belongs
  in `url.full`, because a message is a grouping key.
- `loggable_body(response)` — the response body to log, or `None`. A
  deny-list (`UNREADABLE_CONTENT_TYPES`: HTML, CSV, PDF, images, archives)
  rather than an allow-list, because gateways mislabel JSON as `text/plain`
  or omit `Content-Type`; an HTML/PDF body is still kept when the status is
  4xx/5xx, since an edge proxy's block page is the whole explanation. A JSON
  body is masked by its keys before it is serialised (so `"securityCode"` is
  caught without the `pci` pack), then redacted **before** capping, so a cap
  landing mid-value cannot leave a token head exposed.
- `loggable_request_body(data, json_body)` — the same for the outbound half
  (`json_body` wins over form `data`); never raises.

Both cap what they return at `ECSCTX_REDACT_BODY_LOG_CAP` characters, 4096 by
default. That cuts an Apple Pay token, roughly 5 KB, short: a service that
logs wallet tokens as sent ([keep rules](#keep-rules)) raises the cap.

Every credential these helpers mask is masked as `mask_secret` masks one: its
token where PII tokenization is configured, `[SECRET-MASKED]` where it is not
(and for a card-shaped value or a placeholder), so it carries the token the
same value gets under a key. `redact_body` gives `[SECRET-MASKED]` to a body
value that holds a card-number run in every pack; `mask_secret` does with `pci`
among the call's packs, and the process's, so there the two agree, and without
it `mask_secret`
(and so `redact_url`) hashes such a value. Before 0.15.4 they wrote a fixed
`[REDACTED]`, whatever the keyset.

The credential text rules followed by `redact_body` are a fixed point: after a
scheme word, a form value `redact_body` masked (`Bearer password=<token>`) is
no longer read as the scheme's credential and hashed again, while a credential
glued to a key name (`Token abc123abc123api_key=…`) still is (0.15.6).

Configure per deploy without code changes. Precedence: explicit call >
Django settings > env vars > defaults (same lazy pattern as the masking
exemptions — settings are read via a guarded import, so there is no
hard Django dependency; pure-Python/FastAPI consumers use the call/env path):

```python
from ecsctx.contrib.net import configure_redaction
configure_redaction(extra_secret_keys=["merchant_pin"], body_log_cap=8192)
```

```python
# Django settings.py (list or CSV string)
ECSCTX_REDACT_EXTRA_SECRET_KEYS = ["merchant_pin", "terminal_secret"]
ECSCTX_REDACT_BODY_LOG_CAP = 8192
```

### Shared ECS boundary shapers

The same module holds the request/response shaping helpers every service
needs, so call sites compose redaction + ECS in one place:

```python
from ecsctx.contrib.net import ecs_http, ecs_url, parse_json_or_raw

url = ecs_url(full_url)  # {"full": ..., "domain": ..., "path": ...}, query redacted
http = ecs_http(request_method="POST", response_status_code=200)
payload = parse_json_or_raw(response.content)  # real JSON, or the raw body untouched
```

Two structlog processors apply the same normalization automatically when a
call site logs a raw value (exported from `ecsctx`): `normalize_url_field`
shapes a bare-string `url=`, `normalize_payload_field` parses a bytes
`payload=` (bytes-only by design — auto-parsing `str` would silently change a
plain-text payload's type via JSON's bare primitives).

Order matters: `normalize_payload_field` must run **before**
`mask_sensitive_data` — the masker only walks parsed structures, so a bytes
`payload=` reaching it first gets regex-only scrubbing, then parses into an
unmasked dict with no second masking pass:

```python
processors=[
    ...,
    normalize_payload_field,  # bytes payload -> parsed JSON, first
    normalize_url_field,      # bare-string url -> ECS url object
    mask_sensitive_data,      # ... then mask the parsed structure
    ...,
]
```

```bash
ECSCTX_REDACT_EXTRA_SECRET_KEYS="merchant_pin,terminal_secret"
ECSCTX_REDACT_BODY_LOG_CAP=8192
```

### What Gets Detected

A key name marks its value when the lowercased key **contains** a keyword, so
glued and plural names payloads use (`phonenumber`, `cardcvv`, `nameoncard`,
`tokens`) are caught; the known false positives are listed below as safe keys.
Card keys are matched precisely. Expiry keys are not masked at all: they are
safe keys (the expiry spellings in the whitelist below).

| Type | Key names | Content rule (pack) | Output |
|------|-----------|---------------------|--------|
| **Secrets** | ending in `token`, `secret`, `password`, `passwd`, `passphrase`, `passcode`, `pwd`; `authorization` (also `HTTP_AUTHORIZATION`, `Proxy-Authorization`), `cookie`, `bearer`, `basic`, `digest`, `credential(s)`, an `api`/`access`/`secret`/`private`/`hmac`/`merchant`/… `_key(s)`, `access_code` | credential forms (`default`) | `[SECRET-MASKED…]`; always the label for a PAN-shaped credential (never truncated, never hashed), for a placeholder another masker left (`[REDACTED]`, `***`) and for a token-shaped value with a card number in it; with `pci`, also for a credential or payment id that holds a card-number run anywhere |
| **Emails / phones** | containing `email`; `phone`, `mobile`, `tel` | `default` | `[EMAIL-MASKED…]`, `[PHONE-MASKED…]`; with `pci`, the label for one that holds a card-number run (a phone number after `+` up to E.164's 15 digits keeps its token) |
| **Names / addresses / other PII** | containing `name`, `cardholder`, `payer`, `beneficiary`, `recipient`; `card_details` (the whole key); `address`; `billing`, `shipping`, `customer`, `contact`, `udf` | — | `[NAME-MASKED…]`, … |
| **PANs** | `card`, `pan`, `card_number`, `cardNumber`, `card_no`, `card_num` (MIGS's `vpc_CardNum`) | 12–19 digit runs (`pci`); an XML element so named (`default`) | `411111******1111` |
| **CVV** | containing `cvv`, `cvc`, `security code`, `verification value`, or the words `csc`, `cvd`, `cvn`, `card code` — unless what follows names something *about* one (`cvv_required`, `cvvResult`, `cardSecurityCodeError`) | keyed CVV and an XML element so named (`default`), a bare 3–4 digit group beside a card number or its truncation, or after a CVV word (`pci`) | `[CVV-MASKED]` |
| **SAD** | track data (`track2`, `trackData`, `raw_track`; not `track_id`), `pin`/`pinBlock`, EMV/chip data, and ending in `cryptogram`, `cavv`, `tavv`, `aav`, `ucaf` | an XML element so named (`default`) | `[SAD-MASKED]` |
| **A service's value rules** | none: found by shape under any key, as a mapping or as JSON text ([value rules](#value-rules-a-services-own-shapes)) | the same shapes as JSON in text, or in a JSON string (`default`) | a label rule's label, the whole value; a [keep rule](#keep-rules)'s match as sent |
| **National ids** | `civil_id`, `national_id`, `passport`, `iqama`, `qid`, `cpr`, `nid`, `emirates_id`, `ssn`, `tin`, `tax_id`, `aadhaar`, `id_number` | — | `[SSN-MASKED…]` |
| **IBAN / SSN / payment ids** | `payment_id`, `transaction_id`, `auth_id` (`financial_ids`) | `financial_ids` | `[IBAN-MASKED…]`, … |

A PII container — a dict or list under a key such as `customer`, `billing` or
`contact` — keeps its shape: each field is masked on its own (an `email` field
gets an email token, so the same address correlates across records), a safe key
such as `id` stays readable, and any other field is tokenized as the container's
type. A **card** container keeps its shape too: the PAN truncates to first six
and last four, expiry and scheme read through, and the CVV, track data and PIN
are destroyed — collapsing it threw away the one form PCI DSS 3.5.1 permits us
to keep.

A value a service's **value rule** matches is that rule's label whole, in
every pack and under any key, never hashed — or, for a keep rule, the value as
sent; it is found by shape, so anything else under the same key reads as
before. A value encoded into another field (hex, base64) has no shape to find,
and is left to that field's key.

Since 0.14.0 a **credential, CVV or SAD** key holding a container is walked as
well, because it cannot be holding the value itself: a leaf with no rule of its
own still takes the container's type, and under a CVV or SAD key only a key the
service lists reads through. A card-shaped object under a credential key (a
number plus an expiry — a saved card under `token`) is walked as the card it is.

A **`{name, value}` pair** — `{"name": "customer_name", "value": "…"}`, a HAR
header list — masks its value as the type its identifier names, and the
identifier (a field label) reads through. A bare `name` is a thing's name, not
a person's, under a container named by a thing (`payment_method.name`,
`merchant.name`, `items[].name`). Booleans are never masked. A dataclass or
namedtuple is masked by its field names and rendered back to its repr text.

A credential value found in text (`password=…`, `"token": "…"`, `Bearer …`)
runs to its delimiter, as a form value in `redact_body` does: an unquoted one
to whitespace, `&`, `;`, `,`, a closing bracket or a closing quote (a quote
followed by a JSON key's `":` or an element's `/>` is structure too); a quoted
one to its unescaped closing quote, spaces and all. Neither runs into an end
tag: in `<note>password=abc</note>` the value is `abc`. An empty pair of quotes
is no value: doubled as CSV and SQL escape a quote (`password=""s3cret`), they
are structure before it. A value between escaped quotes — JSON in a JSON
string, `{\"password\": \"correct horse\"}` — runs to its matching escaped
quote too. A backslash, `@`, `#` or an
apostrophe inside a value no longer ends it early, leaving the rest in clear —
except that a `#` right after a whole token opens a URL's fragment, so
`redact_url`'s `?password=<token>#access_token=<token>` keeps both tokens. A
double-quoted value is masked as the JSON string it decodes to, so it carries
the token the same value gets under a key. A value never starts with a quote
or an opening bracket (`{`, `[`, `(`, `<`), and never runs into a label masking
already wrote (`abc[SECRET-MASKED]`). After `Authorization:` (or
`Proxy-Authorization:`, `authorization=`) the scheme and the credential are one
value — `Authorization: Bearer abc…` carries the token the header gets under its
key, not one for `Bearer` with the credential beside it. A whole token right after
the scheme — what masking the credential alone leaves,
`Authorization: Bearer ptok:v1:…` — is left as it is, not hashed again with its
scheme. Ottu's `API-Key` scheme word standing alone does the same, without its
`Authorization:` — `sending API-Key abc123XYZ to core` carries the header's
token, `mask_secret("API-Key abc123XYZ")` — for any key after it, digits or
none, however short: the word is the evidence (`Bearer` and the other schemes
keep their eight characters and a digit, since prose says "Bearer of bad
news"). A header name ending in the word (`X-API-Key <key>`) is no scheme, and
its key alone is masked. A credential
keyword that names a CVV or PIN (`cvv_token=123`, `pin_password=1234`) gives
that label (`[CVV-MASKED]`, `[SAD-MASKED]`), as the key does, never a token.

A container after a credential keyword — `password=%(pw)s` rendered with a list,
`password=['a', 'b']`, or a mapping's repr, `{'password': ('a', 'b')}` — is the
credential's value whole: its token, or the label (a repr's value kept a
string). Not a JSON key's container, which the key walk masked by its keys
before writing it, nor one holding only masking's own output.

An XML element named by a credential keyword — `<password>s3cret</password>`,
`<wsse:Password Type="…">…</wsse:Password>`, `<Authorization>Bearer x</Authorization>`
— is masked to its end tag, as it decodes, in every pack, for a body that never
went through `redact_body`; a start tag with no end tag (a route,
`/v1/cards/<str:token>/`) is no element. So is an element named as a card, CVV
or SAD key, as `redact_body` masks it: `<cvv>123</cvv>` is
`<cvv>[CVV-MASKED]</cvv>`, `<pin>1234</pin>` `<pin>[SAD-MASKED]</pin>`, and
`<cardNumber>` truncated — a test card that fails Luhn too, with or without
`pci` — and a card object is read field by field. A CVV inside a credential's
element is its label before the credential is masked, as under a credential
key. A JSON object a service's label rule matches, written in text or as
JSON in a JSON string, is the rule's label before any credential rule reads
it. One a keep rule matches is set aside before every rule and put back as it
was written: `token={…}`, `"token": {…}`, `Bearer {…}` and
`<password>{…}</password>` keep it, the payment-id rule never reads its
`"transactionId"`, and none is kept right after a CVV or SAD key
(`<cvv>{…}</cvv>`, `"securityCode": {…}`).

A URL's userinfo in text — a DSN in an exception,
`postgresql://user:password@db:5432/app` — is masked part by part as
`redact_url` masks it, keeping the scheme, host and port: with a password,
empty or not (`https://key:@host`). A user alone (`ssh://git@host`) is left to
the other rules, unless it is shaped like a card number or holds a card-number
run (`https://9923960000004314@host/`, a saved card's gateway token): that is
`[SECRET-MASKED]`, as `redact_url` gives it. The email rule never starts inside
masking's own output, so a token or label in a URL's userinfo keeps the host
after it.

A digit run that touches a letter is never a phone number — it is part of an
id. The card rule still matches a PAN followed by a letter, because Track 2
data puts a `D` separator right after it.

The card rule reads a whole run of digit groups separated by a space, a hyphen,
an invisible character (a zero-width space) or, between card-style groups that
are all of their run, a Unicode dash (`5123–4500–0000–0008`; with other digits
in the run, `5123–4500–0000–0008 12 25`, the dashes join a range). Where the
digits around a separator are one card or a card beside another number, Luhn
decides, and no output shows more than the first six and last four of any
Luhn-valid reading of 12–19 digits, except over digits the rule leaves as
something else's (below). An unbroken run of 12–19 digits is a card number
wherever it stands (`4111111111111111 1234` → `411111******1111 1234`); a number
written in groups is read whole with a short group after it
(`5123 4500 0000 0008 12` → `512345********0812`); a card number written in
groups may follow digits that belong to a word, a phone number or another card
(`INV-2026 4111 1111 1111 1111`), or be glued to a word in card-style groups
(`Payer5123 4500 0000 0008 12 25` → `Payer512345******0008 12 25`); and in a
longer run written in groups every Luhn-valid reading is truncated.

Left whole: a longer number with no Luhn-valid reading in it; an id glued to a
word (`REF4111111111111111`); a phone number written after `+` with at most 15
digits (E.164), even one that is also a card number's digits
(`+378282246310005 12`); a range joined by a Unicode dash (`20260901–20260903`),
whose sides are two numbers and never one reading across the dash; and an IBAN
written in groups, only as far as the IBAN itself — its country's registered
length, in groups of four joined by single spaces, with check digits that hold.
Digits after the IBAN, or after a tab or a line break, are read as any others;
after a bank code with letters (`GB33 BUKB 2020 1555 5555 55`,
`IT60 X054 2811 1010 0000 0123 456`) the digits are the IBAN's only when the
IBAN ends where their run does. An unbroken 12–19-digit run after an IBAN's
check digits is still a card number (`DE89 370400440532013000` →
`DE89 370400********3000`). A canonical UUID — 8-4-4-4-12 hex digits with a hex
letter among them, nothing alphanumeric touching it — is left whole
(`request 26888535-1296-4273-8ba1-c634e90bf52f failed`), and a card number
beside one is still truncated; an all-digit string in that shape is read as any
other digits.

Accepted residuals: a card number in groups that are not card-style, glued to a
word or to a truncation's stars, or split by a range's dash, shows what the rule
reads of it; one typed into a UUID's own groups
(`41111111-1111-1111-abcd-ef0123456789`) stays whole; the phone rule, which runs first, takes phone-shaped digits at a
card number's end — ten unbroken digits before a Unicode dash
(`4731592604–8–7311` → `[PHONE-MASKED]–8–7311`), or a card's last digits with
those after them (`2026-09-26 7112\t1817\t9153\t4791\t968 433 4111` →
`2026-09-26 7112\t1817\t9153\t4791\t[PHONE-MASKED]`) — and what is left of the
card may no longer read as one; and a card number that, after a country code,
check digits and a bank code with letters, makes exactly that country's IBAN
length with check digits that hold (one time in 97) is read as the IBAN. Under a
card key those values are refused (`[CARD-MASKED]`): a card key shows its scan
only when no Luhn-valid reading in the value shows more than its first six and
last four, no run of card-number length is left beside the truncations, dots
and slashes joining it too (`4111.1111.1111.1111`), and fewer than twelve
digits show outside the truncations however they are joined — double spaces,
commas, another masker's `X`s (`411111******1111, 4111,1111,1111,1111` is
refused). Nor may twelve digits show in a row, however joined: bare digits, a
truncation's last four and the next one's first six count together, as a card
number could be read across them, while a truncation's own stars separate its
first six from its last four, and a word (not a run of `X`s, which another
masker writes) ends a row. So `4111111111  111111******1111`,
`400001******5018  00  000009******0001` (the Maestro 501800000009 shows in a
row) and `512345******0008 12 25 512345******0008` are refused. One residual
remains: a short group beside a truncation, under twelve digits with it —
`450875******1019 000` could, in theory, be a 19-digit number another masker
cut oddly.

### Structural fields (never scanned)

ecsctx's own metadata (`service.name`/`version`, `project.name`,
`log.level`/`logger`/`origin`) and the correlation ids services generate
(`session_id`, `trace.id`, `span.id`) are left alone: masking them breaks the
joins logs exist for. Anything else a caller puts under those keys is masked
like any other field. `user.name` is exempt from the name rule — it
is a login that audit trails need — but its content is still scanned, so an
email login is masked.

### Whitelist (NOT Masked)

These keys are never masked by name, although a word in them matches a rule.
They mean the same in every service:

```
module_name, func_name, task_name, service_name, app_name, project_name,
class_name, method_name, view_name, username, site_name, domain_name,
event_name, pathname, customer_id, id, pk, namespace, hostname, filename,
token_type, sec-ch-ua-mobile, expires_in, expires_at, refresh_expires_in,
scope, brand, scheme, bin, created, modified, created_at, updated_at,
and the expiry spellings
```

### Safe keys (a service's own names)

A service's payloads have their own names that a key rule would mask for
nothing: a gateway's short name in `pg_name`, a boolean in `cvv_required`. The
service lists them; the list extends the whitelist above and cannot shrink it.
A listed key's value is still content-scanned — except that a digits-only
reference number of up to 14 digits (an RRN, an acquirer id) is left as it is
when the key is not PII on its own. A 15–19 digit value is always truncated.

```python
# 1. Django settings.py
ECSCTX_MASK_SAFE_KEYS = ["pg_name", "cvv_required"]

# 2. Env var, comma-separated
#    ECSCTX_MASK_SAFE_KEYS="pg_name,cvv_required"

# 3. Programmatic, at startup (wins over both)
from ecsctx.masking import configure_masking_safe_keys
configure_masking_safe_keys(["pg_name", "cvv_required"])
```

Names are matched case-insensitively. A card key, or a name ending in a CVV or
credential word (`card_number`, `pan_no`, `card_cvv`, `db_password`,
`oauth_token`, `api_key`, …), names the value itself and cannot be listed:
`configure_masking_safe_keys` raises, and from the setting or env var it is
dropped with a warning, stays masked, and fails the Django boot check. A flag
or status about one (`cvv_required`, `tokenization_status`) can be listed, and
so can an expiry key, though it is safe already: nothing masks it. Ottu
services use `ecsctx.contrib.ottu.masking.SAFE_KEYS`, and list its
`WALLET_RULES` as value rules beside them (below):

```python
from ecsctx.contrib.ottu.masking import SAFE_KEYS as OTTU_SAFE_KEYS, WALLET_RULES

ECSCTX_MASK_SAFE_KEYS = [*OTTU_SAFE_KEYS]
ECSCTX_MASK_VALUE_RULES = [*WALLET_RULES]
```

### Value rules (a service's own shapes)

Some values are known by their shape rather than by the key they sit under —
a payment method's encrypted token, say — and which shapes those are is a
service's to say: ecsctx names none. A service lists its value rules, and the
engine asks them about every mapping the key walk meets (under any key), every
string that is JSON text, and every JSON object written in free text or in a
body `redact_body` masks, JSON in an XML element's text included. A value a
label rule matches becomes the rule's label, in every pack: never hashed, and
left as it is by a later pass; one a [keep rule](#keep-rules) matches ships as
sent. With none configured, none of this runs.

A label rule is any object with a `field_type` (the label it becomes: `"sad"`
is `[SAD-MASKED]`), `matches(value)` — called with a mapping, JSON text parsed
once — and, optionally, `hints`: literal strings a matching value's text holds
at least one of, so text holding none is never parsed to ask that rule.
`ValueRule` is one:

```python
from ecsctx.masking import ValueRule

def is_vault_blob(value):
    return value.get("kind") == "vault-blob" and "payload" in value

VAULT_BLOB = ValueRule("sad", is_vault_blob, hints=("vault-blob",))
```

```python
# 1. Django settings.py: rule objects, or dotted paths to a rule or to a collection of them
ECSCTX_MASK_VALUE_RULES = ["myservice.masking.VAULT_BLOB"]

# 2. Env var, comma-separated dotted paths
#    ECSCTX_MASK_VALUE_RULES="myservice.masking.VAULT_BLOB"

# 3. Programmatic, at startup (wins over both)
from ecsctx.masking import configure_masking_value_rules
configure_masking_value_rules([VAULT_BLOB])
```

An item that does not import or is not a rule makes
`configure_masking_value_rules` raise; from the setting or env var it is
dropped with a warning and fails the Django boot check, and the others still
apply. A label rule that raises leaves the record as `[MASKING-FAILED: …]`,
never an exception out of the log call.

The known-clean set the second pass reads is forgotten whenever the value
rules are configured (`configure_masking_value_rules`), so a string masked
under one rule set never comes back as it was under another.

#### Keep rules

A **keep rule** ships what it matches exactly as sent: a value a service must
be able to read in its logs, found by shape. It is any object whose `keep` is
`True` (the object itself, not a truthy value), with `matches(value)` and,
optionally, `hints`; it has no `field_type`, since it writes no label. An
object with both a `field_type` and `keep = True` is neither, rather than
the less safe of the two: it is refused as an item that is not a rule is
(above), the problem naming both. `KeepRule` is one:

```python
from ecsctx.masking import KeepRule

def is_sealed_box(value):
    return value.get("kind") == "sealed-box" and set(value) <= {"kind", "box"}

SEALED_BOX = KeepRule(is_sealed_box, hints=("sealed-box",))

ECSCTX_MASK_VALUE_RULES = ["myservice.masking.VAULT_BLOB", "myservice.masking.SEALED_BOX"]
```

Keep and label rules go in the one `ECSCTX_MASK_VALUE_RULES` list, and are
asked where label rules are: every mapping the key walk meets, every string
that is JSON text, every JSON object in free text or in a body `redact_body`
masks. They are asked in list order and **the first match wins**: a label
rule listed first labels a value a keep rule would have kept, and an object a
label rule matches is not looked into for one to keep. A label rule wins at
any depth inside a keep match, though: a keep match holding a value whose
own first match is a label rule is walked as if nothing had matched, and
that value is labelled — with an Apple Pay label rule listed before
`KeepRule(lambda value: True)`, `{"outer": {"inner": <paymentData>}}` is
`{"outer": {"inner": "[SAD-MASKED]"}}`. Listed after it, the catch-all keep
rule is the inner value's first match too, and the whole value ships as
sent. A keep match the guard refuses
(below) is walked as if nothing had matched too, and either way no rule
listed after it is asked about the value itself, a label rule for the same
shape included. A kept value is left as sent under any key and not
descended into — a credential's key, a card's, or a PII container's above it
does not stop it (`token`, `paymentToken`, `password`, `card.devicePayment`,
`customer`): what the rule names is the value itself, not something the key
says about it. In text, what a keep rule
ships is set aside as a `[KEPT-<letters>-MASKED]` placeholder before every
content rule, and put back as it was written after; a placeholder a rule
destroys — a credential hashed with what was around it — takes the value with
it. A placeholder is named from a digest of the value it stands for: the same
value has the same name, so a credential hashed around one carries that value
in its token, as under a key, and a name written into the text by anyone
without the value (an element's entity-encoded text decodes to one) is not a
placeholder and restores nothing. Text that already holds `[KEPT-` is masked
as if no keep rule were configured. A keep rule that raises counts as no
match: keep rules are asked on paths that must never raise (`redact_url`,
`redact_body`, `mask_card_value`). So does a label rule asked about what is
inside a keep match: its error refuses the keep and raises nothing there,
and the value is masked as with the label rules alone — whose error reaches
the caller only where the walk itself asks them, as before.

Two things no keep rule overrides, not even `KeepRule(lambda value: True)`:

- **The floor.** Nothing is kept under a CVV or SAD key (`cvv`,
  `securityCode`, `pin`, `cryptogram`, …), inside a CVV or SAD container
  (a key the service lists there included), or as the `value` of a pair
  labelled as one; in text, anywhere in text that names such a key, element
  or pair label. Such a value is masked exactly as without the rule.
- **The guard.** A match that holds, at any depth — JSON text inside it
  included — a key the key rules read as a card, a CVV or other SAD, a
  `{name, value}` pair whose identifier reads as one (as the key walk reads a
  pair), a leaf that is a card number, or a text leaf with a card number in
  it, is walked as if nothing had matched. A leaf is a card number when it is
  an int `int_is_pan` reads as one, or a string `pan_shaped` reads as one,
  whatever its prefix and Luhn or not. A text leaf holds one when a run of 13
  to 19 digits in it, joined by single separators at most and with no digit
  next to either end, passes Luhn: `"card 4111…"`, Track 2 data,
  `"4111…+cvv+123"` in a base64 slot, `"4111…ab"` in a hex one. Both except
  thirteen bare digits from a 1 or a 2 (epoch milliseconds until 2065), Google
  Pay's `keyExpiration`, which `pan_shaped` reads as a card number and every
  Google Pay token carries. A run inside a whole hex token of 24 characters
  or more — an ObjectId, a 32-hex gateway id, a 64-hex digest such as Apple
  Pay's `transactionId`, with nothing alphanumeric touching it — is no card
  number either, as Connect's own card scan reads one: about one random
  64-hex id in two hundred holds a run that passes Luhn, and read like other
  text it cost 1.1% of Apple Pay tokens. Shorter hex, or hex glued to more
  letters, is read. A leaf that is no JSON value counts as card data. What
  the guard cannot tell from a token's own text ships with it: a CVV or other
  short value written inside a longer string (`"note": "cvv=123"`, or
  `cvv+123` inside base64, which reads as ciphertext), a run of digits that
  fails Luhn, and a card number written into a hex id's own characters.
  Keeping that out is the matcher's job, which is why a matcher must be
  strict about what it matches.

Nothing else in a kept value is read: PII or a credential inside it, under a
key of its own or written in a string, ships with it.

JSON text under a key that would hash it whole — a credential's — and that
holds a kept value deeper is still hashed whole: a keep never cuts a value out
of a string. A kept mapping is a copy: the record is masked in place.

A keep decision rests on the text as written, since that is what ships: JSON
that names a key twice in one object (`json.loads` keeps the last) is not
kept, and a JSON-text leaf naming one inside a match is card data to the
guard; a Python repr is kept only where its parse renders back to it exactly
(a comment, or a key written twice, is dropped by the parse). So a repr whose
strings hold a `"` — a Google Pay token's `signedMessage` — written inside
JSON text, where that quote is escaped, is not kept: it no longer renders
back as written (fails closed).

An entity-encoded value (`{&quot;…&quot;}`, an XML element's text) is set
aside by `redact_body`, which reads such text as it decodes, but not by the
text rules the log processor runs, which read it as written: there it is not
kept and the content rules read into it — with `pci`, about one
entity-encoded Google Pay token in ten comes out altered (fails closed).

A service that masks again after ecsctx — Connect does — asks
`is_kept(value, key=None)` (a mapping or JSON text; the rules in force, first
match, the guard, and the floor on `key`; False with no keep rule configured)
before masking a field, and runs its text masker through
`mask_outside_kept(text, mask)`, which hands `mask` the text with each kept
value set aside and puts back each placeholder it leaves. Both are in
`ecsctx.masking` and never raise of their own: `mask_outside_kept` passes on
an error the caller's `mask` raises.

In text a container's reach cannot be told — the text rules read an object
three levels deep, and a wallet token's own nesting takes two — so the floor
reads the whole text: text that names a CVV or SAD key anywhere keeps
nothing, and is masked as without a keep rule. A name is a quoted key then
`:`, `=` or `=>` (JSON, a repr, JSON in a JSON string), a bare key then `:` or
`=>`, a key and `=` where a key starts (`cvv=`, `&cvv=`; not base64's `=`
padding inside a string), an XML tag, or a `{name, value}` pair's label
(`"name": "card security code"`), read as the key walk reads a key — every
pack on, the service's safe keys honoured — in the text as written and, where
it holds an entity, as it decodes. A word in prose (`the cvv check passed`)
names no key. That fails closed: a value beside such a key, not under it
(`{"cvv": "123", "token": {…}}`, or a `<pin>` element elsewhere in a body),
is not kept in text, though the key walk keeps it. `redact_body` reads an
element's entity-encoded text the same way, and keeps nothing in it when the
body around it names one. The text is read for names only once a value to
keep is found in it. An object right after a CVV key in text is not kept, but
no `default` content rule masks a JSON object there either, with or without
keep rules; the key walk masks one under a CVV key leaf by leaf.

The cost: with no keep rule configured none of this runs — a string with no
`{` pays one check, one with a `{` a look at the rules in force; with keep
rules alone, the label rule (rule 2) does not run. Text holding none of a keep
rule's hints never asks it; text holding one is read once for the objects in
it. Every mapping the key walk meets asks every rule, once — a mapping has no
text to hint with — so a matcher must be cheap: test a literal field first.
JSON text under a key asks, and its key walk passes on, only the rules whose
hints it holds. With Ottu's `WALLET_RULES`, a line carrying no wallet token
costs 1-4% more than with 0.16.0's two label rules, and 3-15% more than with
no value rule (most on a line of many small mappings, each of which asks
every rule; `scripts/bench_masking.py`). A line carrying a token has no
single figure: about 2.5× 0.16.0's label rules on a short line (an MPGS line
with the token as `paymentToken`: ~72 µs labelled, ~171 µs kept, ~46 µs with
no rule; a message holding a Google Pay token: ~135 / ~341 / ~305 µs), and
less on a body every content rule would otherwise read (KPay `<udf9>`:
~0.96 ms labelled, ~0.89 ms kept, ~3.1 ms with no rule). The slot checks,
the guard's card-number runs and the text floor's scan add 15-40% over
0.17.0 on such lines.

Ottu's wallet tokens ship in logs exactly as sent (#159487): an Apple Pay or
Google Pay token is single-use, and the token as it was sent is what debugs a
wallet payment. `ecsctx.contrib.ottu.masking.WALLET_RULES` are keep rules
with strict matchers — an Apple Pay `PKPaymentToken`, its `paymentData`
(`version` `EC_v1` or `RSA_v1`, the encrypted `data`, a `header`) and a
Google Pay payment method token (`protocolVersion` `ECv1`, `ECv2` or
`ECv2SigningOnly`, with a `signedMessage`), no key besides the ones each
writes, and every leaf text in its alphabet: standard base64 for a key, a
signature or ciphertext (`data`, `signature`, the header's
`ephemeralPublicKey`, `publicKeyHash` and `wrappedKey`, Google Pay's
`signatures`, and the fields of its `signedMessage` and `signedKey`, each
JSON text of all its fields and nothing else), hex for an id or a hash
(`transactionId`, `applicationData`, `transactionIdentifier`), digits for
`keyExpiration`, and for what `paymentMethod` says about the card short
text: its `network` and `type` at most 64 characters, its `displayName` at
most 40, the network's name and, after a space, the card's last four
(`Visa 0492`, `Amex`) with no other digit. A token holding anything else in a
slot — `"data": "cvv=123"`, a spaced card number as its `signature`,
`"displayName": "cvv 123"` — is not kept, and is masked as before; nor is
one with a card number in a slot's own alphabet (`"4111…+cvv+123"` in
base64), which the guard reads. What neither can tell from ciphertext ships
with a kept token: a CVV or other short value written in a slot's own
alphabet (`cvv+123` inside base64). They are found under `paymentData`,
TAP's `token_data`, MPGS's `paymentToken` (a JSON string), Google Pay's
`tokenizationData.token`, KPay's `<udf9>`, or in a message. A
`PKPaymentToken` with a key of its own keeps only its `paymentData`.
Saved-card tokens stay masked: no wallet shape matches one. Samsung Pay's
token, a JWE, is not matched yet. An Ottu service
lists them in `ECSCTX_MASK_VALUE_RULES` next to its `ECSCTX_MASK_SAFE_KEYS`
(above), or sets
`ECSCTX_MASK_VALUE_RULES=ecsctx.contrib.ottu.masking.WALLET_RULES`.
`WALLET_SAD_RULES` are 0.16.0's label rules, the same tokens' payment data
`[SAD-MASKED]` whole, for a service that must not log them. Core keeps and
labels no wallet token of its own accord: without either list, one is read as
any other value is.

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

**Path syntax.** A pattern is anchored at the root of the record or at a
payload container (`payload`, `args`, `kwargs`, `extra`, the http request and
response bodies), so `payment_methods[*].name` and
`payload.payment_methods[*].name` both exempt the same field, while a short
pattern such as `audit` does not reach an `audit` key nested deeper:

| Segment | Meaning |
|---------|---------|
| `key`   | a dict key |
| `[*]`   | any array element |
| `*`     | any single dict key (wildcard) |

Matching is a **prefix match**, so a pattern also exempts everything nested below it:

- `payment_methods[*].name` — exempts just that field in every array element
- `payment_methods` — exempts the entire `payment_methods` subtree
- `order.customer.name`, `items[*].tags[*].name` — arbitrary nesting works

### Boot check (Django)

Importing `ecsctx.contrib.django` registers a `Tags.security` system check
(`ecsctx.E00x`) that fails `manage.py check`, `migrate` and `runserver` if a
handler that ships logs off-host is unmasked. A handler counts as masked if it
carries `mask_pii_filter` (itself or through its logger) or its formatter runs
`mask_sensitive_data`. Console `StreamHandler`/`NullHandler` never ship;
Django's `AdminEmailHandler` ships only when `ADMINS` is set. The check is
skipped when `ENVIRONMENT` is `local`, `test` or `dev`
(`ECSCTX_MASKING_CHECK_ENV_VAR`, `ECSCTX_MASKING_CHECK_SKIP_ENVS`), or with
`ECSCTX_SKIP_MASKING_CHECK = True`; `assert_no_masking_errors(settings.LOGGING)`
enforces it in a test suite regardless of environment.

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
2. The structure is walked recursively, tracking each value's JSON path. A string that is a JSON object or list (up to 64 KiB, e.g. a callback's raw body) is parsed and walked the same way, then written back
3. A sensitive-key string value is tokenized (HMAC-SHA-256) — unless its key is whitelisted, listed in the service's [safe keys](#safe-keys-a-services-own-names), or its path is exempted (see [Path exemptions](#path-exemptions))
4. Every string value is also scanned for email/phone patterns and tokenized (defense in depth, even on exempted paths)
5. Auth header values (`Authorization`, `Proxy-Authorization`, cookies) are masked as credentials (`mask_secret`): the scheme and the credential as one value, its token, or `[SECRET-MASKED]` without a keyset — never truncated, never encrypted
6. Values are normalized before tokenization (emails lowercased, phones to E.164)

### Example Output

```json
{
  "customer_name": "ptok:v1:KeNDkDCY0cXCg3VJU4xf...",
  "email": "ptok:v1:x8FpQm2kL9nR7vBwYzA3...",
  "amount": 100,
  "service_name": "checkout"
}
```

`amount` is untouched (not a sensitive key). `service_name` is whitelisted. `customer_name` and `email` are tokenized.

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
    log.error("something failed", error=str(e))

# CORRECT — ECS-compliant dict
except Exception as e:
    log.error("something failed", error={"message": str(e)})

# EVEN BETTER — include exception type
except requests.HTTPError as e:
    log.error("api call failed", error={
        "message": str(e),
        "type": type(e).__name__,
    })
```

### Custom Fields and the Root Allowlist

Only ECS reserved names need the dict treatment. The `namespace_ecs_fields` processor enforces a **root allowlist** — all non-allowlisted keys (scalars, lists, and dicts) get automatically wrapped into an `extra` object. See the [Core Rules](#4-core-rules-field-placement-reference) table for the complete allowlist.

```python
# "merchant_id" stays at root (allowlisted)
log.info("payment started", merchant_id="acme")

# "disclosure_pk" is not allowlisted — goes into extra.disclosure_pk
log.info("disclosure created", disclosure_pk=42)
```

### Elasticsearch Indexing: `labels` vs `extra`

- **`labels.*`**: Use for intentionally filterable, low-cardinality keywords (e.g., `labels.env`, `labels.region`). Elasticsearch indexes these as `keyword` by default under the ECS `labels` field.
- **`extra.*`**: Non-filterable detail data. If your Elasticsearch index should not index `extra` children, map it as `flattened` or `enabled: false` in your index template.

```python
# Good: filterable metadata in labels
bind_logging_context(labels={"env": "prod", "region": "us-east-1"})

# Good: non-filterable details as bare kwargs (auto-wrapped into extra)
log.info("payment processed", amount=100, currency="KWD")
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
# ❌ WRONG — the values rendered into the message: every line is different
log.info(f"Payment processed for merchant {merchant} amount {amount}")

# ✅ CORRECT — lowercase prose, a constant template, lazy %s arguments
log.error("oauth token exchange failed for %s: %s", shop, response.status_code)

# ✅ ALSO CORRECT — a constant message, the values as structured fields
log.info("payment processed", merchant=merchant, amount=amount)
```

**Why it matters:** The message is what Kibana aggregates and alerts on, and
what Sentry groups by. A `%s` template stays constant however its arguments
vary — logging fills them in only when the line is emitted, and masking reads
them as values — while an f-string makes every line a message of its own. The
message is lowercase prose a person reads, not an identifier: the event
itself is named by `ecs_event=` ([section 23](#23-declared-events-ecsctxevents)),
so a snake_case "event name" in the message is neither. Ottu's services
(Connect, Ottu PG) gate this style.

---

### Mistake #3: `error=str(e)` — The ECS Violation

```python
# ❌ WRONG — flat string breaks ECS error field mapping
log.exception("invalid data", error=str(error))

# ✅ CORRECT — ECS-compliant dict
log.exception("invalid data", error={"message": str(error)})
```

---

### Mistake #4: `log.exception(e)` — Exception as Message

```python
# ❌ WRONG — exception object as first arg, not a constant message
except Exception as e:
    log.exception(e)

# ✅ CORRECT — a constant message, structlog auto-captures exception info
except Exception as e:
    log.exception("payment processing failed")
```

---

### Mistake #5: Logging Before Binding Context

```python
# ❌ WRONG — first log has no merchant_id or payment context
def post(self, request, merchant_id, client_payment_id):
    log.info("acknowledgement received",
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
    log.info("acknowledgement received")
```

---

### Mistake #6: Redundant kwargs Duplicating Context

```python
# ❌ WRONG — session_id already in context, passed again as kwarg
bind_logging_context(session_id=session_id)
log.info("notification received", session_id=session_id)  # redundant!

# ✅ CORRECT — it's already in context
bind_logging_context(session_id=session_id)
log.info("notification received")
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
log.error("pg codes not found for %s", merchant_id)

# ✅ CORRECT — not our fault, not worth waking someone up; still a failure
log.warning("pg codes not found for %s", merchant_id)
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
    ├── Did something fail, expected or not? (customer config, a retry,
    │   auth fail, a rejected callback) → log.warning
    ├── Normal operations? → log.info
    └── Debug/development info? → log.debug
```

> **The golden rule: `log.error` = "Wake someone up."** If it's not worth waking someone up, it's not `log.error`.

A failure is never below `warning`: the contract validator (`event_contract`,
[section 23](#the-log-contract-event_contract-processor)) reports any event
logged with `outcome=failure` at `debug` or `info` (`failure_below_warning`),
and the catalogue's expected failures declare `failure_level="warning"`.

| Situation | Level | Reasoning |
|-----------|-------|-----------|
| System/infra failure (DB down, API 500) | `log.error` | Needs Sentry alert + on-call |
| Business logic failure (max retries exceeded) | `log.error` | System failed its job |
| Customer config error (merchant not found) | `log.warning` | Not our fault, but a failure |
| Retry-able failure (temporary network blip) | `log.warning` | Task will retry; `error` once retries are exhausted |
| Auth failure (invalid token, bad HMAC) | `log.warning` | Expected and handled, but a failure |
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

log.info("pii masking check", customer_name="John Doe", email="john@example.com", amount=100)
```

Expected stdout:

```json
{
  "message": "pii masking check",
  "customer_name": "ptok:v1:...",
  "email": "ptok:v1:...",
  "amount": 100
}
```

If `customer_name` shows `"John Doe"` in plain text, check that `mask_sensitive_data` is in the processor chain.

### Step 4: Verify Context Propagation (Celery/RQ)

```python
# In a view, dispatch a task and check worker stdout
log.info("dispatching task")
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
2. Select the data stream: `logs-{PROJECT_NAME}-{ENVIRONMENT}` (at Ottu, `logs-*`, or `logs-pci-<env>` for a PCI service)
3. Search: `message: "pii masking check"`
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

With the template above, your logs land in Elasticsearch under:

```
logs-{PROJECT_NAME}-{ENVIRONMENT}
```

Examples:
- `logs-keyloop-production`
- `logs-event-backend-staging`
- `logs-checkout-dev`

Ottu's services do not use this layout: they ship to daily `logs-YYYY.MM.DD`
indices, and a PCI service (Ottu PG) to `logs-pci-<env>`, from log files Vector
tails.

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
| `ECSCTX_REDACT_EXTRA_SECRET_KEYS` | Extra body keys for `redact_body` (CSV, appended to the built-in credential list) | — | No |
| `ECSCTX_REDACT_BODY_LOG_CAP` | Max logged response-body chars in `loggable_body` | `4096` | No |
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
    mask_pan,               # First6/last4 PAN display-mask
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
  "message": "payment processed",
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
├── processors.py              # contextvars_injector, mask_pan, mask_sensitive_data, namespace_ecs_fields
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
│   ├── __init__.py            # Public API: EventSpec, register_domain, timed
│   ├── spec.py                # EventSpec — what an event declares
│   ├── registry.py            # Domain prefixes, aliases, freeze()
│   ├── validator.py           # event_contract processor (strict / repair)
│   └── timing.py              # Timer, timed() — event.duration in ns
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
claims a prefix, where a field lands. The shared Ottu vocabulary is in
`ecsctx.contrib.ottu` (below); anything else stays in your own codebase and
registers at startup.

### The shared Ottu catalogue (`ecsctx.contrib.ottu`)

63 events in 11 domains (`pg`, `crypto`, `payment`, `card`, `threeds`, `net`,
`task`, `cache`, `api`, `webhook`, `auth`), each an `EventSpec` constant with a
description, its ECS `category`/`type`, a `Reason` class and levels, so every
service names the same thing the same way. **[docs/events.md](docs/events.md)**
lists them all with when to log each — look there before adding an event.

Services are built by different teams, so the vocabulary is held in one place
and the rules are enforced, not just written down:

- A service's own events live in **one module of that service**, declared ahead
  of use, and are registered with the catalogue at startup.
- `register_ottu()` checks every local event against the naming rules
  (`ecsctx.contrib.ottu.rules`) and refuses the lot, before registering
  anything, if one breaks them:
  - the action is `<domain>.<subject>_<verb>` and ends in a past-tense verb
    from `VERBS`;
  - a word that has drifted before is rejected with the word to use instead:
    `inited` → `created`, `queued` → `enqueued`, `finished` → `completed`;
  - the action contains no negation;
  - the event has a description.
- An event a second service needs, or a new reason for a shared event, is added
  here by PR. [docs/rules/log-events.md](docs/rules/log-events.md) is the rule
  each service copies into its `.claude/rules/`, so review catches what a rule
  cannot, such as a synonym that is a different word.

Import the constant; register once, together with your service's own events,
from `AppConfig.ready()`:

```python
from ecsctx.contrib.ottu import register_ottu
from ecsctx.contrib.ottu.net import OutboundFailure
from ecsctx.contrib.ottu.pg import PG_REQUEST_FAILED
from ecsctx.events import EventSpec, Outcome

# Your own events, in your service's one events module: one under a shared
# prefix, one under a prefix of your own.
PG_PAYLOAD_BUILT = EventSpec(
    action="pg.payload_built",
    description="The request body for a PSP call was assembled, before sending.",
    terminal=True,
    type=("info",),
)
WALLET_BALANCE_DEBITED = EventSpec(
    action="wallet.balance_debited",
    description="A wallet balance was debited for a payment.",
    terminal=True,
    type=("change",),
)

register_ottu(
    local={"pg": (PG_PAYLOAD_BUILT,), "wallet": (WALLET_BALANCE_DEBITED,)},
    aliases={"token_blacklist": "auth.token_revoked"},  # retired names still logged
)                                                      # freezes the registry

logger.warning("PSP rejected the call", ecs_event=PG_REQUEST_FAILED.ecs(
    outcome=Outcome.FAILURE, reason=OutboundFailure.HTTP_CLIENT_ERROR))
```

A prefix can be registered only once, which is why your events under a shared
prefix go through `register_ottu(local=...)` rather than a second
`register_domain`; redefining a shared action raises. The `api` domain is the
one `@api_logging` emits, so it never conflicts with `register_http_events()`.
A retired name warns once, not on every line.

### Adding an event

1. Search [docs/events.md](docs/events.md) and your service's events module.
   If an event already names what happened, use it. The difference goes in
   fields or a reason, not in a new action.
2. If more than one service will log it, add it to the catalogue module for
   its domain here:
   - with a `description`, and its reasons as a `Reason` subclass;
   - regenerate the page with `python -m ecsctx.contrib.ottu.render_docs`;
   - the catalogue owners review it (`.github/CODEOWNERS`).
3. If only your service can log it, declare it in your service's events module
   and pass it to `register_ottu(local=...)`. The naming rules are checked
   when the service starts.

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

### Logging an event

There is one way to log an event: your own logger, with the event's payload.

```python
logger.info(
    "gateway replied in %s ms", elapsed_ms,
    ecs_event=PG_RESPONSE_RECEIVED.ecs(outcome=Outcome.SUCCESS, duration_ns=elapsed_ns),
    session_id=sid,
    payment={"pg_code": "mpgs"},
    http={"response": {"status_code": 200}},
)
```

`.ecs()` builds the `ecs_event=` payload: `action`, `kind`, `category` and
`type` from the spec, plus the `outcome`, `reason` and `duration_ns` you pass —
each checked against the spec, so a terminal event without an outcome or an
undeclared reason raises at the call site. Everything else is an ECS namespace
passed by name (`payment=`, `http=`, `url=`, `error=`), placed where you wrote
it.

**Outcomes and reasons are objects.** `Outcome` is ECS's closed set
(`SUCCESS`, `FAILURE`, `UNKNOWN`); an event's reasons are a `Reason` subclass
declared next to it and passed as `reasons=`:

```python
from ecsctx.events import EventSpec, Reason

class CallbackRejection(Reason):
    INVALID_SIGNATURE = "invalid_signature"
    MALFORMED_PAYLOAD = "malformed_payload"

PG_CALLBACK_REJECTED = EventSpec(
    action="pg.callback_rejected", terminal=True, reasons=CallbackRejection,
)

PG_CALLBACK_REJECTED.ecs(outcome=Outcome.FAILURE, reason=CallbackRejection.INVALID_SIGNATURE)
```

A member is a name your editor completes and a linter sees; a string is valid
until the line runs, usually on the failure path. The document carries the
plain value (`"failure"`, `"invalid_signature"`), so nothing changes in the
index. A member of another event's set is rejected even when its value matches
— `WebhookFailure.TIMEOUT` does not explain a `pg.request_failed`. Plain strings
are still accepted for a declared value. An event that declares no set takes no
reason at all: a reason is a bounded value or it aggregates nothing, so the
event's `Reason` class is declared before the first call site passes one. A set
with members cannot be subclassed, so a new reason for a shared event is added
where the set is declared.

**The level is the call site's.** The spec's `level` and `failure_level` declare
the intended level (the catalogue's warning-level `*_rejected`/`*_failed` events
set `failure_level="warning"`), and the contract validator reports a failure
logged below warning; nothing picks the level for you.

### Timing: `event.duration` is nanoseconds

`event.duration` is on **0.0%** of application logs in one production index —
every document carrying it is nginx's — because there was no timer to reach for.

```python
from ecsctx.events import timed

with timed() as t:
    response = call_gateway()

logger.info(
    "Gateway replied in %.1f ms", t.ms,
    ecs_event=PG_RESPONSE_RECEIVED.ecs(outcome=Outcome.SUCCESS, duration_ns=t.ns),
)
```

`.ns` and `.ms` are separate, explicitly named properties, and `.ecs()` takes
`duration_ns`, because **the unit is the thing most likely to go
wrong here**: a millisecond value is accepted, indexes cleanly, and misreports
by six orders of magnitude while looking entirely plausible. There is no
unit-less `duration` anywhere in this package to pass by accident.

The timer stops whether the block completed or raised, so a failure path still
reports how long it took to fail — usually the more interesting number.

### The one vocabulary this package does ship

`api_logging` is a decorator *in this package* that emits two log lines, and a
log line that will not name itself is the defect this whole area exists to
remove — a service cannot declare an action for a call site it does not own. So
`ecsctx.events.http` defines three specs and the decorator uses them:

| action | when |
|---|---|
| `api.request_received` | a request arrives |
| `api.response_sent` | the view answered; carries `event.outcome`, `event.duration` and `http.response.status_code` |
| `api.request_rejected` | refused at the boundary — `reason` is `throttled` or `validation_failed` |

They are generic to any DRF service, not Ottu vocabulary. The `api` domain is
**not** claimed on import — that would take the prefix from a service that wants
it, and the decorator needs no registry. Call `register_http_events()` from your
AppConfig if you run the contract validator in strict mode.

### The log contract (`event_contract` processor)

The most damaging mistake in this whole area is invisible at the call site:

```python
logger.info("Payment started", ecs_event="payment.started")   # WRONG
```

A **string** `ecs_event` is routed by `namespace_ecs_fields` to `event.original`
— ECS's field for the *raw unparsed message* — so `event.action` is simply
absent and the line vanishes from every dashboard that filters on it. Six of the
most important events in one production service are in that state today.

`event_contract` is a structlog processor that catches it. It is already wired
into `get_logging_config()`, immediately **before** `namespace_ecs_fields` —
ordering is the point, since running after it would leave nothing to repair.

It checks five things:

| code | what it caught | repaired? |
|---|---|---|
| `string_action` | `ecs_event` passed as a string | coerced to `{"action": ...}` |
| `unknown_action` | the action is not in the registry (only once `freeze()` has been called) | no — the name is the call site's to fix |
| `missing_outcome` | a terminal event with no `event.outcome` | set to `"unknown"` |
| `failure_below_warning` | `outcome="failure"` logged at debug or info | **no** — the level was decided before the chain ran, and a processor cannot re-route an emitted record |
| `unbounded_label` | a `labels.*` value that is not a scalar | stringified |

**Modes.** `repair` (the default) fixes what it can, stamps
`labels.log_contract` with the comma-joined codes, and never drops the line.
`strict` raises `EventContractError` instead — use it in dev and test settings,
so a broken call is caught at the desk:

```python
# settings/dev.py
ECSCTX_EVENT_CONTRACT = "strict"
```

Resolution is Django setting, then `ECSCTX_EVENT_CONTRACT`, then `repair`.
`repair` is the default deliberately: a logging library that takes a service down
over a malformed log line has chosen the wrong failure.

`unknown_action` stays silent until `freeze()` is called, and silent entirely if
nothing is registered — a service that does not use the registry must not have
every line stamped as a violation.

`labels.log_contract` is a keyword field, which is why the codes are a bounded
set joined into one string rather than a list.

### Migrating existing names

```python
from ecsctx.events import register_aliases

register_aliases({"PG_CALL": "pg.request_sent"})
```

A line still logging `ecs_event={"action": "PG_CALL"}` then resolves to the
current spec in the contract validator instead of being reported as
`unknown_action`, with a `DeprecationWarning` once per name. The document keeps
the old name until the call site imports the constant, so aliases are a bridge
for a migration, not a rename.

## License

MIT. See [LICENSE](LICENSE).
