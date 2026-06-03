# Changelog

## v0.5.3 (2026-06-03)

### Fixes
- fix(django): don't read settings in setup_logging (settings.py re-entrancy) (#11) (97e42cf)


## v0.5.2 (2026-06-03)

### Features
- feat(django): log ECS user.id + user.name in api_logging (#10) (b8ab412)


## v0.5.1 (2026-05-29)

### Fixes
- fix(django): honor ECSCTX_MASK_EXEMPT_PATHS at log time, not only in setup_logging() (769a89e)


## v0.5.0 (2026-05-29)

### Features
- feat(processors): path-aware PII masking with per-service path exemptions (62189d8)

### Other
- chore: stop tracking .serena/ and refresh uv.lock (ab61a63)
- docs: correct stale PII/crypto, Django, and naming claims in Markdown (ff3539c)


## v0.4.3 (2026-03-20)

### Fixes
- fix(processors): preserve structlog internal keys in reshape_log_event (7810539)

### Other
- chore: stop tracking .claude/settings.local.json (ed9bc72)


## v0.4.2 (2026-03-13)

### Features
- feat: add Django test project and fix lazy User import (ecd7fb9)


## v0.4.1 (2026-03-12)

### Features
- feat: enhance LoggingContext with labels support and reshape log event structure (e6ccb7b)
- feat: add timeout configuration for Vault HTTP requests and enhance PII provider documentation (2b043aa)
- feat: enhance PII configuration with environment variable support and access mode handling (ca3701c)
- feat: add PII tokenization and encryption module with normalization and keyset provider (73b0ebf)
- Merge pull request #5 from ottuco/readme_file_updated (dca15f0)
- feat : README.md file got updated. (2377b4a)
- feat(django): add Django middleware and processors with lazy settings loading (657f0f2)
- feat(django): add plug-and-play LOGGING configuration (99df5cf)
- feat: initial ecsctx package (4d18526)

### Fixes
- fix: enhance logging context reset handling to suppress RuntimeError (d33984b)
- fix: make Django processors read settings lazily (f53a486)
- fix: avoid circular import in django __init__.py (c71fb03)

### Other
- ci: add changelog generation to release workflow (996e000)
- refactor: rename package to ecsctx and update imports across the codebase (b95f626)
- refactor: rename package to ecsctx and update imports across the codebase (6b96482)
- Merge branch 'main' of github.com:ottuco/ecsctx (6b8f2de)
- Merge pull request #4 from ottuco/149309 (6167126)
- Fix: deep merge extra dict in LoggingContext.evolve() to preserve nested keys (63b72c5)
- Add: Celery context propagation utilities for logging context management (57f22de)
- Merge pull request #3 from ottuco/origin/Task-147936 (8a9ca7f)
- Add : missing `__doc__` (146517d)
- Update : `api_logging` decorator updated. (#2) (cc64510)
- Add : User Object serialization (#1) (69e457b)
- refactor: update LoggingContext attributes and ECS mapping for improved clarity (1a7da7c)
- refactor: simplify contextvars_injector and update README for dynamic merchant_id binding (16a5dbf)
- refactor: separate Django-specific code into contrib/django (56be223)

