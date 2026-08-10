# Changelog

## v0.6.1 (2026-08-10)

### Other
- Merge pull request #27 from ottuco/chore/158877_dependabot_upgrades (fdaa9ad)
- ci: warn future editors that the Django matrix pin dies on any re-sync (#158877) (c6859f6)
- chore(deps): upgrade vulnerable locked deps; test Django 4.2/5.2/6.0 explicitly in CI (#158877) (2783b92)


## v0.6.0 (2026-08-10)

### Features
- Merge pull request #22 from ottuco/bug/158767_sentry_processor (4bf322f)
- feat: ChainIntegration hook + ecsctx.contrib.sentry.SentryIntegration for masked in-chain Sentry events (#158767) (1b12a3a)

### Fixes
- Merge pull request #25 from ottuco/bug/158865-structlog-context-leak (08f2970)
- fix(contrib): clear stale structlog contextvars at request/job/task boundaries (ac296ff)

### Other
- Merge origin/main (v0.6.0 sentry work) — union test deps, regen uv.lock (d8547ee)
- docs(middleware): transport-neutral leak explanation — cover ASGI base-context inheritance, not just WSGI workers (#158865) (05b59be)
- docs: scope SentryIntegration to the native chain; drop vendor name from core docstring (#158767) (71479c3)


## v0.5.6 (2026-08-05)

### Features
- feat(processors): callsite_ecs_fields — log.logger + log.origin attribution (#158349) (c41f770)

### Fixes
- Merge pull request #21 from ottuco/bug/158762_log_level_exception (d4484bf)
- fix(formatters): normalize log.level "exception" -> "error" (#158762) (86c859e)
- fix(processors): consume exc_info fully in error_ecs_fields — safe for renderer-less pipelines (39ffdc2)
- fix(processors): render unhandled exc_info as ECS error.*, not stringified extra.exc_info (#158750) (6f530ac)

### Other
- style(formatters): add missing trailing newline (7340def)
- docs: add error_ecs_fields to the processor-chain order list (b563956)
- Merge task/158349-native-log-attribution (review fixes) into bug/158750_exc_info_error_fields (0c30db7)
- docs+test(attribution): address review — README chain/quickstart parity, import order, end-to-end tests (9a2eee5)
- chore: refresh uv.lock (5d81156)


## v0.5.5 (2026-06-11)

### Features
- Merge pull request #14 from ottuco/feat/configurable-root-fields (8c4024e)
- feat(processors): configurable root fields via ECSCTX_ROOT_FIELDS (1f84e42)


## v0.5.4 (2026-06-10)

### Fixes
- Merge pull request #12 from ottuco/133722-logging-correlation-fix (6bd921e)
- fix(processors): preserve log message, emit ECS event as dotted keys (b8e3372)

### Other
- Merge pull request #13 from ottuco/add-claude-github-actions-1781087512781 (b8621f8)
- "Claude PR Assistant workflow" (ec235f4)
- refactor(pii): make safe_tokenize public (was _tokenize) (b1eca74)
- chore: refresh uv.lock (stale ecsctx 0.4.2 -> 0.5.3) (2232186)
- refactor(context_binder): generic overridable base; no forced domain fields or auditlog (40f28b5)


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

