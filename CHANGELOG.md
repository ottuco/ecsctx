# Changelog

## Unreleased

Fixes found adopting 0.7.x in ottu_backend; each was present since 0.7.0.

- **Exceptions survive masking.** `exc_info` and `stack_info` are never masked.
  An exception passed as `exc_info=exc` (as the middleware's
  `unhandled_exception` line does) was turned into strings, so with
  `SentryIntegration` the line lost `error.stack_trace` and Sentry received no
  exception. The rendered `error.*` fields are masked as before.
- **`ECSCTX_MASK_EXEMPT_PATHS` always applies.** The exemptions now read the
  Django setting themselves (explicit call → setting → `PII_MASK_EXEMPT_PATHS`).
  Before, if anything masked before the first structlog line — the handler
  filter on a stdlib record — the env var was loaded and the setting ignored.
- **PII containers keep their shape.** A dict or list under a PII key
  (`customer`, `billing`, `contact`, …) was masked into one string. Each field
  is now masked on its own: by its own key's type (an `email` field gets an
  email token, so the same address correlates across records), kept if a safe
  key (`id`, `customer_id`), else tokenized as the container's type. Card,
  CVV, expiry and secret containers are still masked as one unit. A service
  that logged such containers on 0.7.x sees the field change from a string
  back to an object in its index once.

## v0.7.3 (2026-09-18)

### Features
- feat(net): url_host, loggable_request_body, redact_url(secrets=), deny-list bodies (5704f40)
- feat(ottu): align the shared catalogue with Connect; register_ottu() (43a706d)
- feat(masking): content rules in packs; card/CVV/financial-id rules opt-in (e1e9e5e)

### Fixes
- fix(net): mask gateway bodies without log-record exemptions (242538e)
- fix(net): mask gateway bodies with nothing skipped (c6b5132)
- fix(events): warn once per retired name under concurrency; review nits (37ec549)
- fix(masking): mask each string to a fixed point; cache only fixed points (5382f3f)
- fix(masking): close the leaks review found; keep masking twice, cheaply (17104b1)
- fix(masking): mask every record in place again; keep the ADMINS rule (e7d6c34)
- fix(masking): JWT pre-check honours the rule's case-insensitivity (d698ba4)
- fix(masking): leave non-string args alone unless masking changed them (e02de78)
- fix(masking): never scan structural fields; exemption paths match at any depth (0e1b5ed)
- fix(masking): no match on digit runs touching letters; last 4 only below 15 digits (dc7f3d2)
- fix(masking): match key names by whole word, cache them, restore card keys (1063bec)

### Other
- Merge pull request #48 from ottuco/feature/catalogue-align (de1768f)
- Merge pull request #49 from ottuco/feature/net-parity (f0fb77e)
- Merge pull request #50 from ottuco/feature/masking-packs (f686c7a)
- Merge remote-tracking branch 'origin/feature/net-parity' into feature/masking-packs (206c124)
- Merge remote-tracking branch 'origin/feature/catalogue-align' into feature/net-parity (b459f06)
- Merge remote-tracking branch 'origin/feature/net-parity' into feature/masking-packs (d14ff26)
- docs: resolve the changelog merge left with conflict markers (5800653)
- Merge remote-tracking branch 'origin/feature/catalogue-align' into feature/net-parity (e6af61e)
- test: Connect's jade cases through the full logging pipeline (cd2e336)
- docs: masking packs, PCI opt-in and upgrade notes (4d2336f)
- perf(masking): try credential rules only near credential words; benchmark (05b8e3c)
- perf(masking): mask each record once; boot check accepts formatter masking (8481078)
- docs: implementation plan for masking packs (4bc9523)
- docs: design masking packs, one pass and precise rules for 0.8.0 (481dcb3)


## Unreleased

**Upgrading a PCI service (ottu_pg): enable the `pci` pack, or it loses PAN
and CVV content masking.** Card-number and CVV content rules, and the
IBAN/SSN/payment-id rules, are now opt-in packs:
`get_logging_config(masking_packs=("pci", "financial_ids"))`, or
`ECSCTX_MASKING_PACKS` as a Django setting or env var. That pair reproduces
0.7.x's content coverage. Key names (`card`, `pan`, `card_number`, `cvv`,
`securityCode`, `expiry`, `exp_month`, …) are masked in every service.

- Masking a Connect gateway-response record through `get_logging_config()`
  (handler filter + formatter): 486 µs → 47 µs, or 515 µs → 111 µs when the
  body holds a secret (0.6.8, formatter only: 18 µs; `scripts/bench_masking.py`).
  Content rules sit behind literal pre-checks with an early exit, credential
  rules are tried only near credential words, and key decisions are cached.
- A string is masked until a pass changes nothing (masking the CVV-shaped
  group after a PAN frees the PAN on the next pass), so the record the filter
  masks in place — what Sentry's logging integration reads — is complete on
  its own. Those fixed points are remembered, so the formatter's pass over
  them is a lookup.
- The correlation ids `session_id`, `trace` and `span` are never scanned
  (with `service`, `project`, `log`). A hex id starting with ten digits was
  being masked as a phone number: a digit run touching a letter is no longer
  a phone number. The card rule still matches a PAN followed by a letter
  (Track 2 data).
- Key names still match by substring, failing closed; `namespace`,
  `hostname`, `filename`, `token_type`, `tokenization_status` are safe keys.
  `user.name` is exempt from the name rule but content-scanned.
- PANs below 15 digits keep only their last 4 (PCI SSC FAQ 1091 covers them
  only for Discover); 15–19 digits keep first 6 + last 4.
- Card keys mask as in 0.6.8: a PAN value is truncated, a card object is one
  `[CARD-MASKED]`; expiry keys give `[EXPIRY-MASKED]` (they logged in clear
  since 0.7.0). Card values are never tokenized.
- `logger.info("%.3f", Decimal(...))` formats again: a number passed as a
  format argument stays a number unless its text holds something to mask. In
  structured fields every object, `Decimal` included, becomes its masked text,
  as in 0.7.x.
- Exemption paths anchor at the root or a payload container, so 0.6.x
  container-relative patterns (`payment_methods[*].name`) work again.
- A record masked with fewer packs is masked again by a filter with more
  (a PCI handler after a default one).
- `mask_sensitive_data` masks free-text `event.*` fields such as
  `event.reason`; only the bounded ones (action, kind, category, type,
  outcome, duration) are left alone.
- `ECSCTX_MASKING_PACKS` may be a list or a comma-separated string; an
  unknown pack name turns every pack on, warns once, and fails the boot
  check.
- The credential key prefix is bounded to 128 characters and the email rule
  to RFC 5321's lengths: a 20 KB run of `a-a-a-…` before `token` or `@` took
  seconds to scan. A credential whose key has 129+ characters before `_token`
  with no hyphen in them, or an email with a local part over 64 characters, is
  no longer masked by content (key-name masking is unchanged).
- The four non-ASCII letters `IGNORECASE` folds onto ASCII ones (`İ`, `ı`,
  `ſ`, `K`) are folded before the pre-checks, so they cannot skip a match.
- Boot check: Django's `AdminEmailHandler` counts as shipping only when
  `ADMINS` is set, so a stock project passes `manage.py check` with
  `ENVIRONMENT=prod`.
- The shared catalogue (`ecsctx.contrib.ottu`) carries ECS `category`, `type`
  and bounded `reasons` for all 63 events, aligned with Connect's
  definitions; `crypto.credential_resolved` is `debug` and
  `webhook.delivery_retried` is `warning`.
- A warning-level terminal event (`pg.request_failed`, `*_rejected`, …) now
  logs at **warning** through `emit(outcome="failure")`, not error; pass
  `level="error"` for an unexpected failure.
- `required` fields match what services emit: `cache.*` → `labels.cache`
  (+ `labels.cache_hit` on read, `labels.trigger` on invalidation), `net.*`
  → `labels.operation`, `task.*` → `labels.job`/`labels.queue`.
  `OUTBOUND_FAILURE_REASONS` is shared by `pg.request_failed` and
  `net.request_failed`.
- `ecsctx.contrib.ottu.api` is the `ecsctx.events.http` definition, so the
  catalogue and `register_http_events()` no longer conflict over `api`.
- `register_ottu(local=..., aliases=..., freeze=True)` registers the catalogue
  plus a service's own events (merged under shared prefixes).
- A retired event name warns once instead of on every log line.
- `ecsctx.contrib.net` gains `url_host()`, `loggable_request_body()` and
  `redact_url(url, secrets=...)` (literal values masked anywhere in the URL),
  so services can drop their own copies.
- `loggable_body()` uses a deny-list of unreadable content types instead of an
  allow-list of textual ones: JSON labelled `text/plain` or sent without a
  `Content-Type` is logged, and an HTML/PDF error body (4xx/5xx) is kept. A
  JSON body is masked by its keys before it is serialised.

## v0.7.2 (2026-09-17)

### Fixes
- Merge pull request #47 from ottuco/fix/159795-review-followup (a7415e2)
- fix(masking): address PR #46 review — doc drift and shared truncation (0f3a857)


## v0.7.1 (2026-09-17)

### Fixes
- fix(masking): truncate PANs to first6/last4 instead of full mask (07f80ed)

### Other
- Merge pull request #46 from ottuco/fix/159795-pan-truncation (ecd7800)


## v0.7.0 (2026-09-16)

### Features
- Merge pull request #29 from ottuco/task/158598-masking-filter (82319d5)
- feat(django): extend the masking check to the live logging tree (ab2eb8c)
- feat: expose MaskPIIFilter and install/uninstall_maskers at package root (614ffbc)
- feat(django): export validate_masking_config (0f5d6fc)
- feat(django): validate mask_pii_filter resolves to MaskPIIFilter (0b999f6)
- feat(django): add system check for PII masking configuration (39e3a22)
- feat(masking): tokenization, content/key rules, and MaskPIIFilter (e553341)

### Fixes
- test(django): cover the masking boot check (31d931d)
- test(masking): cover ecsctx.masking.install (89fdb3f)
- fix(django): wire mask_pii_filter into get_logging_config() by default (9ae7427)
- fix(masking): use tuples instead of dicts for pattern/keyword maps (fae01be)
- fix(pii): strip quotes and whitespace before AND after normalization (ac2a8e4)

### Other
- Merge pull request #45 from ottuco/chore/sync-init-version (0849dd2)
- Merge pull request #44 from ottuco/feature/shared-ottu-vocabulary (b409de7)
- Sync __version__ with pyproject (0.6.9) (4e7f81b)
- Merge origin/main (PR #43) into task/158598-masking-filter (bf19c6e)
- Merge pull request #43 from ottuco/feature/centralize-boundary-shapers (e4890da)
- Merge origin/main into task/158598-masking-filter + review fixes (4a4f0d4)
- Review fixes: UnicodeDecodeError catch, processor-order docs (496aa1d)
- Address review: outcome in required, auth mix note, renderer test (fda96be)
- Catalogue slice 3: threeds, net, task, cache, api, webhook, auth (8c45d63)
- Catalogue slice 2: payment + card domains (9eca7ec)
- Drop service legacy aliases from shared package (273c364)
- Add shared Ottu event catalogue (contrib.ottu), slice 1: pg + crypto (0e5f14c)
- Centralize ECS boundary shapers and normalizer processors (b52f8d0)
- docs(core): describe the masking engine and its submodules (1928a4c)
- docs(django): document the masking wiring and boot check (df4fe96)
- test(django): pin the callsite attribution assertions (da26844)
- test: assert whole values across the masking suites (f67b979)
- docs: describe the MaskPIIFilter masking setup (71f93d3)
- test: move the logging_state fixture into conftest (4698fca)
- refactor(masking): drop the unused _enabled flag (551b7e8)
- test(masking): port the full MaskPIIFilter case suite from ottu_pg (afc8bde)
- test(pii): cover ecsctx.pii.normalize (0961f57)
- test(masking): cover configure_masking_from_env, move normalize tests out (b64b11b)
- test(django): add end-to-end masking pipeline coverage, fix missing import (fb8a466)
- test(django): update test_django_processors.py for the MaskPIIFilter refactor (db08964)
- test(masking): drop stale _IS_MASKED_ expectation from empty-dict test (0639005)
- test(sentry): match masked auth-header assertion to current label format (237bf53)
- refactor(masking): drop the dict-level _IS_MASKED_ marker (9f57dfe)
- test(masking): update test_processors.py for the MaskPIIFilter refactor (315d5eb)
- refactor(django): move assert_masking_configured into contrib.django.checks (1696ffc)
- refactor(masking): unify already-masked marker for dicts and objects (bddb899)
- refactor(masking): move exemptions.py under masking/ (3d01d3f)
- refactor(masking): drop masking_is_disabled export (06b6fff)
- refactor(masking): split install_maskers()/uninstall_maskers() into config + handler variants (23beba9)
- refactor(masking): simplify install_maskers()/uninstall_maskers() (f7bcf7f)
- refactor(masking): delegate mask_sensitive_data processor to MaskPIIFilter (f0cbbe6)
- refactor(masking): move STRUCTURAL_ECS_KEYS to MaskPIIFilter as skip_keys default (1f8e2a2)
- refactor(masking): drop partial PAN reveal, always fully mask card numbers (a69c35f)
- refactor(masking): rename tokenize/mask/apply_all_patterns_masking for clarity (add4793)
- refactor(masking): centralize field-type rules via FieldRule, key detection via regex map (c7eda0b)
- chore: ignore __IGNORED__ directory (ec69ae2)
- refactor(processors): extract PII mask exemptions into ecsctx.exemptions (56043f0)


## Unreleased

- `ecsctx.contrib.net` gains the shared ECS boundary shapers: `ecs_url()`
(credential query redacted by default), `ecs_http()`, `parse_json_or_raw()`
- New structlog processors `normalize_url_field` / `normalize_payload_field`
(auto-shape `url=` / auto-parse bytes `payload=`), exported from `ecsctx`

## v0.6.9 (2026-09-12)

### Other
- Merge pull request #42 from ottuco/feature/pan-display-and-net-redact (ebe24ef)
- Review fixes: PAN idempotency, loggable_body fails closed, Django settings bridge (2813966)
- Display-mask PANs (12-19, first6/last4) and add contrib.net redaction (c92206f)


## Unreleased

- PANs are display-masked (`mask_pan`: first 6 + last 4, e.g. `411111******1111`) instead of tokenized, in free text and under card keys; coverage widened to 12–19 digits (Maestro–UnionPay) incl. bare `int` values
- New `ecsctx.contrib.net`: `redact_url` / `redact_body` / `loggable_body` ported from ottu_backend's net boundary, with `configure_redaction()` + `ECSCTX_REDACT_EXTRA_SECRET_KEYS` / `ECSCTX_REDACT_BODY_LOG_CAP` overrides
(explicit call > Django settings > env; no hard Django dependency)
- PAN display-masking is idempotent: a second pass leaves `mask_pan()` output
alone instead of degrading it to an opaque token
- `loggable_body` never raises: an unreadable body is omitted (`None`)

## v0.6.8 (2026-09-07)

### Other
- Merge pull request #41 from ottuco/fix/lowercase-boundary-messages (be9062e)
- Stop the mpgs masking test failing on a random token (b5ec357)
- Say what happened, not "inbound"/"outbound", on the API boundary (0.6.7) (0dce196)


## v0.6.6 (2026-09-05)

### Other
- Merge pull request #40 from ottuco/fix/service-target-clobber (2ebd7fd)
- Remove the committed .venv symlink, and stop it recurring (8baa4ca)
- CI: use setup-uv@v10.0.1 (no v10 major alias exists) (0976c6a)
- CI: upgrade actions to Node 24 versions (b7741a1)
- CI: pin uv to 0.12.9 (dbb3e8e)
- Regenerate uv.lock for 0.6.5 (e32366f)
- Stop clobbering caller-set service.* subfields, release 0.6.5 (514d4eb)


## v0.6.4 (2026-09-04)

### Other
- Merge pull request #39 from ottuco/fix/restore-http-boundary-events (209f7c5)
- Say why a refusal carries no error.type (8ef8982)
- Name the two boundary log lines, and time them (#159494) (be298ae)


## v0.6.3 (2026-09-04)

### Other
- Merge pull request #38 from ottuco/feature/159487 (9802e67)
- Merge pull request #36 from ottuco/task/159492 (2717770)
- Merge pull request #35 from ottuco/task/159491 (d5a7445)
- Merge pull request #34 from ottuco/task/159490 (4d6e509)
- Merge pull request #33 from ottuco/task/159489 (00a8c27)
- Merge pull request #32 from ottuco/task/159488 (bceb5b3)
- Say what CARD_KEYS holds, and test all seven token spellings (b8d58c7)
- Honour path exemptions for list elements, not just dict leaves (1a34df2)
- Mask the saved-card token too, not just the card (6b98f37)
- Stop reserving `level`, which never collided (7b38fab)
- Reject fields that collide with the ones emit_pair sets itself (93a8ffe)
- Add timed() and emit_pair(), so event.duration is implementable (#159492) (c1d360e)
- Pin the double-pass behaviour, and say in the README what is not repaired (d96a73d)
- Add the log-contract processor, in strict and repair modes (#159491) (597f2cc)
- Follow the live root allowlist, and reject a duplicated action (157a6a5)
- Add ecsctx.events: declared events, a registry and one emit() (#159490) (740a30f)
- Move the identity section out of the middle of the table (4394a87)
- Update the docs this change invalidated (d1ebc66)
- Resolve service identity from settings, not only the environment (13ecc55)
- Note what the container propagation widens (1a8631c)
- Sort imports and drop the one left unused (3a06ba5)
- Propagate card sensitivity into nested containers (ead6442)
- Teach the masker to recognise cardholder data (5bd4882)


## v0.6.2 (2026-08-11)

### Features
- Merge pull request #28 from ottuco/task/158768_sentry_integration_params (20a3583)
- feat(sentry): breadcrumb level + ignore_loggers on SentryIntegration (#158768) (0199b01)


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

