# Masking packs, one pass, and precise rules (ecsctx 0.8.0)

## Why

0.7.0 made `MaskPIIFilter` (ported from ottu_pg) the engine for every service. Measured
against v0.7.2 on a Connect `pg.response_received` line with a 336-char gateway body:

- **Cost:** ~570 µs per line, against ~19 µs on 0.6.8. The record is masked twice
  (handler filter + formatter processor, ~285 µs each); every string runs all 17
  content regexes (3.5 µs even for `cs-direct`); key-name regexes re-run for every
  key on every line; the three credential regexes backtrack on their `[\w-]*` key
  prefix (~46 µs of the 129 µs a 336-char body costs).
- **Correlation damage:** a `session_id` starting with 10 digits becomes
  `[PHONE-MASKED]ab34…` (13 of 3,193 session lines on jade); `trace.id` and 12–19 digit
  ids become `[CARD-MASKED:172665…]`; the phone/card rules accept a digit run that
  runs straight into letters.
- **False positives:** key names match by substring (`namespace` → name,
  `hostname` → name, `telemetry` → tel); any bare 3–4 digit group in text is a CVV
  (`HTTP 200 OK`, `1500 ms`).
- **Lost lines:** the filter stringifies `record.args`, so `"%.3f" % "12.500"` raises
  `TypeError` and logging drops the line.
- **Silent regressions:** exemption paths became root-relative (Connect's
  `payment_methods[*].name` stopped applying); card/expiry keys stopped being sensitive
  by name (expiry logs in clear); `user.name` is masked.

Most services that use ecsctx never see a card number. Scanning every string of every
line for PANs and CVVs costs them CPU and correlation for nothing.

## Decisions

1. **Content rules come in packs.** `default` is always on; `pci` and
   `financial_ids` are opt-in, enabled by PCI services in their logging config.
2. **Key-name rules stay on everywhere,** card fields included: a key lookup is cached
   and near-free, and it only fires when such a key reaches a log line.
3. **PAN output:** first 6 + last 4 for 15–19 digits, last 4 only below 15. Logs are
   stored data, so PCI DSS 3.5.1 (truncation) applies; FAQ 1091 allows first 6 + last 4
   for 15–16 digit PANs of every listed brand and covers <15 only for Discover. No
   token or hash beside a truncated PAN (FAQ 1117).
4. **CVV is masked in full, never tokenized**, in every form the `pci` pack detects,
   including a token + CVV payment (no PAN present).
5. **One masking pass per record per handler.**
6. **Structural fields are never content-scanned.**

Released as **0.8.0**: a PCI service that upgrades without enabling `pci` loses PAN and
CVV content masking. The CHANGELOG says so first.

## Design

### Packs (`ecsctx/masking/patterns.py`)

The 17 regexes keep their text and their relative order; `REGEX_MASKER` is split into:

| Pack | Rules (current numbering) | Default |
|---|---|---|
| `default` | 1 PEM, 2/3/8 credential, 12 phone, 13 email, 14 JWT | on |
| `pci` | 4/5/9 keyed CVV, 15 card, 17 bare CVV | off |
| `financial_ids` | 6/7/10 payment-id, 11 IBAN, 16 SSN | off |

Within an enabled set, rules run in the documented global order, so the ordering
invariants (credential/CVV/payment-id before shape rules; IBAN and phone before card;
SSN before bare CVV; bare CVV last) hold for any combination.

Selection, first match wins: `get_logging_config(masking_packs=...)` →
Django `ECSCTX_MASKING_PACKS` → env `ECSCTX_MASKING_PACKS` (CSV) → `("default",)`.
`default` is always included. An unknown pack name raises `ValueError` at
configuration time. ottu_pg's 0.7.2 coverage is `("default", "pci", "financial_ids")`.

### Key-name rules (`patterns.py`, `fields_rules.py`)

- Keys are split into lowercase words on `_`, `-`, `.` and camelCase, with trailing
  digits dropped (Connect's `utils/log_masking.py` tokenizer). A keyword matches a
  whole word, never a substring: `namespace`, `hostname`, `telemetry`,
  `tokenization_status` no longer match.
- The key → field type decision is memoised (`functools.lru_cache`, bounded).
- Always on: secret/credential, cvv, card, expiry, email, phone, address, name,
  generic. `payment_id` key matching follows the `financial_ids` pack.
- Card keys restored: exactly `card`, `pan`, `card_number`/`cardnumber`/`card_no`
  → card; `expiry*`, `expiration*`, `exp_month`, `exp_year`, `exp_date` → a new
  `expiry` type (not tokenizable, not exemptable) → `[EXPIRY-MASKED]`; `cvv`, `cvc`,
  `cvn`, `cvv2`, `security_code` → cvv. `card_id` is not a card key.
- A key-matched card value is truncated like the content rule when it holds 12–19
  digits, else `[CARD-MASKED]` — never tokenized.
- `token_type` joins `SAFE_KEYS` (OAuth metadata, not a secret).

### Fast paths (`patterns.py`, `filters.py`)

- **Per-rule literal pre-check.** Each rule carries a cheap test derived from its own
  pattern; the regex runs only if it passes: `-----begin` (PEM); the credential words
  spelled in full — `token`, `secret`, `password`, `passwd`, `bearer`, `basic`,
  `digest`, `credential`, `authorization`, `authorisation`, and `key` for the `*_key`
  compounds; `@` (email); `eyJ` (JWT); a digit run of the rule's minimum length
  (phone, card, SSN, IBAN, CVV). The substring used must be one the rule requires:
  `authori` is wrong because "AUTHORIZED" contains it and the rule needs
  `authorization`.
- **Structural skip set.** Never content- or key-scanned: `event.*`, `trace`, `span`,
  `session_id`, `service`, `project`, `log`, `host`, `labels`,
  `ecs_event`, and the leaves `transaction.id`, `user.name`, `http.request.method`,
  `http.response.status_code`, `url.domain`. Extended by
  `ECSCTX_MASK_SKIP_PATHS` (settings → env), matched with the exemption path syntax.
  `labels.*` is safe to skip because the event contract keeps labels bounded scalars.

### Linear credential rules (`patterns.py`)

Rules 2, 3 and 8 lose the unbounded `(?:[\w-]*[_-])?` prefix. The keyword is matched
directly with a word-boundary-aware prefix that cannot backtrack across the string
(`\b[\w-]{0,64}?` bounded, or keyword-first matching with the key reconstructed from a
lookbehind-free scan). Acceptance: identical output on the whole ported suite, and the
credential-bearing benchmark body within budget.

### Boundaries (`patterns.py`)

Phone, card, SSN and bare-CVV rules must not match a digit run adjacent to a letter or
digit on either side: `_CARD_TAIL_GUARD` becomes "not followed by `[-\s]?\d` and not
followed by a letter"; the lead guard already rejects a preceding letter.

### PAN truncation (`patterns.py::_truncate_pan`, `processors.py::mask_pan`)

```
15–19 digits: first 6 + '*' * (n - 10) + last 4    -> 411111******1111
12–14 digits: '*' * (n - 4) + last 4               -> ********1234
```

Both entry points share `_truncate_pan`. No Luhn gate inside the `pci` pack: in a PCI
service a PAN-shaped run is masked whether or not it checks out; the false positives
this caused came from the boundary and scope problems above.

### One pass per record (`install.py`, `contrib/django/logging.py`, `checks.py`)

- `install_maskers_in_config` attaches `mask_pii_filter` only to handlers whose
  formatter is **not** an ecsctx `ProcessorFormatter` that runs `mask_sensitive_data`.
  `get_logging_config()`'s console handler therefore no longer carries the filter; its
  formatter masks each record once (structlog records in `processors`; foreign records
  as in 0.6.8).
- The filter still exists for handlers ecsctx does not format (mail, third-party,
  plain console) and for `install_maskers_on_handlers()`.
- The boot check counts a handler as masked if it carries the filter **or** its
  formatter (declared by name in `LOGGING["formatters"]`, or live
  `handler.formatter.processors`) includes `mask_sensitive_data`.
- `django.utils.log.AdminEmailHandler` is treated as non-shipping when
  `settings.ADMINS` is empty (it sends nothing), so a stock `get_logging_config()`
  project passes `manage.py check` with `ENVIRONMENT=prod`; with `ADMINS` set it is
  still reported.

### Correctness fixes (`filters.py`, `exemptions.py`)

- **Args preserved.** A non-string value is scanned as `str(value)` and returned
  unchanged unless masking altered that text, so `%d`/`%f` with `Decimal`, `UUID`,
  `datetime` keep formatting.
- **Exemption paths match as suffixes** of the record path, so container-relative
  patterns written for 0.6.x (`payment_methods[*].name`) keep working, as do
  root-relative ones (`payload.payment_methods[*].name`).
- `user.name` is in the skip set.

## Performance budget

`scripts/bench_masking.py` times `mask_sensitive_data` on fixed fixtures:

1. Connect `pg.response_received` with the 336-char gateway body (default pack).
2. Fixture 1 with a `"access_token":"…"` field in the body (default pack).
3. An ottu_pg-style line with a PAN, an expiry and a CVV (`default` + `pci` +
   `financial_ids`).

Budget, same machine as the baseline: fixture 1 ≤ 2 × 0.6.8 (0.6.8 = 19 µs), fixture 2
≤ 3 × 0.6.8, and a record passes through no more masking steps than on 0.6.8. The
script prints 0.6.8 / 0.7.2 / new numbers for the PR.

## Tests

- The ported MaskPIIFilter suite passes with all three packs enabled.
- With the default pack: a 40-hex `session_id` and a 32-hex `trace.id` starting with
  10–19 digits are untouched; `labels.namespace`, `user.name`, `hostname` untouched;
  `HTTP 200 OK` and `1500 ms` untouched; a PAN in free text is untouched by content
  rules but a `card_number` key is truncated; `expiry` key → `[EXPIRY-MASKED]`;
  `cvv` key → `[CVV-MASKED]`; `token_type` untouched; `access_token` masked.
- With `pci`: bare CVV masked; token + CVV payload (`{"token": …, "cvv": "123"}` and
  free text `token abc123 cvv 123`) masks the CVV in full; 16-digit PAN →
  `411111******1111`; 13-digit PAN → last 4 only; `mask_pan` agrees.
- `logger.info("%.3f of %d", Decimal("12.5"), Decimal("3"))` formats.
- Both exemption spellings apply.
- Boot check: stock config passes with `ENVIRONMENT=prod` and empty `ADMINS`; fails
  with an unmasked shipping handler; fails for `AdminEmailHandler` with `ADMINS` set.
- Pack selection: settings, env, argument precedence; unknown pack raises.

## Out of scope here (same release, separate PRs)

- Catalogue alignment with Connect as the reference (`category`/`type`/`reasons`,
  required fields, `failure_level`, one `api` definition, `register_ottu`, alias
  warnings once).
- `contrib.net` parity with Connect (`url_host`, `loggable_request_body`,
  `redact_url(secrets=)`, deny-list `loggable_body`, precise query hints).
