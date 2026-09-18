# Masking packs, one pass, precise rules — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make ecsctx's masking cheap and precise for non-PCI services while keeping
ottu_pg's PCI coverage available as opt-in packs.

**Architecture:** Content rules become tagged `Rule`s grouped into packs
(`default`, `pci`, `financial_ids`), compiled once per pack set and each guarded by a
cheap literal pre-check. `MaskPIIFilter` takes the effective packs, skips structural
fields, classifies keys by whole words through a cache, and keeps non-string args.
`get_logging_config()` masks each record once (formatter), and the boot check accepts
formatter-based masking.

**Tech Stack:** Python ≥3.10, structlog, stdlib logging, Django (optional), pytest.

**Spec:** `docs/superpowers/specs/2026-09-18-masking-packs-design.md`

## Global Constraints

- Released as 0.8.0; CHANGELOG leads with: a PCI service must enable `pci` (and
  `financial_ids` for 0.7.2 parity) or loses PAN/CVV content masking.
- Pack selection order: `get_logging_config(masking_packs=...)` / explicit
  `configure_masking(packs=...)` → Django `ECSCTX_MASKING_PACKS` → env
  `ECSCTX_MASKING_PACKS` (CSV) → `("default",)`; `default` always included; unknown
  name → `ValueError`.
- PAN: first 6 + last 4 for 15–19 digits; last 4 only for 12–14; never tokenized.
- CVV: always `[CVV-MASKED]`, never tokenized.
- Python 3.10 compatible: no possessive quantifiers / atomic groups in regexes.
- Test command: `.venv/bin/python -m pytest -q -p no:cacheprovider` (baseline 979
  passed, 4 xfailed).

---

### Task 1: Rule packs and pack selection

**Files:**
- Modify: `ecsctx/masking/patterns.py` (rule table, `mask_by_all_patterns`)
- Create: `ecsctx/masking/config.py` (pack + skip-path configuration state)
- Modify: `ecsctx/masking/filters.py` (`MaskPIIFilter.__init__`, `_mask_string`)
- Modify: `ecsctx/masking/__init__.py`, `ecsctx/__init__.py` (exports)
- Modify: `ecsctx/contrib/django/logging.py` (`get_logging_config(masking_packs=None)`)
- Test: `tests/test_masking_filter.py` (ported suite on all packs), `tests/test_masking_packs.py` (new)

**Interfaces:**
- Produces: `Rule(name: str, pack: str, pattern: re.Pattern, repl, gate: Callable[[str, str], bool])`;
  `RULES: tuple[Rule, ...]` in the documented global order; `PACK_NAMES = ("default", "pci", "financial_ids")`;
  `ALL_PACKS = frozenset(PACK_NAMES)`; `rules_for(packs: frozenset[str]) -> tuple[Rule, ...]` (cached);
  `mask_by_patterns(text: str, rules: tuple[Rule, ...]) -> str`; `mask_by_all_patterns(text)` = all packs (kept for callers).
- Produces (`config.py`): `configure_masking_packs(packs: Iterable[str] | None) -> None`,
  `get_masking_packs() -> frozenset[str]`, `_reset_masking_config()`.
- `MaskPIIFilter(*, skip_keys=..., packs: Iterable[str] | None = None)`: `None` → `get_masking_packs()` at call time.

- [ ] **Step 1: failing tests** in `tests/test_masking_packs.py`:

```python
import logging
import pytest
from ecsctx.masking.config import configure_masking_packs, get_masking_packs, _reset_masking_config
from ecsctx.masking.filters import MaskPIIFilter

@pytest.fixture(autouse=True)
def _reset():
    yield
    _reset_masking_config()

def _mask(msg, packs=None):
    record = logging.LogRecord("t", logging.INFO, __file__, 0, msg, None, None)
    MaskPIIFilter(packs=packs).filter(record)
    return record.msg

def test_default_pack_leaves_card_shaped_text_alone():
    assert _mask("card 4111111111111111 cvv 123 HTTP 200 OK") == "card 4111111111111111 cvv 123 HTTP 200 OK"

def test_pci_pack_truncates_the_pan_and_masks_the_cvv():
    assert _mask("card 4111111111111111 cvv 123", packs=("pci",)) == "card [CARD-MASKED:411111******1111] cvv [CVV-MASKED]"

def test_default_pack_still_masks_email_and_bearer():
    assert _mask("a@b.co Bearer abc12345def") == "[EMAIL-MASKED] Bearer [SECRET-MASKED]"

def test_packs_default_to_default_only():
    assert get_masking_packs() == frozenset({"default"})

def test_env_selects_packs(monkeypatch):
    monkeypatch.setenv("ECSCTX_MASKING_PACKS", "pci, financial_ids")
    assert get_masking_packs() == frozenset({"default", "pci", "financial_ids"})

def test_explicit_configuration_wins_over_env(monkeypatch):
    monkeypatch.setenv("ECSCTX_MASKING_PACKS", "pci")
    configure_masking_packs(["financial_ids"])
    assert get_masking_packs() == frozenset({"default", "financial_ids"})

def test_unknown_pack_is_rejected():
    with pytest.raises(ValueError, match="unknown masking pack"):
        configure_masking_packs(["pcii"])
```
  Plus a Django-settings precedence test (`settings.ECSCTX_MASKING_PACKS = ["pci"]` with
  pytest-django `settings` fixture) and `get_logging_config(masking_packs=("pci",))` →
  `get_masking_packs()` includes `pci`.

- [ ] **Step 2:** run `pytest tests/test_masking_packs.py` → fails (module missing).
- [ ] **Step 3: implement.** Convert `REGEX_MASKER` entries to `Rule`s tagged with the
  spec's pack table (1,2,3,8,12,13,14 → default; 4,5,9,15,17 → pci; 6,7,10,11,16 →
  financial_ids), keep global order. Gates (lowercased text `l`, raw `s`):
  PEM `"-----begin" in l`; credential `any(w in l for w in _CRED_LITERALS)` with
  `_CRED_LITERALS = ("token", "secret", "password", "passwd", "bearer", "basic", "digest", "credential", "authorization", "authorisation", "key")`;
  CVV keyed `any(w in l for w in ("cvv", "cvc", "security"))`; payment-id
  `"id" in l`; IBAN `_DIGITS_2.search(s)`; phone/SSN `_DIGITS_7.search(s)` (≥7 digits
  with optional separators); card `_DIGITS_12` (12 digits with optional `[-\s]`);
  email `"@" in s`; JWT `"eyJ" in s`; bare CVV `_DIGITS_3.search(s)`.
  `rules_for` = `functools.lru_cache` over `frozenset`. `config.py`: explicit >
  Django setting (read lazily, guarded like `identity._from_django`, cached only once
  settings are configured) > env > default; normalise by adding `"default"`.
  `get_logging_config(..., masking_packs=None)` calls `configure_masking_packs` when
  given. In `tests/test_masking_filter.py` change the module helper `_mask` to
  `MaskPIIFilter(packs=ALL_PACKS)` and `mask_by_all_patterns` stays all-packs, so the
  ported suite keeps its meaning.
- [ ] **Step 4:** full suite green (except tests that pinned the removed behaviour —
  none expected in this task).
- [ ] **Step 5:** commit `feat(masking): content rules in packs; card/CVV/financial-id rules opt-in`.

### Task 2: Whole-word, cached key classification; card/expiry/CVV keys

**Files:** `ecsctx/masking/patterns.py` (`check_if_sensitive_keyword`, `SAFE_KEYS`),
`ecsctx/masking/fields_rules.py` (`expiry`, card non-tokenizable),
`ecsctx/masking/filters.py` (`_mask_dict` card branch); tests in
`tests/test_masking_filter.py::TestCheckIfSensitiveKeyword` and `tests/test_masking_packs.py`.

**Interfaces:**
- Produces: `classify_key(key: str, packs: frozenset[str]) -> str | None` (cached);
  `check_if_sensitive_keyword(key)` = `classify_key(key, ALL_PACKS)`;
  `mask_card_value(value) -> str` (truncates 12–19 digits, else `[CARD-MASKED]`).

- [ ] **Step 1: failing tests**

```python
@pytest.mark.parametrize("key", ["namespace", "hostname", "telemetry", "tokenization_status", "token_type", "card_id", "filename"])
def test_whole_words_only(key):
    assert classify_key(key, frozenset({"default"})) is None

@pytest.mark.parametrize("key,expected", [
    ("first_name", "name"), ("cardHolderName", "name"), ("access_token", "secret"),
    ("x-api-key", "secret"), ("cvv", "cvv"), ("security_code", "cvv"), ("cvv2", "cvv"),
    ("card_number", "card"), ("cardNumber", "card"), ("pan", "card"), ("card", "card"),
    ("expiry", "expiry"), ("exp_month", "expiry"), ("expirationDate", "expiry"),
    ("phone", "phone"), ("telephone", "phone"), ("billing_address", "address"),
])
def test_key_classification(key, expected):
    assert classify_key(key, frozenset({"default"})) == expected

def test_payment_id_keys_follow_the_financial_ids_pack():
    assert classify_key("transaction_id", frozenset({"default"})) is None
    assert classify_key("transaction_id", frozenset({"default", "financial_ids"})) == "payment_id"

def test_card_key_is_truncated_not_tokenized():
    assert _mask({"card_number": "4111 1111 1111 1111", "expiry": "12/27", "cvv": "123"}) == {
        "card_number": "[CARD-MASKED:411111******1111]", "expiry": "[EXPIRY-MASKED]", "cvv": "[CVV-MASKED]"}
```
- [ ] **Step 2:** run → fail.
- [ ] **Step 3: implement.** Tokenizer `_KEY_SPLIT = re.compile(r"[_\-.\s]|(?<=[a-z0-9])(?=[A-Z])")`,
  drop trailing digits per word, lowercase. Word sets per field type (`cvv`:
  `{cvv, cvc, cvn}` + phrase `security code`; `card`: exact key `card`, word `pan`,
  phrases `card number`/`card no`, word `cardnumber`; `expiry`: words starting with
  `expir`, `exp month|year|date`; `secret`: `{token, secret, password, passwd, bearer,
  basic, digest, credential, credentials, authorization, authorisation, apikey}` or a
  `{secret, private, public, encryption, decryption, signing, access, master, root,
  session, api}` word followed by `key`; `email`; `phone`: `{phone, mobile, tel,
  telephone, msisdn}`; `address`; `name`: `{name, cardholder, beneficiary, recipient,
  payer}`; `generic`: `{billing, shipping, customer, contact, udf}`; `payment_id`
  (pack-gated): `payment|transaction|auth` followed by `id`). Order of checks: SAFE_KEYS,
  cvv, card, expiry, secret, payment_id, email, phone, address, name, generic.
  `SAFE_KEYS += {"token_type"}`. `FIELD_RULES["expiry"] = FieldRule("expiry", False, False)`,
  `card` → `tokenizable=False`. `_mask_dict`: `card` → `mask_card_value(value)`.
- [ ] **Step 4:** suite green; update `TestCheckIfSensitiveKeyword` rows that pinned
  substring matches (each changed row named in the commit body).
- [ ] **Step 5:** commit `fix(masking): match key names by whole word, cache them, restore card keys`.

### Task 3: Boundaries and PAN truncation

**Files:** `ecsctx/masking/patterns.py` (`_CARD_TAIL_GUARD`, `_truncate_pan`),
`ecsctx/processors.py` (`mask_pan`); tests `tests/test_masking_packs.py`,
`tests/test_masking_filter.py` (card cases for 12–14 digits), `tests/test_processors.py` (`mask_pan`).

- [ ] **Step 1: failing tests**

```python
@pytest.mark.parametrize("value", [
    "8231045567ab34cd9f0e1a2b3c4d5e6f7a8b9c0d",      # session_id: 10 digits then hex
    "1726650000123456789abcdef0123456",              # trace.id: 19 digits then hex
])
def test_digit_run_touching_letters_is_not_a_phone_or_pan(value):
    assert _mask(value, packs=ALL_PACKS) == value

def test_short_pan_keeps_last_four_only():
    assert _mask("pan 5018123456789", packs=("pci",)) == "pan [CARD-MASKED:*********6789]"

def test_mask_pan_agrees_with_the_rule():
    assert mask_pan("4111111111111111") == "411111******1111"
    assert mask_pan("5018123456789") == "*********6789"
```
- [ ] **Step 2:** run → fail.
- [ ] **Step 3:** `_CARD_TAIL_GUARD = r"(?![-\s]?\d)(?![A-Za-z])"`; `_truncate_pan`:
  `n >= 15` → first 6 + stars + last 4, else stars + last 4.
- [ ] **Step 4:** suite green; update CARD_NUMBER_CASES rows for 12–14 digit PANs.
- [ ] **Step 5:** commit `fix(masking): no match on digit runs touching letters; last 4 only below 15 digits`.

### Task 4: Structural skip paths and suffix exemptions

**Files:** `ecsctx/masking/config.py` (skip paths), `ecsctx/masking/filters.py`
(`STRUCTURAL_ECS_KEYS`, `_mask_dict`), `ecsctx/masking/exemptions.py` (`_path_is_exempt`),
`ecsctx/contrib/django/processors.py` (bridge `ECSCTX_MASK_SKIP_PATHS`); tests
`tests/test_masking_packs.py`, `tests/test_processors.py`.

**Interfaces:** `DEFAULT_SKIP_PATHS: tuple[tuple[str, ...], ...]`;
`configure_masking_skip_paths(paths: Iterable[str])`; `get_skip_paths()`.

- [ ] **Step 1: failing tests**

```python
def test_structural_fields_are_not_scanned():
    event = {"session_id": "8231045567abcd", "trace": {"id": "4111111111111111"},
             "labels": {"namespace": "cybersource", "hostname": "jade"},
             "user": {"name": "admin@jade.ottu.dev"}, "http": {"response": {"status_code": 200}},
             "service": {"name": "app"}}
    assert MaskPIIFilter(packs=ALL_PACKS)._mask_dict(dict(event)) == event

def test_container_relative_exemption_still_applies():
    configure_masking(exempt_paths=["payment_methods[*].name"])
    out = MaskPIIFilter()._mask_dict({"payload": {"payment_methods": [{"name": "KNET"}]}})
    assert out == {"payload": {"payment_methods": [{"name": "KNET"}]}}
```
- [ ] **Step 2:** run → fail.
- [ ] **Step 3:** default skip set = top-level `{"service","project","log","session_id",
  "trace","span","host","labels","ecs_event"}` plus leaves
  `("transaction","id")`, `("user","name")`, `("http","request","method")`,
  `("http","response","status_code")`, `("url","domain")`; `_mask_dict` checks
  `child_path in skip_exact` (O(1)) before classifying; configured wildcard patterns
  go through `_path_matches`. Exemption match: pattern matches if it equals the path's
  trailing segments or its prefix (`_path_matches(path[i:], pattern)` for any `i`).
  Keep `skip_keys` kwarg working (top-level).
- [ ] **Step 4:** suite green.
- [ ] **Step 5:** commit `fix(masking): never scan structural fields; exemption paths match as suffixes`.

### Task 5: Keep non-string args

**Files:** `ecsctx/masking/filters.py` (`_mask_value`); test `tests/test_masking_packs.py`.

- [ ] **Step 1: failing test**

```python
def test_numeric_format_args_survive(caplog):
    record = logging.LogRecord("t", logging.INFO, __file__, 0, "refunded %.3f of %d", (Decimal("12.5"), Decimal("3")), None)
    MaskPIIFilter().filter(record)
    assert record.getMessage() == "refunded 12.500 of 3"
```
- [ ] **Step 2:** run → `TypeError`.
- [ ] **Step 3:** non-string, non-container value: `text = str(value)`; `masked = self._mask_string(text)`; return `value if masked == text else masked`.
- [ ] **Step 4:** suite green. **Step 5:** commit `fix(masking): leave non-string args alone unless masking changed them`.

### Task 6: One pass per record; boot check

**Files:** `ecsctx/masking/install.py` (`install_maskers_in_config`),
`ecsctx/contrib/django/logging.py` (docstring), `ecsctx/contrib/django/checks.py`
(`_handler_masked_by_formatter`, live variant, AdminEmailHandler/ADMINS);
tests `tests/test_masking_install.py`, `tests/test_masking_config_check.py`, `tests/test_django_logging.py`.

- [ ] **Step 1: failing tests**

```python
def test_console_handler_is_masked_by_its_formatter_only():
    cfg = get_logging_config()
    assert "mask_pii_filter" not in cfg["handlers"]["console"]["filters"]
    assert find_masking_config_errors(cfg) == []

def test_handler_with_a_foreign_formatter_gets_the_filter():
    cfg = get_logging_config()
    cfg["handlers"]["file"] = {"class": "logging.FileHandler", "filename": "x.log"}
    install_maskers_in_config(cfg)
    assert "mask_pii_filter" in cfg["handlers"]["file"]["filters"]

def test_admin_email_handler_ships_nothing_without_admins(settings):
    settings.ADMINS = []
    assert find_unmasked_live_handlers(settings.LOGGING) == []  # with django's DEFAULT_LOGGING applied
```
  Plus: with `settings.ADMINS = [("a", "a@x")]` the `django -> AdminEmailHandler` error is reported;
  a live handler whose `formatter.processors` includes `mask_sensitive_data` counts as masked.
- [ ] **Step 2:** run → fail.
- [ ] **Step 3:** `_formatter_masks(formatter_config)`: `formatter_config.get("()")`
  is `structlog.stdlib.ProcessorFormatter` (class or dotted path) and
  `mask_sensitive_data in formatter_config.get("processors", [])`.
  `install_maskers_in_config` skips handlers whose `formatter` names such a formatter.
  Checks: config handler masked if filter present or `_formatter_masks(formatters[h["formatter"]])`;
  live handler masked if filter or `mask_sensitive_data in getattr(handler.formatter, "processors", ())`;
  `AdminEmailHandler` counts as non-shipping when `not settings.ADMINS`.
- [ ] **Step 4:** suite green; update tests that asserted the filter on the console handler.
- [ ] **Step 5:** commit `perf(masking): mask each record once; boot check accepts formatter masking`.

### Task 7: Linear credential rules, cheaper phone guard, benchmark

**Files:** `ecsctx/masking/patterns.py` (rules 2, 3, 8, phone lead guard),
create `scripts/bench_masking.py`; tests: whole ported suite (behaviour must not change).

- [ ] **Step 1:** create `scripts/bench_masking.py`: fixtures from the spec (Connect
  body; body + `"access_token":"abc123def456"`; ottu_pg line with PAN/expiry/CVV on all
  packs); times `mask_sensitive_data` on a fresh copy per iteration minus the copy
  cost; prints µs/line per fixture; `--compare TAG` loads a git tag's ecsctx in memory
  for side-by-side numbers.
- [ ] **Step 2:** run it → record current numbers (expect fixture 2 above budget).
- [ ] **Step 3:** rewrite the `(?:[\w-]*[_-])?` credential prefix as
  `(?:[a-z0-9]+[_-])*` segments (each segment must end at a separator, so a word
  without a separator fails at its first attempt), and move the phone lead guard to a
  single `(?<![^\s,.:=\"'([{])(?<!\d )`; re-run the ported suite after each change.
- [ ] **Step 4:** bench within budget: fixture 1 ≤ 38 µs, fixture 2 ≤ 57 µs (2×/3× the
  0.6.8 figure of 19 µs, same machine). If fixture 2 misses, stop and report numbers
  before trying anything further.
- [ ] **Step 5:** commit `perf(masking): linear credential rules; benchmark script`.

### Task 8: Docs and CHANGELOG

**Files:** `README.md` (masking section, packs, PCI opt-in example, exemption paths,
skip paths, boot check), `CLAUDE.md`, `ecsctx/CLAUDE.md`, `CHANGELOG.md` (Unreleased →
0.8.0 notes: breaking PCI opt-in first; formats; one pass; key rules; boundaries; short
PAN; args; exemptions; boot check), `install_maskers()` docstring/docs.

- [ ] Update docs; run full suite; commit `docs: masking packs, PCI opt-in and migration notes`.

---

## Self-review

- Spec coverage: packs (T1), key rules (T2), fast paths — gates (T1) and skip set (T4),
  linear credential rules (T7), boundaries + PAN (T3), one pass + boot check (T6),
  correctness fixes — args (T5), exemptions + user.name (T4), budget (T7), tests (all),
  CHANGELOG/0.8.0 (T8).
- Names used across tasks: `Rule`, `RULES`, `ALL_PACKS`, `rules_for`,
  `mask_by_patterns`, `classify_key`, `mask_card_value`, `configure_masking_packs`,
  `get_masking_packs`, `_reset_masking_config`, `configure_masking_skip_paths`,
  `get_skip_paths` — consistent.
