# ecsctx.events — a declared event vocabulary, and one way to emit it

Ticket #159490. Parent #159487.

## The problem

`event.action` is the field an agent reads first to know what happened, and it is
the least disciplined field we have. Production carried 34 hand-rolled names in
Connect — 88% with no namespace, two containing a literal space, one in
SCREAMING_CASE — and roughly 163 in Ottu PG. Nothing rejected any of them,
because writing a log line takes a string and a string is always valid.

Connect now has `utils/log_events.py` (#159493): 92 events as frozen constants,
so a typo is an `ImportError`. That fixes one service. Wallet, AutoPay, Event
Management, Real Estate and Ottu PG each still get to invent their own, and
nothing makes two services spell the same concept the same way.

The mechanism belongs one level down, in the package all of them already import.

## What ships here, and what does not

ecsctx is public and MIT licensed. It ships the **mechanism**: how an event is
declared, how a domain registers, where a field lands in the document. Ottu's
**vocabulary** — `pg.*`, `payment.*`, `wallet.*`, our merchant semantics — stays
private in `ottu_backend` and registers at startup through `register_domain()`.

The line is: a reader of this package learns how to declare events, not what
Ottu's events are.

Payment-generic concepts already in the package (`payment.pg_code`, `merchant_id`
in `ROOT_ALLOWLIST`) predate this and stay.

## Modules

Four files, each with one job.

### `spec.py` — what an event is

`EventSpec` is a frozen slotted dataclass. It is deliberately a superset of
Connect's `LogEvent`, with an identical `.ecs()` signature and output, so
`utils/log_events.py` can be swapped onto it mechanically in a later ticket
rather than maintained twice.

Two additions over `LogEvent`:

- **`failure_level`.** `LogEvent.level` documents the *success* path only. The
  taxonomy that generated it said things like "info on success, error on
  failure", and the generator kept the first word — so the failure level was
  lost, and `emit()` had no way to know that `pg.response_received` is `info`
  when it works and `error` when it does not. `failure_level` defaults to
  `"error"` for terminal events and to `level` otherwise.
- **`required` / `optional`.** Field names this event is expected to carry.
  Declaration only: nothing in this ticket enforces them. The runtime validator
  (#159491) is the consumer, and putting the declaration here means EventSpec is
  not reopened next ticket.

`__str__` returns the action, so a spec drops into an f-string message or a
dict key without `.action`.

`.ecs()` keeps every validation `LogEvent` already had — terminal events refuse
to build without an outcome, outcome is checked against the ECS closed set,
a declared `reasons` tuple bounds `event.reason`, and `duration_ns` rejects
negatives. `duration_ns` is nanoseconds because ECS `event.duration` is, and a
millisecond value misreports by six orders of magnitude while looking fine.

### `registry.py` — who owns which prefix

A process-global registry mapping domain prefix to its specs.

- `register_domain(prefix, specs)` rejects a prefix already registered, a prefix
  that is not a bare lowercase identifier, and any spec whose action does not
  start with `<prefix>.`. Two services claiming `payment.*` with different
  meanings is the failure this prevents.
- **Reserved prefixes** are the ECS field-set names — `ecs`, `event`, `log`,
  `service`, `trace`, `span`, `error`, `http`, `url`, `user`, `labels`. A domain
  called `log` emitting `log.written` reads in a query exactly like the `log.*`
  field set, and the ambiguity is unfixable after the fact.
- `resolve(name)` returns a spec by action, following the legacy alias map.
- `register_aliases(mapping)` maps an old name to a current one. 44 `ecs_event`
  sites in Connect and ~163 live names in Ottu PG predate this; they migrate by
  alias rather than by breaking.
- `freeze()` closes registration after app loading. A domain registered later
  than that is invisible to anything that snapshotted the registry, which is a
  bug that otherwise surfaces as a missing event in Kibana weeks later.

### `fields.py` — where a kwarg lands

The kwarg-to-ECS-path table, so field placement stops being a per-developer
decision. `session_id` stays at root; `pg_code` becomes `payment.pg_code`;
`status_code` becomes `http.response.status_code`.

Routing rules, in order:

1. A name in the table goes to its declared path, deep-merged so `method` and
   `status_code` land in one `http` object rather than clobbering each other.
2. Any other scalar goes to `labels.<name>` — ECS's sanctioned home for
   arbitrary keyword data, and aggregatable.
3. Any other non-scalar goes to `extra.<name>`, which is where
   `namespace_ecs_fields` would have put it anyway.

Nothing warns here. Unknown-field warnings are the validator's job (#159491);
splitting them keeps this table a pure lookup.

Every path in the table resolves under a key already in `ROOT_ALLOWLIST`, so
routing never produces a field that the processor chain then buries in `extra`.

### `emit.py` — one call

```python
emit(logger, PG_RESPONSE_RECEIVED, "PG replied", outcome="success",
     duration_ns=elapsed, pg_code="mpgs", status_code=200)
```

builds `ecs_event=`, routes the fields, picks the level, and calls the logger.

Level precedence: an explicit `level=` wins; then `failure_level` when
`outcome="failure"`; then `spec.level`.

`*args` passes through untouched, so `emit(log, SPEC, "took %s", elapsed)` keeps
lazy formatting — the house rule against f-strings in logging still applies, and
an API that forced eager formatting would quietly break it.

`spec` may be a string, resolved through the registry and the alias map, so
call sites migrating from raw names have a step that does not require importing
constants yet.

## What is out of scope

- Enforcement of `required`/`optional` — #159491.
- A `timed()` context manager for `event.duration` — #159492.
- Ottu's actual vocabulary — stays in `ottu_backend`.
- Migrating Connect's `utils/log_events.py` onto `EventSpec` — a Connect ticket,
  and gated on this being released.

## Testing

Behaviour, not implementation:

- `.ecs()` output equals `LogEvent.ecs()` output for the same inputs, asserted
  against the real Connect definitions, so the swap later is a rename.
- Registry rejects duplicate prefixes, reserved prefixes, and mismatched actions.
- `freeze()` makes registration raise.
- Routing places each table entry at its declared path, and two `http` kwargs
  merge rather than overwrite.
- `emit()` chooses the failure level on `outcome="failure"` and respects an
  explicit override.
- `emit()` with a string name resolves through an alias.
- Lazy `%s` args survive to the logger uncollapsed.
- Every routed path's root key is in `ROOT_ALLOWLIST` — the property that keeps
  routing honest as the table grows.
