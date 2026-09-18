---
paths:
  - "ecsctx/contrib/ottu/**"
  - "ecsctx/events/**"
  - "docs/events.md"
  - "docs/rules/**"
---

# The shared Ottu event catalogue

`ecsctx.contrib.ottu` is the vocabulary every Ottu service logs with, owned by
several teams. A change here reaches every service, so review it as an API
change, not as a log line.

## Adding an event

- **Check for synonyms.** Search `docs/events.md` for the same thing under
  another word. A near-duplicate (`payment.session_initiated` next to
  `payment.session_created`) is the defect this package exists to prevent.
- **Check it is shared.** More than one service logs it, or will. An event only
  one service can ever log belongs in that service's events module.
- **Check the domain.** Pick the domain whose table row in `docs/events.md`
  covers it. A new domain goes in `ALL_DOMAINS`. It may not be an ECS field-set
  name (`registry.RESERVED_PREFIXES`).
- **Check the name.**
  - It passes `rules.check()`; the catalogue test enforces this.
  - A new word in `rules.VERBS` needs a reason why no existing verb fits.
  - A word that has already drifted goes into `rules.SYNONYMS`, pointing at the
    word to use.
- **Check the description.** It says when to log the event and what success
  and failure mean, in terms a developer on another service understands.
- **Check the reasons.** They are a `Reason` subclass next to the event, and
  each value names a cause.
- **Check the generated page.** Regenerate `docs/events.md` with
  `python -m ecsctx.contrib.ottu.render_docs`; the test fails on a stale copy.

## Changing an event

- Adding a reason or a field is additive.
- Renaming an action, removing an event or removing a reason value is
  breaking. Every service and dashboard that uses the old value must move, so
  it needs a CHANGELOG entry marked breaking and coordination with the teams
  that log it. `register_aliases()` can bridge a rename while call sites
  migrate.
