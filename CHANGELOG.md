# Changelog

## Unreleased

### Fixed

- A saved card's `agreements` read through with Ottu's safe keys
  (`ecsctx.contrib.ottu.masking.SAFE_KEYS`). Walked as part of the card, each
  auto-debit agreement id came out as `[CARD-MASKED]`. Without the list it
  stays masked.
- `card_details`, as a key or as a "Card Details" label beside a `value`, is
  masked as a name. It is one string of brand, holder's name, masked number and
  expiry, and nothing classified it, so the holder's name shipped in clear. A
  longer key (`card_details_url`) reads as before.

## v0.15.1 (2026-09-25)

### Fixes
- Merge pull request #65 from ottuco/fix/crypto-key-names (b253e24)
- fix(masking): the key-algorithm text rule matches in linear time (ca06fdc)
- fix(masking): a key name that says it holds key material is a credential (8c6c40b)

### Other
- chore: shorter, generic comments for the key-material rules (2cdba49)


## Unreleased

### Fixed

- Key names that carry key material are credentials. A size, mode or
  algorithm between the stem and `key` let the value through (`aes256Key`).
  Now masked:
  - an algorithm, size or mode before `key`: `aes256Key`, `aesGcmKey`,
    `hmacSha256Key`, `3desKey`, `rsaKey`;
  - an encoding after it: `privateKeyPem`, `aesKeyBase64`;
  - `symmetricKey`, `cipherKey`, `cryptoKey`, `wrappedKey`, `rawKey`,
    `keyMaterial`;
  - payment-HSM keys as the last word: `zpk`, `zmk`, `tmk`, `bdk`, `ipek`,
    `kek`, `dek`.

  Names that only refer to a key stay readable (`sessionKeyId`, `keyAlias`,
  `tmkCheckValue`).
- The text rules mask the same algorithm- and encoding-named keys, for text
  that is not valid JSON.

## v0.15.0 (2026-09-24)

### Fixes
- fix(django): unhandled_exception masks the route's credentials in url.path (a4331e5)
- fix(django): mask the segments a route parameter fills, not every match (a61a49d)
- fix(django)!: api_logging names the route, not the path (d9d4234)

### Other
- Merge pull request #63 from ottuco/fix/api-logging-route-not-path (645c5a2)
- Merge pull request #64 from ottuco/fix/unhandled-exception-url-path (343df7a)


## Unreleased

### Changed (behaviour)

- `@api_logging`'s two messages name the route the request matched, not its
  path: `api request received: DELETE /v1/cards/<str:token>/`, where it was
  `… DELETE /v1/cards/9584184138614802/`. A path carries ids and credentials,
  and made every message unique, so the lines never grouped in Kibana. **The
  message text changes, so a Kibana saved search, alert or visualization on
  the old paths needs updating**: to the route, or to `url.path` for one
  specific path. The messages that change:
  - every route with a parameter;
  - every regex route (`re_path()`, DRF's routers), which reads as its
    pattern, parameters or not: `/api/payments/$`,
    `/api/payments/(?P<pk>[^/.]+)/$`;
  - every message of a service mounted under a prefix: the route leaves
    `FORCE_SCRIPT_NAME` out. Connect has both of the last two: `POST
    /b/pbl/v2/sign/` reads `POST /pbl/v2/sign/?$`, and its card deletion
    `DELETE /pbl/v2/card/(?P<token>[^/.]+)/?$`.

  A `path()` route without parameters, in a service with no mount prefix,
  reads as before. A view called without URL resolution (`APIRequestFactory`
  in a test) still names its path.

### Fixed

- `url.path` on the same two lines carried a credential in a path segment in
  clear (Connect's `DELETE /pbl/v2/card/<token>`, ottu_pg's
  `/v1/pbl/card/token/<str:token>/`). Each segment a route parameter fills is
  now masked by `mask_by_field_type(value, key_field_type(name))` when the
  engine classifies its name: `/v1/cards/[SECRET-MASKED]/`, or the bare
  `ptok:` token where PII tokenization is configured. A parameter it leaves
  alone (`pk`, `uid`) stays readable, and so does the mount prefix, unless it
  has the same text as a masked value. A value that shares its segment (a
  regex route's `(?P<token>[^/.]+)\.pdf`) is masked wherever it appears.
- `LoggingContextMiddleware`'s `unhandled_exception` line masks its
  `url.path` the same way. A view on a card route that raised logged the card
  token there in clear.

### Known

- Django's own `django.request` lines still write the raw path in their
  message ("Not Found: …", "Internal Server Error: …").

## v0.14.0 (2026-09-23)

### Features
- feat(masking): export key_field_type() for values that reach a log outside a mapping (e011a77)
- feat(masking): a key the service lists keeps its reference number readable (26b5799)
- feat(masking)!: walk a credential, CVV or SAD container instead of hashing it whole (1e92bda)

### Fixes
- fix(masking): an upper-case VALUE key is a pair too (43341b6)
- fix(masking): record timestamps read through a card object (659a2b8)
- fix(masking): an int that is a card number, and a bytes body, are masked like text (88f7807)
- fix(masking): skip keys skip the fields ecsctx owns, not whole subtrees (030f3f4)
- fix(masking): masking never makes a log call raise, nor lets the unmasked record out (1aacff6)
- fix(masking): mask a dataclass or namedtuple by its fields; never crash on one (469df2c)
- fix(masking): a {name, value} pair masks the value by the name beside it (cc18026)
- fix(masking): a bare `name` is a thing's name under a thing; amounts leave Ottu's billing (8fde3ca)
- fix(masking): never mask a boolean; keep a card list's PAN truncated (888c487)
- fix(masking): a national identity number is PII by its key, in every service (42c177f)
- fix(masking): classify the credential key names that reached logs in clear (c387fb7)
- fix(masking): a CVV key names the value and fails closed; a key about one is readable (2a20463)
- fix(masking): a tracking id is not track data; cryptograms and 3DS values are SAD (dc98c67)

### Other
- Merge pull request #62 from ottuco/fix/pairs-containers-false-positives (fb8ccb9)
- docs: describe the engine as this round leaves it (d4bd055)
- perf(masking): keep this round's rules off the hot path (c609215)


## Unreleased

From a live log review of ottu_pg and Connect on 0.13.0. Every change below
has a test that fails on 0.13.0.

### Changed (breaking)

- A credential, CVV or SAD key holding a container is walked, not hashed or
  labelled as one unit: the value in the log is a mapping. A card-shaped
  object under a credential key (a number plus an expiry — ottu_pg's saved
  card under `token`) is walked as the card it is.
- A PAN-shaped value under a credential key (`card_token`, a numeric
  `api_key`) is `[SECRET-MASKED]`, no longer truncated: truncation showed ten
  of its digits.
- A key the service lists (`ECSCTX_MASK_SAFE_KEYS`) keeps a digits-only
  reference number of up to 14 digits readable; 15–19 digits always truncate.
- `display_name` left the core safe keys (under a customer it is theirs).

### Added

- `ecsctx.masking.key_field_type(key)` — the type the engine gives a key name,
  for a value outside a mapping (a URL segment).
- Key rules: national ids (`civil_id`, `passport`, `qid`, `iqama`, `cpr`, …) →
  `ssn` in every pack; payment cryptograms and 3DS values (`cryptogram`,
  `cavv`, `ucaf`) and chip data → `sad`; credential names that reached logs in
  clear (`HTTP_AUTHORIZATION`, `Cookie`, `passphrase`, `vpc_AccessCode`, …).
- Ottu preset: MPGS's CVV verdict codes, acquirer references and the fee
  breakdown keys.

### Fixed

- A customer's name in a `{name, value}` pair (Connect's `order_description`)
  shipped in clear while the field id was tokenized; a pair's value is now
  masked by its identifier, whatever the case of its keys (`VALUE` too). The
  same closed `{"name": "cvv", "value": "123"}`.
- `track_id` / "Track ID" read as track data; a CVV key missed `security-code`
  and masked MPGS's CVV verdict; a bare `name` under a thing (payment method,
  merchant) was a person; booleans were masked; a card list lost its PAN
  truncation; an int PAN and a bytes body shipped in clear.
- A dataclass's fields shipped in clear inside its repr (the Trandata leak).
- Masking could make a log call raise (namedtuple, cyclic or deeply nested
  input); it now never does, and a failure replaces the message whole.
- `service`/`log`/`trace` skipped their whole subtrees, so a caller's
  `service.card_number` shipped in clear.

### Known

- `_mask_json_text` still rescans a whole JSON text as prose, so the
  reference-number exemption does not reach a body logged as text.

## v0.13.0 (2026-09-22)

### Features
- feat(masking)!: walk a card object; stop masking names that name no person (04a0b4b)

### Other
- Merge pull request #61 from ottuco/fix/card-container-and-key-false-positives (3f88c22)
- refactor(masking): the key-classification order is written out, not implied (eeeef78)


## v0.12.0 (2026-09-22)

### Features
- feat(masking)!: a PAN outranks its key; expiry is readable; a card key shows what is not a PAN (a86feaf)
- feat(masking)!: brackets mean nothing survived; a truncated PAN is bare (18ddcd8)

### Fixes
- fix(masking): the standalone-CVV rule stops eating response codes (e7fff60)

### Other
- Merge pull request #60 from ottuco/fix/masking-false-positives (dc72224)
- Stop documenting expiry as a name no service may whitelist (d220b55)
- docs+test: correct the deferred example, pin how narrow the pass-through is (785ab8c)


## v0.10.0 (2026-09-19)

### Features
- Merge pull request #59 from ottuco/feat/bare-tokens (9754685)
- feat(masking)!: log tokens bare (ptok:v1:…); a null under a sensitive key stays null (24f876e)


## Unreleased

### Changed (breaking)

- A tokenized value is the bare token again, `ptok:v1:…`, as it was in 0.6.x
  (and as the README showed), not `[EMAIL-MASKED:ptok:v1:…]`. A `[LABEL]`
  stands only where no token can: PII tokenization not configured or failing,
  or a type that is never tokenized (`[CVV-MASKED]`, `[EXPIRY-MASKED]`,
  `[CARD-MASKED:411111******1111]`). A search on a token that spans this
  release matches the new documents exactly and the older ones by substring.
- A null under a sensitive key stays null. It used to become a masked
  marker (a token of the text "None"), which read as a value that was hidden.

### Added

- `ecsctx.contrib.ottu.masking.SAFE_KEYS` includes MPGS's
  `authorizationResponse` (the acquirer's processing and response codes).

### Changed (breaking)

- **Brackets now mean nothing survived.** A masked value that still carries
  something real is rendered bare: a token was already bare since 0.10.0, and a
  card's truncation now joins it — `450875******1019`, not
  `[CARD-MASKED:450875******1019]`. A bracketed label stands only where the
  value is gone: `[CVV-MASKED]`, `[EXPIRY-MASKED]`, and `[EMAIL-MASKED]` and
  friends where no token could be made. One rule for a reader: brackets mean
  there is nothing here, bare text means this IS the value.

  The wrapper was doing three jobs that now need the truncation's own shape —
  the BIN, a run of stars, the last four — to be recognised directly:
  `already_masked()`, `mask_card_value()`'s `_SINGLE_MARKER`, and
  `_text_has_card_context()`. The last one matters most: rule 15 runs before
  rule 17, so by the time the CVV rule looks at a string the PAN is already
  truncated, and the truncation is the only card context left. Without it a
  CVV sitting beside a masked PAN would silently stop being masked.

  `already_masked()` is now an anchored `fullmatch` rather than a substring
  test, so a marker-shaped fragment can no longer vouch for the value around
  it. Values masked by an earlier release — `[CARD-MASKED:…]`,
  `[EMAIL-MASKED:ptok:…]` — are still recognised, so re-masking an old
  document is still a noop.

- **A PAN is truncated whatever key it arrived under**, instead of being
  tokenized when the key says PII. Customers mistype the card number into the
  name box, and the key used to win: with a keyset configured, a record holding
  the PAN in a card key and in a name key carried a truncation AND a keyed hash
  of the same PAN. That is the combination PCI DSS FAQ 1117 warns about, and
  the one `mask_card_value` already refuses by never tokenizing — the card path
  honoured the rule and every other path ignored it, so a key ecsctx recognised
  as PII came off worse than one it did not recognise at all. Now covers name,
  email, phone, address, generic, secret and the rest; gated on the `pci` pack,
  like every other card rule, so a service that never opted in is unaffected.

- **Expiry is no longer masked.** It is Cardholder Data, not Sensitive
  Authentication Data: PCI DSS forbids storing SAD (CVV, full track, PIN) at
  all, but permits storing expiry with protection, and only the PAN must be
  rendered unreadable. `[EXPIRY-MASKED]` sat above the requirement and cost the
  one thing worth reading — an expired-card decline. Expiry keys are no longer
  classified, and are listed in `SAFE_KEYS` so they also escape a PII
  container's sweep; their values are still content-scanned, so a PAN pasted
  into an expiry field is still truncated. CVV is unchanged.

- **A card key shows what is not a PAN.** `{"card_number": "not-a-number"}` was
  `[CARD-MASKED]`, and so were a gateway token, a scheme name and an error
  string — identical, in the one field someone debugging a decline looks at.
  Fewer than 12 digits cannot be a PAN (the shortest issued), so the value
  reads through. Twelve or more is content-scanned rather than collapsed, so an
  embedded PAN is truncated with its context intact
  (`card 4508 7500 0000 1019 visa` → `card 450875******1019 visa`); if the scan
  finds nothing to truncate the value is still refused, because
  `4508750**0001019` keeps 14 of 16 digits with no run for the rule to catch.

- An **empty value stays empty** instead of becoming its type's label.
  `{"address": ""}` used to render `[ADDRESS-MASKED]`, which reads as though
  something had been hidden; nothing was there. Same reasoning as a null
  staying null. The CVV rules no longer route through `mask_by_field_type("")`
  to spell their label, since that made them depend on this.

### Fixed

- The credential text rules no longer read an existing token as a credential
  value (`token=ptok:v1:…`), so masking masked text again changes nothing.
- The standalone-CVV rule — a bare 3-4 digit group, the loosest rule in the
  file — no longer destroys three- and four-digit data that is not a CVV. It
  fired on any such string whatever key it sat under, so a payment gateway's
  own logs rendered every PSP response code (`"000"`, `"101"`, `"199"`), every
  `Content-Length`, and every HTTP status inside a message as `[CVV-MASKED]`:
  the one field an operator needs to read a decline. Two fences now apply.

  It never runs over a **whole scalar field value**, only over prose. A field
  value has a key to be judged by, and the key rules have already had their
  say; this is the same reasoning that has always exempted ints and floats
  (`{"code": 400}` was safe, `{"code": "400"}` was not — and a PSP sends
  JSON, where codes are strings).

  In prose it runs only when the text carries **card context** — a card-shaped
  digit run, or the word card/pan/cardholder/credit/cvv/cvc/security. A CVV is
  worth nothing without the PAN it belongs to, and a 3-4 digit group with no
  card anywhere near it is a status, a count or an amount. A keyword-anchored
  CVV (`cvv=123`, `"cvv": "123"`, `the cvv is 123`) is unaffected: rules 4, 5
  and 9 match it whatever else the text holds.

  Two cases of the documented space-cascade bug are fixed by this and have
  been promoted out of its strict-xfail list.

### Known

- A 12-19 digit string still masks as a card under any key, so an epoch
  millisecond timestamp sent as a string (`"1727394279301"`) renders as
  `*********9301`. Narrowing it means gating the rule on a card
  IIN, which changes a deliberate fail-safe contract ("any 12-19 digit run is
  a card"). A Luhn check is **not** the fix: PANs in live test use exist that
  fail Luhn (`4508750000001019`), while epoch timestamps exist that pass it
  (`1727394280470`) — it would unmask a real card and keep a timestamp masked.

## v0.9.0 (2026-09-19)

### Features
- feat(masking)!: a service lists its own safe keys; Ottu's names leave the core list (4515b68)

### Fixes
- Merge pull request #58 from ottuco/fix/json-body-masking (1251b2e)
- fix(masking): refuse every card/expiry safe key and names ending in a CVV or credential word (e538bbe)
- fix(masking): mask JSON text by key, keep masked JSON valid, drop key false positives (3c5834b)


## Unreleased

### Added

- `ECSCTX_MASK_SAFE_KEYS` (Django setting or env var) and
  `ecsctx.masking.configure_masking_safe_keys()`: key names a service's own
  payloads use for things that are not PII, which the key rules then leave
  alone. It extends the built-in whitelist and cannot shrink it; a listed key's
  value is still content-scanned. A card or expiry key, or a name ending in a
  CVV or credential word (`card_number`, `pan_no`, `expiry_month`, `card_cvv`,
  `db_password`, `oauth_token`, …), names the value itself and is refused: the
  call raises, and from the setting or env var it stays masked, warns once and
  fails the Django boot check. A flag or status about one (`cvv_required`,
  `tokenization_status`) can be listed.
- `ecsctx.contrib.ottu.masking.SAFE_KEYS`: Ottu's names for that setting
  (`pg_name`, `cvv_required`, `cvv_required_for_card_payment`, and the six
  names below). A service opts in with
  `ECSCTX_MASK_SAFE_KEYS = [*SAFE_KEYS, ...]`; nothing installs it implicitly.

### Changed

- The built-in whitelist holds only names that mean the same in every service.
  `gateway_name`, `vendor_name`, `bank_name`, `install_name`,
  `installation_name` and `tokenization_status` moved to
  `ecsctx.contrib.ottu.masking.SAFE_KEYS`: a service that logs them lists them,
  or they are masked.

### Fixed

- A JSON object or list logged as a string is masked by its keys, as the same
  data logged as a dict is. A PSP callback's raw body used to get the content
  rules only, so a cardholder name or an expiry date inside it (`nameOnCard`,
  `name_on_card`, `expiry`, `expiry_month`) reached the index in clear. Strings
  up to `JSON_PARSE_LIMIT` (64 KiB) are parsed and walked with the key rules;
  a card or token object is masked as one unit, as in a dict; the text is
  re-serialised only when a key rule changed something, and the content rules
  still run once on the result.
- Masked text stays valid JSON. A quoted key with a bare `null`, `true` or
  `false` (or a repr's `None`, `True`, `False`) is left alone, where
  `"public_key": null` became `"public_key": [SECRET-MASKED]`; a masked
  number after a quoted key gets its marker in quotes (credential and CVV text
  rules). Unquoted `token=…` / `cvv: …` text is unchanged.
- `tel` is matched as a word of the key, so `hotel` and `hostel` are no longer
  phone numbers (`tel`, `tel_no`, `telNo`, `tel2` still are).
  `Sec-Ch-Ua-Mobile`, a standard client-hint header, is whitelisted.

## v0.8.3 (2026-09-19)

### Fixes
- fix(ottu)!: drop pg.payload_decrypted, a second name for crypto.payload_decrypted (b666cf0)

### Other
- Merge pull request #57 from ottuco/fix/drop-pg-payload-decrypted (0500198)


## Unreleased

### Removed

- `pg.payload_decrypted` (added in 0.8.2). The catalogue already had
  `crypto.payload_decrypted` for the same thing — an encrypted payload
  decrypted, `labels.cipher` naming the scheme, error when it failed — so the
  second name would have split every query that counts it. Log the KNET-family
  `trandata` failure as `crypto.payload_decrypted`.

### Added

- A catalogue test that fails when two domains name the same thing: an action's
  `<subject>_<verb>` may repeat across domains only for the boundary events
  (`request_sent`, `response_received`, `request_failed`, `request_rejected`).

## v0.8.2 (2026-09-18)

### Features
- feat(ottu): pg.payload_decrypted; mask a pre-serialised request body (c8e569a)

### Other
- Merge pull request #56 from ottuco/feat/pg-payload-decrypted (4e1a400)


## Unreleased

### Added

- `pg.payload_decrypted` (`PG_PAYLOAD_DECRYPTED`): a KNET-family PSP's
  encrypted `trandata` was decrypted, logged on failure at error. Connect and
  ottu_pg both decrypt it (ottu_pg's local `benefit.decryption_failed` is this
  event), so it is shared.

### Fixed

- `loggable_request_body` masks a body the caller serialised itself
  (`data=json.dumps(payload)`) by key, as it does a dict. A string body skipped
  key masking entirely, so only the eight OAuth-shaped body keys were redacted.
- `authkey` (Telr's merchant credential) joins the default secret body keys.

## v0.8.1 (2026-09-18)

### Features
- Merge pull request #55 from ottuco/feature/auth-reasons (c0ef34b)
- feat(ottu): auth reasons Connect logs — login refusals, revocations, token failures (d96a8b2)


## Unreleased

### Added

- Reasons Connect logs on shared auth events, declared in the catalogue so
  every service uses the same values: `AuthRejection.ACCOUNT_LOCKED` and
  `INVALID_CREDENTIALS` (login refusals), `TokenRevocation.USER_DEACTIVATED` on
  `auth.token_revoked`, and `TokenIssueFailure.CONNECTION_FAILED` / `REJECTED`
  on `auth.token_issued`.

## v0.8.0 (2026-09-18)

### Features
- Merge pull request #54 from ottuco/feature/catalogue-governance (8dda9d0)
- Merge pull request #53 from ottuco/feature/event-values (37ee704)
- feat(ottu): one vocabulary, enforced: naming rules, descriptions, docs page (70609ce)
- feat(events): Outcome and Reason; catalogue reasons are objects (1ac952f)

### Fixes
- fix(ottu): signature_verification_skipped requires the reason it promises (132caa0)
- fix(events): a reason needs a declared set; say why specs equal by value (f723e1e)
- fix(masking): keep exceptions, honour the exemption setting, walk PII containers (e57d2de)

### Other
- Merge pull request #52 from ottuco/refactor/remove-emit (9097484)
- Merge branch 'feature/event-values' into feature/catalogue-governance (909c012)
- Merge branch 'refactor/remove-emit' into feature/event-values (147dcb1)
- Merge remote-tracking branch 'origin/main' into refactor/remove-emit (b714bfb)
- Merge pull request #51 from ottuco/fix/masking-074 (f373b32)
- Merge branch 'feature/event-values' into feature/catalogue-governance (009cfd8)
- refactor(django): drop the exemption-setting bridge; one resolution path (34e84c3)
- Merge branch 'feature/event-values' into feature/catalogue-governance (e5b86d8)
- Merge branch 'refactor/remove-emit' into feature/event-values (5c1788d)
- docs: one blank line before v0.7.3 in the changelog (dbdf58c)
- refactor(events)!: remove emit(); one way to log an event (dd10c12)


## Unreleased

### Added

- **One vocabulary, enforced.**
  - `ecsctx.contrib.ottu.rules` holds the naming rules every Ottu event follows,
    shared or local: `<domain>.<subject>_<verb>`, a past-tense verb from
    `VERBS`, no known synonym (`SYNONYMS`: `inited` → `created`, `queued` →
    `enqueued`, …), no negation, and a description.
  - The catalogue's tests hold it to these rules. `register_ottu(local=...)`
    checks a service's own events at startup and raises `EventRuleError`
    listing every problem, before anything is registered.
- `EventSpec.description`: when to log the event and what success and failure
  mean. Every catalogue event has one.
- `docs/events.md`, generated from the catalogue with
  `python -m ecsctx.contrib.ottu.render_docs`, lists every shared event with its
  import, description, levels, reasons and fields. A test fails if it is stale.
- `docs/rules/log-events.md`: the rule each service copies into its
  `.claude/rules/`, so review catches what a rule cannot.
- `.github/CODEOWNERS` covers the catalogue.
- `ApiRejection.MISSING_HEADER` and `ApiRejection.INVALID_HEADER`: a header gate
  that refuses a request before the view reports `api.request_rejected`
  instead of an action of its own.

### Changed (breaking)

- `register_ottu(local=...)` refuses local events that break the naming rules.
- `pg.signature_verification_skipped` requires `event.reason`, as the #159487
  catalogue does; its description already promised one. It has no reason set
  yet, so it takes none until a service declares one.
- `registry.RESERVED_PREFIXES` covers every ECS field set (`file`, `host`,
  `network`, `process`, `source`, `destination`, `client`, `server`, …), not
  only eleven of them. A domain named after a field set reads, in every query,
  like the fields a document already carries.

- **`Outcome` and `Reason`** (`ecsctx.events`): outcomes and reasons are
  objects a call site imports, not strings it types. `Outcome` is ECS's closed
  set; an event's reasons are a `Reason` subclass passed as
  `EventSpec(reasons=...)`. `.ecs()` still accepts declared plain strings,
  rejects a member of another event's set even when its value matches, and
  always writes the plain value, so documents are unchanged.
- **Breaking:** `.ecs(reason=...)` on an event that declares no reasons raises.
  It used to accept any string, so a free-text reason reached the index
  unchecked. Declare the event's `Reason` class first. Eight catalogue events
  require `event.reason` but have no set yet, because no service logs one; the
  first that does adds the class to the catalogue.
- Every catalogue reason set is a `Reason` subclass next to its event:
  `OutboundFailure` (net/pg `request_failed`; `OUTBOUND_FAILURE_REASONS` is
  `tuple(OutboundFailure)`), `ApiRejection`, `AuthRejection`,
  `CacheWriteFailure`, `EligibilityRejection`, `OperationFailure`,
  `CheckoutFailure`, `CallbackRejection`, `CallbackSkip`, `TaskCancellation`,
  `WebhookFailure`, `WebhookSkip`.

### Removed (breaking)

- **`emit()` and everything built on it:** `emit`, `emit_pair`, `Call`,
  `UnknownEventError` (`ecsctx.events.emit`), and `route` / `FIELD_PATHS`
  (`ecsctx.events.fields`). There is one way to log an event — the service's
  own logger with the spec's payload:

  ```python
  # before
  emit(logger, PG_REQUEST_FAILED, "PSP rejected the call",
       outcome="failure", reason="http_client_error", status_code=400)
  # after
  logger.warning(
      "PSP rejected the call",
      ecs_event=PG_REQUEST_FAILED.ecs(outcome="failure", reason="http_client_error"),
      http={"response": {"status_code": 400}},
  )
  ```

  `emit()` chose the level out of sight of the call site, placed fields by
  kwarg name (an unknown or misspelled one silently became a `labels.*`
  value), and accepted an event as a string. `EventSpec.level` /
  `failure_level` stay as the declared intent; the call site picks the level.
  `Timer` and `timed()` stay: pass `duration_ns=t.ns` to `.ecs()`.
  A service still calling `emit` must convert before upgrading.

### Fixes

Found adopting 0.7.x in ottu_backend; each was present since 0.7.0.

- **Exceptions survive masking.** `exc_info` and `stack_info` are never masked.
  An exception passed as `exc_info=exc` (as the middleware's
  `unhandled_exception` line does) was turned into strings, so with
  `SentryIntegration` the line lost `error.stack_trace` and Sentry received no
  exception. The rendered `error.*` fields are masked as before.
- **`ECSCTX_MASK_EXEMPT_PATHS` always applies.** The exemptions now read the
  Django setting themselves (explicit call → setting → `PII_MASK_EXEMPT_PATHS`).
  Before, if anything masked before the first structlog line — the handler
  filter on a stdlib record — the env var was loaded and the setting ignored.
  The Django processor's bridge for the setting (`_auto_configure_masking`) is
  gone: one resolution path, not two that happened to agree.
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

