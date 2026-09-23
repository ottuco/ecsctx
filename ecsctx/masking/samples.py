"""Masking sample tables, shipped so a project can run them against its own logging.

Each case is (label, sample, expected). A string sample is logged as the event
message; a dict sample is logged as one field. MaskingTestsMixin runs them
through a project's real handlers, and ecsctx's own suite runs that mixin with
every pack on, so these tables are ecsctx's filter tests too.

Expected values are the [LABEL] form a project without PII tokenization emits.
Where tokenization is configured, a tokenizable value is logged as a bare
ptok:v1:… token instead; the test helper treats the two as equal.

Content rules come in packs: "default" is always on, "pci" and
"financial_ids" are opt-in (ecsctx.masking.config). case_pack() says which pack
a case needs, so a project is only held to the packs it has turned on.
"""


class _FakeCard:
    """Stand-in for a model whose ``__repr__`` embeds sensitive data (PAN/token)."""

    def __repr__(self) -> str:
        return "<Card(VISA, 512345******0008, 9584184138614802)>"


def _pem(kind: str, body: str) -> str:
    """Build a PEM block of the given kind, e.g. 'RSA PRIVATE KEY'."""
    return f"-----BEGIN {kind}-----\n{body}\n-----END {kind}-----"


_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.abc123def456ghi"
_HEX = "1a2b3c4d5e6f7a8b9c0d1e2f"


# ---------------------------------------------------------------------------
# PEM key blocks. Mask ANY type (PRIVATE / RSA PRIVATE / EC PRIVATE /
# PUBLIC / ...) — enumerating variants is a losing game, so the filter
# matches the whole "-----BEGIN ... KEY----- ... -----END ... KEY-----"
# envelope. Public keys aren't secret, but masking them too is the safe
# direction and future-proofs new key types.
# ---------------------------------------------------------------------------
PEM_MASKED_CASES = [
    ("pem-private-key", _pem("PRIVATE KEY", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"), "[PEM-KEY-MASKED]"),
    ("pem-rsa-private-key", _pem("RSA PRIVATE KEY", "MIIEpAIBAAKCAQEA0abcDEF"), "[PEM-KEY-MASKED]"),
    ("pem-ec-private-key", _pem("EC PRIVATE KEY", "MHcCAQEEIABxYZec012private"), "[PEM-KEY-MASKED]"),
    ("pem-public-key", _pem("PUBLIC KEY", "MIIBIjANBgkqhkiG9w0pubKEY"), "[PEM-KEY-MASKED]"),
    ("pem-rsa-public-key", _pem("RSA PUBLIC KEY", "MEgCQQCrsaPUBLICkeyXYZ"), "[PEM-KEY-MASKED]"),
]


# ---------------------------------------------------------------------------
# Credential keywords (_CRED_KEYWORD): bearer/basic/api_key/token/secret/
# password/*_key compounds/credentials, across all three separator forms
# (quoted key, ":"/"=", bare space) and every realistic shape a header/token
# lands in — bare value, full "Authorization:" line, lowercase scheme,
# interpolated into a message, nested inside a logged `headers` dict, and
# short/single-char/single-digit values. Exact match, not "secret not in
# output" — that weaker check can't tell "masked correctly" from "masked
# into garbage".
# ---------------------------------------------------------------------------
CREDENTIAL_MASKED_CASES = [
    # quotes
    ("cred-single-quoted-colon", "'token': 'abcd1234'", "'token': '[SECRET-MASKED]'"),
    ("cred-single-quoted-colon-tight", "'token':'abcd1234'", "'token':'[SECRET-MASKED]'"),
    ("cred-double-quoted-colon", '"token": "abcd1234"', '"token": "[SECRET-MASKED]"'),
    ("cred-double-quoted-colon-tight", '"token":"abcd1234"', '"token":"[SECRET-MASKED]"'),
    # colons
    ("cred-colon", "token: abcd1234", "token: [SECRET-MASKED]"),
    ("cred-colon-tight", "token:abcd1234", "token:[SECRET-MASKED]"),
    # equals
    ("cred-equals", "token= abcd1234", "token= [SECRET-MASKED]"),
    ("cred-equals-tight", "token=abcd1234", "token=[SECRET-MASKED]"),
    # shorts — no 8-char floor
    ("cred-equals-single-digit", "token=1", "token=[SECRET-MASKED]"),
    ("cred-equals-single-char", "token=a", "token=[SECRET-MASKED]"),
    ("cred-colon-single-digit", "token: 1", "token: [SECRET-MASKED]"),
    ("cred-colon-single-char", "token: a", "token: [SECRET-MASKED]"),
    # HEX & JWT values
    ("cred-colon-hex", f"token:{_HEX}", "token:[SECRET-MASKED]"),
    ("cred-equals-hex", f"token={_HEX}", "token=[SECRET-MASKED]"),
    ("cred-colon-jwt", f"token:{_JWT}", "token:[SECRET-MASKED]"),
    ("cred-equals-jwt", f"token={_JWT}", "token=[SECRET-MASKED]"),
    # bare space (no colon, no equals, no quotes)
    ("cred-space-hex", f"token {_HEX}", "token [SECRET-MASKED]"),
    ("cred-space-jwt", f"token {_JWT}", "token [SECRET-MASKED]"),
    ("cred-space-8chars-4digits", "token abcd1234", "token [SECRET-MASKED]"),
    # in a sentence
    ("cred-short-token-equals-in-sentence", "message token=1", "message token=[SECRET-MASKED]"),
    # (token/secret/password/passwd) prefixes-on-token
    ("cred-token", "token abcd1234", "token [SECRET-MASKED]"),
    ("cred-anyword_token", "anyword_token abcd1234", "anyword_token [SECRET-MASKED]"),
    ("cred-any_word_token", "any_word_token abcd1234", "any_word_token [SECRET-MASKED]"),
    ("cred-any-word_token", "any-word_token abcd1234", "any-word_token [SECRET-MASKED]"),
    ("cred-any-word-token", "any-word-token abcd1234", "any-word-token [SECRET-MASKED]"),
    ("cred-any_1-word_2-token", "any_1-word_2-token abcd1234", "any_1-word_2-token [SECRET-MASKED]"),
    # (token/secret/password/passwd) keywords
    ("cred-secret", "secret abcd1234", "secret [SECRET-MASKED]"),
    ("cred-any_1-word_2-secret", "any_1-word_2-secret abcd1234", "any_1-word_2-secret [SECRET-MASKED]"),
    ("cred-password", "password abcd1234", "password [SECRET-MASKED]"),
    ("cred-any_1-word_2-password", "any_1-word_2-password abcd1234", "any_1-word_2-password [SECRET-MASKED]"),
    ("cred-passwd", "passwd abcd1234", "passwd [SECRET-MASKED]"),
    ("cred-any_1-word_2-passwd", "any_1-word_2-passwd abcd1234", "any_1-word_2-passwd [SECRET-MASKED]"),
    # auth schemes
    ("cred-bearer", "bearer abcd1234", "bearer [SECRET-MASKED]"),
    ("cred-basic", "basic abcd1234", "basic [SECRET-MASKED]"),
    ("cred-digest", "digest abcd1234", "digest [SECRET-MASKED]"),
    ("cred-credential", "credential abcd1234", "credential [SECRET-MASKED]"),
    ("cred-credentials", "credentials abcd1234", "credentials [SECRET-MASKED]"),
    # auth keywords (both spellings, both separators)
    ("cred-authorization", "authorization abcd1234", "authorization [SECRET-MASKED]"),
    ("cred-authorization_header", "authorization_header abcd1234", "authorization_header [SECRET-MASKED]"),
    ("cred-authorization-header", "authorization-header abcd1234", "authorization-header [SECRET-MASKED]"),
    ("cred-authorisation", "authorisation abcd1234", "authorisation [SECRET-MASKED]"),
    ("cred-authorisation_header", "authorisation_header abcd1234", "authorisation_header [SECRET-MASKED]"),
    ("cred-authorisation-header", "authorisation-header abcd1234", "authorisation-header [SECRET-MASKED]"),
    # key examples with api prefix
    ("cred-apikey", "apikey abcd1234", "apikey [SECRET-MASKED]"),
    ("cred-api_key", "api_key abcd1234", "api_key [SECRET-MASKED]"),
    ("cred-api-key", "api-key abcd1234", "api-key [SECRET-MASKED]"),
    # sensitive *_key compounds
    ("cred-secret-key", "secret-key abcd1234", "secret-key [SECRET-MASKED]"),
    ("cred-private-key", "private-key abcd1234", "private-key [SECRET-MASKED]"),
    ("cred-public-key", "public-key abcd1234", "public-key [SECRET-MASKED]"),
    ("cred-encryption-key", "encryption-key abcd1234", "encryption-key [SECRET-MASKED]"),
    ("cred-decryption-key", "decryption-key abcd1234", "decryption-key [SECRET-MASKED]"),
    ("cred-signing-key", "signing-key abcd1234", "signing-key [SECRET-MASKED]"),
    ("cred-access-key", "access-key abcd1234", "access-key [SECRET-MASKED]"),
    ("cred-master-key", "master-key abcd1234", "master-key [SECRET-MASKED]"),
    ("cred-root-key", "root-key abcd1234", "root-key [SECRET-MASKED]"),
    ("cred-session-key", "session-key abcd1234", "session-key [SECRET-MASKED]"),
    # 16-digit numeric secret, inside the card rules' 12-19 digit range —
    # the credential rule must claim it before the card rule sees it.
    ("cred-numeric-secret-in-card-digit-range", "secret_key=1234567890123456", "secret_key=[SECRET-MASKED]"),
    # Authorization header, every realistic shape
    ("auth-header-line-single-quotes", f"'Authorization': 'Bearer {_JWT}'", "'Authorization': '[SECRET-MASKED]'"),
    ("auth-header-line-double-quotes", f'"Authorization": "Bearer {_JWT}"', '"Authorization": "[SECRET-MASKED]"'),
    ("auth-header-line-colon", f"Authorization: Bearer {_JWT}", "Authorization: [SECRET-MASKED] [JWT-MASKED]"),
    ("auth-header-line-equal", f"Authorization= Bearer {_JWT}", "Authorization= [SECRET-MASKED] [JWT-MASKED]"),
    ("auth-header-line-space", f"Authorization Bearer {_JWT}", "Authorization Bearer [SECRET-MASKED]"),
    ("auth-header-quoted-kv", f'{{"Authorization": "{_HEX}"}}', '{"Authorization": "[SECRET-MASKED]"}'),
    ("auth-header-quoted-kv-in-sentence", f'Here is {{"Authorization": "{_HEX}"}}', 'Here is {"Authorization": "[SECRET-MASKED]"}'),
    ("auth-dict-value-with-spaces", f'{{"Authorization": "Bearer {_HEX} more"}}', '{"Authorization": "[SECRET-MASKED]"}'),
    ("authorization-raw-colon", f"Authorization: {_HEX}abcd", "Authorization: [SECRET-MASKED]"),
    ("authorisation-raw-dict", f'{{"Authorisation": "{_HEX}abcd"}}', '{"Authorisation": "[SECRET-MASKED]"}'),
    (
        "auth-inside-headers-dict-apikey",
        {"headers": {"Authorization": f"API-Key {_HEX}"}},
        {"headers": {"Authorization": "[SECRET-MASKED]"}},
    ),
    (
        "auth-inside-headers-dict-bearer",
        {"headers": {"Authorization": f"Bearer {_JWT}"}},
        {"headers": {"Authorization": "[SECRET-MASKED]"}},
    ),
    (
        "auth-inside-headers-dict-token",
        {"headers": {"Authorization": "token abcd 1234 anything"}},
        {"headers": {"Authorization": "[SECRET-MASKED]"}},
    ),
    (
        "auth-interpolated-in-message",
        f"Authentication failed with key 'API-Key {_HEX}'",
        "Authentication failed with key 'API-Key [SECRET-MASKED]'",
    ),
    # common OAuth/API field names
    ("access_token-kv", "access_token=abcd1234efgh5678", "access_token=[SECRET-MASKED]"),
    ("refresh_token-kv", "refresh_token=abcd1234efgh5678", "refresh_token=[SECRET-MASKED]"),
    ("client_secret-kv", "client_secret=sk_live_abcd1234ef", "client_secret=[SECRET-MASKED]"),
    ("private_key-kv", "private_key=abcd1234efgh5678", "private_key=[SECRET-MASKED]"),
    ("secret_key-kv", "secret_key=abcd1234efgh5678", "secret_key=[SECRET-MASKED]"),
    ("auth-basic-equals", f"basic= {_HEX}", "basic= [SECRET-MASKED]"),
    ("auth-api-key-value", f"API-Key {_HEX}", "API-Key [SECRET-MASKED]"),
    ("auth-basic-value", "Basic dXNlcjpwYXNzd29yZA==", "Basic [SECRET-MASKED]"),
    # A quoted key whose value is a bare literal: text that is JSON (or a
    # Python repr) must stay parseable, and a null/boolean holds no secret.
    ("cred-quoted-key-json-null", 'body {"public_key": null, "a": 1}', 'body {"public_key": null, "a": 1}'),
    ("cred-quoted-key-json-bool", 'body {"session_key": true}', 'body {"session_key": true}'),
    ("cred-quoted-key-python-none", "body {'public_key': None}", "body {'public_key': None}"),
    (
        "cred-quoted-key-number-stays-quoted",
        'body {"session_key": 12345}',
        'body {"session_key": "[SECRET-MASKED]"}',
    ),
    (
        "cred-single-quoted-key-number-stays-quoted",
        "body {'api_key': 12345}",
        "body {'api_key': '[SECRET-MASKED]'}",
    ),
]


# ---------------------------------------------------------------------------
# CVV/CVC/security-code rules (_CVV_KEYWORD): quoted key, ":"/"=", and mixed
# casing, same 3-rule shape as the credential rules above. Never tokenized —
# PCI forbids storing a CVV in any form, so [CVV-MASKED] is always final.
# ---------------------------------------------------------------------------
CVV_KEYWORD_CASES = [
    ("cvv-single-quoted-colon", "'cvv': '123'", "'cvv': '[CVV-MASKED]'"),
    ("cvv-single-quoted-colon-tight-mixed-case", "'Cvv':'123'", "'Cvv':'[CVV-MASKED]'"),
    ("cvv-double-quoted-colon-mixed-case", '"cVv": "123"', '"cVv": "[CVV-MASKED]"'),
    ("cvv-double-quoted-colon-tight-mixed-case", '"cvV":"123"', '"cvV":"[CVV-MASKED]"'),
    ("cvv-unquoted-colon-mixed-case", "CVv: 1234", "CVv: [CVV-MASKED]"),
    ("cvv-unquoted-colon-tight-mixed-case", "cVV:1234", "cVV:[CVV-MASKED]"),
    ("cvv-unquoted-equals-mixed-case", "CvV= 1234", "CvV= [CVV-MASKED]"),
    ("cvv-unquoted-equals-tight-mixed-case", "CVV=1234", "CVV=[CVV-MASKED]"),
    ("cvv-in-sentence", "Here cvv=100 is submitted", "Here cvv=[CVV-MASKED] is submitted"),
    ("cvc-single-quoted-colon", "'cvc': '123'", "'cvc': '[CVV-MASKED]'"),
    ("cvc-single-quoted-colon-uppercase", "'CVC': '1234'", "'CVC': '[CVV-MASKED]'"),
    # real dicts, cvv key nested one level deep — not just a string sample.
    ("cvv-dict-obj", {"processed_data": {"cvv": "100"}}, {"processed_data": {"cvv": "[CVV-MASKED]"}}),
    (
        "cvv-dict-obj-long",
        {"processed_data": {"cvv": "not a cvv shape 123456789"}},
        {"processed_data": {"cvv": "[CVV-MASKED]"}},
    ),
    # same shape, but as a JSON string, not a real dict — the quoted-key rule
    # must still find it nested inside the braces.
    (
        "cvv-quoted-inside-json-string",
        '{"processed_data": {"cvv": "100"}}',
        '{"processed_data": {"cvv": "[CVV-MASKED]"}}',
    ),
    # A quoted key with a numeric value: the marker is quoted so JSON text
    # stays parseable.
    ("cvv-quoted-key-number-stays-quoted", 'data {"cvv": 123}', 'data {"cvv": "[CVV-MASKED]"}'),
]


# ---------------------------------------------------------------------------
# Payment/transaction/auth id — bare, quoted-key, and dict forms.
# ---------------------------------------------------------------------------
PAYMENT_ID_QUOTE_CASES = [
    ("payment_id-bare-colon", "payment_id: abc12345", "payment_id: [PAYMENT-ID-MASKED]"),
    ("payment_id-bare-equals", "payment_id= abc12345", "payment_id= [PAYMENT-ID-MASKED]"),
    ("payment_id-bare-space", "payment_id abc12345", "payment_id [PAYMENT-ID-MASKED]"),
    ("payment-id-bare-colon", "payment-id: abc12345", "payment-id: [PAYMENT-ID-MASKED]"),
    ("payment-id-bare-equals", "payment-id= abc12345", "payment-id= [PAYMENT-ID-MASKED]"),
    ("payment-id-bare-space", "payment-id abc12345", "payment-id [PAYMENT-ID-MASKED]"),
    ("payment_id-single-quoted-colon", "'payment_id': 'abc12345'", "'payment_id': '[PAYMENT-ID-MASKED]'"),
    ("payment-id-single-quoted-colon", "'payment-id': 'abc12345'", "'payment-id': '[PAYMENT-ID-MASKED]'"),
    ("payment_id-single-quoted-colon-tight", "'payment_id':'abc12345'", "'payment_id':'[PAYMENT-ID-MASKED]'"),
    ("payment-id-single-quoted-colon-tight", "'payment-id':'abc12345'", "'payment-id':'[PAYMENT-ID-MASKED]'"),
    ("payment_id-double-quoted-colon", '"payment_id": "abc12345"', '"payment_id": "[PAYMENT-ID-MASKED]"'),
    ("payment-id-double-quoted-colon", '"payment-id": "abc12345"', '"payment-id": "[PAYMENT-ID-MASKED]"'),
    ("payment_id-double-quoted-colon-tight", '"payment_id":"abc12345"', '"payment_id":"[PAYMENT-ID-MASKED]"'),
    ("payment-id-double-quoted-colon-tight", '"payment-id":"abc12345"', '"payment-id":"[PAYMENT-ID-MASKED]"'),
    ("transaction-id-quoted-alnum-value", "'transaction_id': 'jbzzTT577'", "'transaction_id': '[PAYMENT-ID-MASKED]'"),
    ("auth-id-quoted-numeric-value", "'auth_id': '016153570198200'", "'auth_id': '[PAYMENT-ID-MASKED]'"),
    ("payment-id-numeric-in-card-digit-range", "payment_id: 1234567890123456 done", "payment_id: [PAYMENT-ID-MASKED] done"),
    ("payment-id-equals-numeric-in-card-digit-range", "payment_id= 9876543210987654 done", "payment_id= [PAYMENT-ID-MASKED] done"),
    ("transaction_id-bare-colon", "transaction_id: abcd1234", "transaction_id: [PAYMENT-ID-MASKED]"),
    ("transaction-id-bare-colon", "transaction-id: abcd1234", "transaction-id: [PAYMENT-ID-MASKED]"),
    ("auth_id-bare-colon", "auth_id: abcd1234", "auth_id: [PAYMENT-ID-MASKED]"),
    ("auth-id-bare-colon", "auth-id: abcd1234", "auth-id: [PAYMENT-ID-MASKED]"),
    (
        "payment-id-dict-obj",
        {"processed_data": {"payment_id": "abc12345"}},
        {"processed_data": {"payment_id": "[PAYMENT-ID-MASKED]"}},
    ),
    (
        "payment-id-dict-obj-long",
        {"processed_data": {"payment_id": "not a cvv shape abc12345"}},
        {"processed_data": {"payment_id": "[PAYMENT-ID-MASKED]"}},
    ),
    (
        "payment-id-quoted-inside-json-string",
        '{"processed_data": {"payment_id": "abc12345"}}',
        '{"processed_data": {"payment_id": "[PAYMENT-ID-MASKED]"}}',
    ),
]


# ---------------------------------------------------------------------------
# IBAN (bank account numbers). Must be masked before the card-number rules
# run: several real IBAN formats have a long, letter-free digit run (check
# digits + BBAN) that falls inside the card rules' 12-19-digit body and
# would otherwise get caught as if it were a PAN.
# ---------------------------------------------------------------------------
IBAN_MASKED_CASES = [
    ("iban", "account GB33BUKB20201555555555 credited", "account [IBAN-MASKED] credited"),
    # BE/FR: not Gulf-region at all; BH/QA: Gulf-region codes that still
    # collide despite embedded letters elsewhere in the BBAN.
    ("iban-be-digit-run-collision", "acct BE68539007547034 debited", "acct [IBAN-MASKED] debited"),
    ("iban-fr-digit-run-collision", "acct FR1420041010050500013M02606 debited", "acct [IBAN-MASKED] debited"),
    ("iban-bh-digit-run-collision", "acct BH67BMAG00001299123456 debited", "acct [IBAN-MASKED] debited"),
    ("iban-qa-digit-run-collision", "acct QA58DOHB00001234567890ABCDEFG debited", "acct [IBAN-MASKED] debited"),
    # Synthetic IBANs pinned to exact digit-run lengths, covering the card
    # rule's collision window directly (_CARD_BODY matches a 12-19-digit
    # run). 13 (2 check digits + 11 BBAN) is the shortest constructible case.
    ("iban-digit-run-13-just-over-card-floor", "acct GB1212345678901 debited", "acct [IBAN-MASKED] debited"),
    ("iban-digit-run-16-classic-pan-length", "acct GB3412345678901234 debited", "acct [IBAN-MASKED] debited"),
    ("iban-digit-run-19-top-of-card-range", "acct GB5612345678901234567 debited", "acct [IBAN-MASKED] debited"),
    ("iban-digit-run-20-past-card-range", "acct GB78123456789012345678 debited", "acct [IBAN-MASKED] debited"),
]


# ---------------------------------------------------------------------------
# Phone numbers. Runs before the card rules: a purely numeric value in the
# card rules' 12-19-digit range would otherwise be claimed as a PAN.
# ---------------------------------------------------------------------------
PHONE_MASKED_CASES = [
    # bare local number, no country code, fixed 3-3-4 grouping.
    ("phone-local-space-separators", "091 234 5678", "[PHONE-MASKED]"),
    ("phone-local-dash-space-mixed", "091-234 5678", "[PHONE-MASKED]"),
    ("phone-local-space-dash-mixed", "091 234-5678", "[PHONE-MASKED]"),
    ("phone-local-dash-separators", "091-234-5678", "[PHONE-MASKED]"),
    # "+" country code, E.164-style, any grouping/separators.
    ("phone-intl-plus-no-separators", "+963912345678", "[PHONE-MASKED]"),
    ("phone-intl-plus-space-after-code", "+963 912345678", "[PHONE-MASKED]"),
    ("phone-intl-plus-dash-after-code", "+963-912345678", "[PHONE-MASKED]"),
    ("phone-intl-country-code-in-card-digit-range", "call +44-555-123-4567 now", "call [PHONE-MASKED] now"),
    ("phone-intl-3digit-country-code-in-card-digit-range", "call +971-555-123-4567 now", "call [PHONE-MASKED] now"),
]


# ---------------------------------------------------------------------------
# Email addresses. No keyword needed — matched purely by shape
# (local@domain.tld), so it works the same whether it's a bare string, a
# real dict value, or nested inside a quoted/JSON-shaped key:value pair.
# ---------------------------------------------------------------------------
EMAIL_MASKED_CASES = [
    ("email-plain", "user@example.com", "[EMAIL-MASKED]"),
    ("email-in-sentence", "contact john.doe@example.com now", "contact [EMAIL-MASKED] now"),
    ("email-mixed-case", "User.Name+tag@Example.CO.UK", "[EMAIL-MASKED]"),
    ("email-subdomain", "first.last@sub.domain.example.com", "[EMAIL-MASKED]"),
    ("email-underscore-local-part", "user_name@example.com", "[EMAIL-MASKED]"),
    ("email-hyphen-local-part", "user-name@example.com", "[EMAIL-MASKED]"),
    ("email-hyphenated-domain", "user@sub-domain.example.co.uk", "[EMAIL-MASKED]"),
    ("email-plus-tag-local-part", "disposable.style.email.with+symbol@example.com", "[EMAIL-MASKED]"),
    # numeric-heavy local part / domain — must mask as one email, not get
    # fragmented by the card/phone/CVV rules that also look for digit runs.
    ("email-numeric-local-part", "123456@example.com", "[EMAIL-MASKED]"),
    ("email-numeric-domain", "notify: john@1234567890.com", "notify: [EMAIL-MASKED]"),
    ("email-single-quoted-colon", "'email': 'user@example.com'", "'email': '[EMAIL-MASKED]'"),
    ("email-double-quoted-colon", '"email": "user@example.com"', '"email": "[EMAIL-MASKED]"'),
    ("email-equals", "email=user@example.com", "email=[EMAIL-MASKED]"),
    (
        "email-quoted-inside-json-string",
        '{"contact": {"email": "user@example.com"}}',
        '{"contact": {"email": "[EMAIL-MASKED]"}}',
    ),
]


# ---------------------------------------------------------------------------
# Bare JWT — standalone secret with no keyword/scheme in front (the
# keyworded forms, e.g. "token:<jwt>" / "Bearer <jwt>", are covered by the
# credential rules above).
# ---------------------------------------------------------------------------
JWT_MASKED_CASES = [
    ("jwt-standalone", _JWT, "[JWT-MASKED]"),
    ("jwt-in-sentence-space-bounded", f"Here it's {_JWT} failed!", "Here it's [JWT-MASKED] failed!"),
    ("jwt-in-sentence-parens-wrapped", f"Here it's ({_JWT}) failed!", "Here it's ([JWT-MASKED]) failed!"),
    ("jwt-in-sentence-colon-prefixed", f"Here it's: {_JWT} failed!", "Here it's: [JWT-MASKED] failed!"),
    # leading "\b" only blocks a letter/digit/underscore glued directly in
    # front — hyphen and dot aren't word characters, so they still match.
    ("jwt-hyphen-prefixed", f"-{_JWT}", "-[JWT-MASKED]"),
    ("jwt-dot-prefixed", f".{_JWT}", ".[JWT-MASKED]"),
    # no boundary check at the end at all — any letter/digit/underscore/
    # hyphen glued directly after gets silently swallowed into the match.
    ("jwt-suffix-letter-swallowed", f"{_JWT}abc", "[JWT-MASKED]"),
    ("jwt-suffix-digit-swallowed", f"{_JWT}123", "[JWT-MASKED]"),
    ("jwt-suffix-underscore-swallowed", f"{_JWT}_more", "[JWT-MASKED]"),
    ("jwt-suffix-hyphen-swallowed", f"{_JWT}-more", "[JWT-MASKED]"),
    ("jwt-suffix-swallowed-in-sentence", f"token was {_JWT}extra and more", "token was [JWT-MASKED] and more"),
]


# ---------------------------------------------------------------------------
# Card numbers (PAN), 12-19 digits, dash/space separators. ecsctx truncates
# to first 6 + last 4 (#159795, PCI DSS 3.4.1) — the leading digit no longer
# changes the outcome, and every row below carries its own truncated core
# inside [CARD-MASKED:...]. Separators are stripped, so grouped input comes
# back contiguous.
# ---------------------------------------------------------------------------
CARD_NUMBER_CASES = [
    # continuous, leading 9
    ("card-12d-9-continuous", "912345678912", "[CARD-MASKED:********8912]"),
    ("card-13d-9-continuous", "9123456789123", "[CARD-MASKED:*********9123]"),
    ("card-14d-9-continuous", "91234567891234", "[CARD-MASKED:**********1234]"),
    ("card-15d-9-continuous", "912345678912345", "[CARD-MASKED:912345*****2345]"),
    ("card-16d-9-continuous", "9123456789123456", "[CARD-MASKED:912345******3456]"),
    ("card-17d-9-continuous", "91234567891234567", "[CARD-MASKED:912345*******4567]"),
    ("card-18d-9-continuous", "912345678912345678", "[CARD-MASKED:912345********5678]"),
    ("card-19d-9-continuous", "9123456789123456789", "[CARD-MASKED:912345*********6789]"),
    # space-separated, leading 9
    ("card-12d-9-space", "9123 4567 8912", "[CARD-MASKED:********8912]"),
    ("card-13d-9-space", "9123 4567 8912 3", "[CARD-MASKED:*********9123]"),
    ("card-14d-9-space", "9123 4567 8912 34", "[CARD-MASKED:**********1234]"),
    ("card-15d-9-space", "9123 4567 8912 345", "[CARD-MASKED:912345*****2345]"),
    ("card-16d-9-space", "9123 4567 8912 3456", "[CARD-MASKED:912345******3456]"),
    ("card-17d-9-space", "9123 4567 8912 34567", "[CARD-MASKED:912345*******4567]"),
    ("card-18d-9-space", "9123 4567 8912 345678", "[CARD-MASKED:912345********5678]"),
    ("card-19d-9-space", "9123 4567 8912 3456789", "[CARD-MASKED:912345*********6789]"),
    # dash-separated, leading 9
    ("card-12d-9-dash", "9123-4567-8912", "[CARD-MASKED:********8912]"),
    ("card-13d-9-dash", "9123-4567-8912-3", "[CARD-MASKED:*********9123]"),
    ("card-14d-9-dash", "9123-4567-8912-34", "[CARD-MASKED:**********1234]"),
    ("card-15d-9-dash", "9123-4567-8912-345", "[CARD-MASKED:912345*****2345]"),
    ("card-16d-9-dash", "9123-4567-8912-3456", "[CARD-MASKED:912345******3456]"),
    ("card-17d-9-dash", "9123-4567-8912-34567", "[CARD-MASKED:912345*******4567]"),
    ("card-18d-9-dash", "9123-4567-8912-345678", "[CARD-MASKED:912345********5678]"),
    ("card-19d-9-dash", "9123-4567-8912-3456789", "[CARD-MASKED:912345*********6789]"),
    # continuous, other leading digit — truncated too (BIN + last 4 visible)
    ("card-12d-other-continuous", "112345678912", "[CARD-MASKED:********8912]"),
    ("card-13d-other-continuous", "1123456789123", "[CARD-MASKED:*********9123]"),
    ("card-14d-other-continuous", "11234567891234", "[CARD-MASKED:**********1234]"),
    ("card-15d-other-continuous", "112345678912345", "[CARD-MASKED:112345*****2345]"),
    ("card-16d-other-continuous", "1123456789123456", "[CARD-MASKED:112345******3456]"),
    ("card-17d-other-continuous", "11234567891234567", "[CARD-MASKED:112345*******4567]"),
    ("card-18d-other-continuous", "112345678912345678", "[CARD-MASKED:112345********5678]"),
    ("card-19d-other-continuous", "1123456789123456789", "[CARD-MASKED:112345*********6789]"),
    # space-separated, other leading digit
    ("card-12d-other-space", "11234 56 78912", "[CARD-MASKED:********8912]"),
    ("card-13d-other-space", "11234 56 789123", "[CARD-MASKED:*********9123]"),
    ("card-14d-other-space", "11234 56 7891234", "[CARD-MASKED:**********1234]"),
    ("card-15d-other-space", "11234 56 78912345", "[CARD-MASKED:112345*****2345]"),
    ("card-16d-other-space", "11234 56 789123456", "[CARD-MASKED:112345******3456]"),
    ("card-17d-other-space", "11234 56 7891234567", "[CARD-MASKED:112345*******4567]"),
    ("card-18d-other-space", "11234 56 78912345678", "[CARD-MASKED:112345********5678]"),
    ("card-19d-other-space", "11234 56 789123456789", "[CARD-MASKED:112345*********6789]"),
    # dash-separated, other leading digit
    ("card-12d-other-dash", "1123-4567-8912", "[CARD-MASKED:********8912]"),
    ("card-13d-other-dash", "1123-4567-8912-3", "[CARD-MASKED:*********9123]"),
    ("card-14d-other-dash", "1123-4567-8912-34", "[CARD-MASKED:**********1234]"),
    ("card-15d-other-dash", "1123-4567-8912-345", "[CARD-MASKED:112345*****2345]"),
    ("card-16d-other-dash", "1123-4567-8912-3456", "[CARD-MASKED:112345******3456]"),
    ("card-17d-other-dash", "1123-4567-8912-34567", "[CARD-MASKED:112345*******4567]"),
    ("card-18d-other-dash", "1123-4567-8912-345678", "[CARD-MASKED:112345********5678]"),
    ("card-19d-other-dash", "1123-4567-8912-3456789", "[CARD-MASKED:112345*********6789]"),
    # irregular grouping
    ("card-2groups-9-space", "90345 67812901256", "[CARD-MASKED:903456******1256]"),
    ("card-2groups-9-dash", "90345-67812901256", "[CARD-MASKED:903456******1256]"),
    ("card-2groups-other-space", "10345 67812901256", "[CARD-MASKED:103456******1256]"),
    ("card-2groups-other-dash", "10345-67812901256", "[CARD-MASKED:103456******1256]"),
    ("card-3groups-9-space", "90345 678129012 90345", "[CARD-MASKED:903456*********0345]"),
    ("card-3groups-9-dash", "90345-678129012-90345", "[CARD-MASKED:903456*********0345]"),
    ("card-3groups-other-space", "10345 678129012 10345", "[CARD-MASKED:103456*********0345]"),
    ("card-3groups-other-dash", "10345-678129012-10345", "[CARD-MASKED:103456*********0345]"),
    ("card-5groups-9-space", "90345 678 1290 12 56789", "[CARD-MASKED:903456*********6789]"),
    ("card-5groups-9-dash", "90345-678-1290-12-56789", "[CARD-MASKED:903456*********6789]"),
    ("card-5groups-other-space", "40345 678 1290 12 56789", "[CARD-MASKED:403456*********6789]"),
    ("card-5groups-other-dash", "40345-678-1290-12-56789", "[CARD-MASKED:403456*********6789]"),
    # mixed separators within one number
    ("card-2-mixed-separator-9", "9034-5678 1290", "[CARD-MASKED:********1290]"),
    ("card-3-mixed-separator-9", "9034-5678 1290-125", "[CARD-MASKED:903456*****0125]"),
    ("card-4-mixed-separator-9", "9034-5678 1290-1256 125", "[CARD-MASKED:903456*********6125]"),
    ("card-2-mixed-separator-other", "4034-5678 1290", "[CARD-MASKED:********1290]"),
    ("card-3-mixed-separator-other", "4034-5678 1290-125", "[CARD-MASKED:403456*****0125]"),
    ("card-4-mixed-separator-other", "4034-5678 1290-1256 125", "[CARD-MASKED:403456*********6125]"),
    # trailing chunk is phone-shaped (10 bare digits) — the phone rule runs
    # first, so the card rule needs its guard to still claim the full PAN.
    ("card-17d-space-trailing-chunk-is-phone-shaped", "11234 56 7891234567", "[CARD-MASKED:112345*******4567]"),
    # every allowed lead-guard prefix, embedded in a sentence
    ("card-19d-9-space-prefixed-in-sentence", "Here is 9123456789123456789 card Number", "Here is [CARD-MASKED:912345*********6789] card Number"),
    ("card-19d-9-paren-prefixed-in-sentence", "Here is (9123456789123456789) card Number", "Here is ([CARD-MASKED:912345*********6789]) card Number"),
    ("card-19d-9-bracket-prefixed-in-sentence", "Here is [9123456789123456789] card Number", "Here is [[CARD-MASKED:912345*********6789]] card Number"),
    ("card-19d-9-brace-prefixed-in-sentence", "Here is {9123456789123456789} card Number", "Here is {[CARD-MASKED:912345*********6789]} card Number"),
    ("card-19d-9-colon-prefixed-in-sentence", "Here num:9123456789123456789 card Number", "Here num:[CARD-MASKED:912345*********6789] card Number"),
    ("card-19d-9-equals-prefixed-in-sentence", "Here num=9123456789123456789 card Number", "Here num=[CARD-MASKED:912345*********6789] card Number"),
    ("card-19d-9-comma-prefixed-in-sentence", "Here num,9123456789123456789 card Number", "Here num,[CARD-MASKED:912345*********6789] card Number"),
    ("card-19d-9-dot-prefixed-in-sentence", "Here num.9123456789123456789 card Number", "Here num.[CARD-MASKED:912345*********6789] card Number"),
    # 4-4-4-4 grouping: cascaded into per-group CVV masking in the ported
    # source, but full-PAN masking claims the whole run here.
    ("card-12d-other-space-4x4", "1123 4567 8912", "[CARD-MASKED:********8912]"),
    ("card-15d-other-space-4x4", "1123 4567 8912 345", "[CARD-MASKED:112345*****2345]"),
    ("card-16d-other-space-4x4", "1123 4567 8912 3456", "[CARD-MASKED:112345******3456]"),
    ("card-17d-other-space-4x4", "1123 4567 8912 34567", "[CARD-MASKED:112345*******4567]"),
    ("card-19d-other-space-4x4", "1123 4567 8912 3456789", "[CARD-MASKED:112345*********6789]"),
]


# ---------------------------------------------------------------------------
# SSN. Runs before standalone-CVV (the loosest rule of all — any bare 3-4
# digit group): a space-separated SSN's outer groups ("123" and "6789") are
# each individually CVV-standalone-shaped, so without this order it would
# fragment instead of masking as one SSN.
# ---------------------------------------------------------------------------
SSN_MASKED_CASES = [
    ("ssn-space-glued-no-separators", "ssn 123456789 on file", "ssn [SSN-MASKED] on file"),
    ("ssn-space-then-glued-tail", "ssn 123 456789 on file", "ssn [SSN-MASKED] on file"),
    ("ssn-glued-head-then-space", "ssn 12345 6789 on file", "ssn [SSN-MASKED] on file"),
    ("ssn-space-separated-all-groups", "ssn 123 45 6789 on file", "ssn [SSN-MASKED] on file"),
    ("ssn-dash-then-glued-tail", "ssn 123-456789 on file", "ssn [SSN-MASKED] on file"),
    ("ssn-glued-head-then-dash", "ssn 12345-6789 on file", "ssn [SSN-MASKED] on file"),
    ("ssn-dash-separated-all-groups", "ssn 123-45-6789 on file", "ssn [SSN-MASKED] on file"),
    ("ssn-mixed-space-then-dash", "ssn 123 45-6789 on file", "ssn [SSN-MASKED] on file"),
    ("ssn-mixed-dash-then-space", "ssn 123-45 6789 on file", "ssn [SSN-MASKED] on file"),
    ("ssn-equals-prefixed", "ssn=123456789 on file", "ssn=[SSN-MASKED] on file"),
    ("ssn-colon-prefixed", "ssn:123456789 on file", "ssn:[SSN-MASKED] on file"),
    ("ssn-comma-prefixed", "ssn,123456789 on file", "ssn,[SSN-MASKED] on file"),
    ("ssn-dot-prefixed", "ssn.123456789 on file", "ssn.[SSN-MASKED] on file"),
    ("ssn-single-quote-prefixed", "ssn'123456789' on file", "ssn'[SSN-MASKED]' on file"),
    ("ssn-double-quote-prefixed", 'ssn"123456789" on file', 'ssn"[SSN-MASKED]" on file'),
    ("ssn-paren-prefixed", "ssn(123456789) on file", "ssn([SSN-MASKED]) on file"),
    ("ssn-bracket-prefixed", "ssn[123456789] on file", "ssn[[SSN-MASKED]] on file"),
    ("ssn-brace-prefixed", "ssn{123456789} on file", "ssn{[SSN-MASKED]} on file"),
    ("ssn-string-start-no-prefix", "123456789 on file", "[SSN-MASKED] on file"),
]


# ---------------------------------------------------------------------------
# _mask_dict's key-name check: a dict key that is itself a sensitive keyword
# masks its whole value outright, regardless of type/content — this is what
# makes a bare structlog kwarg (log.info(..., token="abcd1234")) get masked,
# since the content rules never see key and value joined into one string.
# ---------------------------------------------------------------------------
DICT_KEY_VALUE_MASKING_CASES = [
    (
        "key-token-string-value",
        {"event": "create payment", "token": "abcd1234"},
        {"event": "create payment", "token": "[SECRET-MASKED]"},
    ),
    ("key-cvv-int-value", {"cvv": 123}, {"cvv": "[CVV-MASKED]"}),
    ("key-cvv-string-value", {"cvv": "123"}, {"cvv": "[CVV-MASKED]"}),
    ("key-session-key-int-value", {"session_key": 12345}, {"session_key": "[SECRET-MASKED]"}),
    # A null holds nothing to mask: a marker there would read as a value.
    ("key-access-token-none-value", {"access_token": None}, {"access_token": None}),
    (
        "key-sensitive-nulls-stay-null",
        {"public_key": None, "customer_name": None, "card": None, "expiry": None, "cvv": None},
        {"public_key": None, "customer_name": None, "card": None, "expiry": None, "cvv": None},
    ),
    ("key-mixed-case-cvv", {"Cvv": "123"}, {"Cvv": "[CVV-MASKED]"}),
    ("key-camelcase-security-code-int", {"securityCode": 999}, {"securityCode": "[CVV-MASKED]"}),
    (
        "key-nested-under-sensitive-key-blanket-masked",
        {"data": {"token": {"nested": "stuff", "more": 1}}},
        {"data": {"token": "[SECRET-MASKED]"}},
    ),
]


# Structured logging passes objects as kwargs; their repr must not leak. The
# filter stringifies a non-primitive before masking, or the embedded PAN would
# render unmasked downstream. Numbers, bools and None must survive intact — a
# 3-digit status code or count must not be caught by the CVV pattern.
OBJECT_AND_PRIMITIVE_CASES = [
    (
        "object-repr-pan-masked",
        {"event": "decrypted payment data", "source": _FakeCard()},
        {"event": "decrypted payment data", "source": "<Card(VISA, 512345******0008, [CARD-MASKED:958418******4802])>"},
    ),
    (
        "object-nested-in-list-and-dict",
        {"data": {"cards": [{"instrument": _FakeCard()}]}},
        {"data": {"cards": [{"instrument": "<Card(VISA, 512345******0008, [CARD-MASKED:958418******4802])>"}]}},
    ),
    ("cvv-string-field", {"processed_data": {"cvv": "100"}}, {"processed_data": {"cvv": "[CVV-MASKED]"}}),
    (
        "numeric-primitives-not-mangled",
        {"status_code": 200, "count": 100, "ok": True, "nothing": None},
        {"status_code": 200, "count": 100, "ok": True, "nothing": None},
    ),
    ("plain-string-message-with-pan", "card 5123 4500 0000 0008", "card [CARD-MASKED:512345******0008]"),
]

# ---------------------------------------------------------------------------
# Non-sensitive fields and prose that must NOT be masked — guards the rules
# against over-masking. "key" is only sensitive as a *_key compound, so
# cache_key/sort_key/primary_key are spared; and the space rule's digit
# guard leaves prose like "Basic authentication" untouched.
# ---------------------------------------------------------------------------
NOT_MASKED = [
    ("cache-key", "cache_key=user_profile_v2"),
    ("sort-key", "sort_key=created_at_desc"),
    ("primary-key", "primary_key=customer_00042"),
    ("partition-key", "partition_key=eu_west_1a"),
    ("prose-basic", "Basic authentication required"),
    ("prose-bearer", "the bearer of this message"),
    ("prose-token", "token expired, please retry"),
    ("cred-char-session-id-unaffected", "session_id=abcdefghijklmn"),
    ("cred-both-session-id-unaffected", "session_id=6ea04d6db060f7ce414b6f5faa7119161e2214bc"),
    # IBAN pattern must validate a real uppercase country prefix, not just
    # the "2 letters + 2 digits + alnum" shape — these are not IBANs.
    ("iban-fake-country", "order AB12CDEF3456GH78 shipped"),
    ("iban-non-iban-country", "ref US12INVOICE0000042 paid"),
    ("iban-lowercase", "acct gb33bukb20201555 done"),
    # Card rules only recognize dash/space (the two real-world PAN
    # separators), so dot/comma/underscore are deliberately not chased.
    ("card-dot-separated-not-a-real-pan-format", "4111.1111.1111.1111"),
    # outside the 12-19 digit range entirely
    ("card-11d-9-continuous", "91234567891"),
    ("card-20d-9-continuous", "91234567891234567891"),
    ("card-11d-9-space", "912345 67891"),
    ("card-20d-9-space", "912345 678912 34567891"),
    ("card-11d-9-dash", "9123-4567-891"),
    ("card-20d-9-dash", "9123-4567-8912-34567891"),
    ("card-11d-other-continuous", "11234567891"),
    ("card-20d-other-continuous", "11234567891234567891"),
    ("card-11d-other-space", "112345 67891"),
    ("card-20d-other-space", "112345 678912 34567891"),
    ("card-11d-other-dash", "1123-4567-891"),
    ("card-20d-other-dash", "1123-4567-8912-34567891"),
    # Email rule requires a literal "@", a domain, a dot, and a 2+ letter
    # TLD — anything short of that full shape is left alone.
    ("email-no-tld-dot", "user@localhost"),
    ("email-trailing-dot-no-tld", "user@example."),
    ("email-no-domain-before-dot", "user@.com"),
    ("email-no-local-part", "@example.com"),
    ("email-no-domain", "user@"),
    ("email-single-char-tld", "user@example.c"),
    # not a sensitive key at all, regardless of value.
    ("key-cache-key-unaffected", {"cache_key": "user_profile_v2"}),
]


# ---------------------------------------------------------------------------
# Space-cascade bug (open): the standalone-CVV rule — the loosest rule in the
# file, any bare 3-4 digit group — claims the 4-digit groups of a
# space-separated digit run that the card rules correctly ignored for being
# outside the 12-19 range. Each case is (label, sample): the intended output
# is the sample untouched, which is not what ships today. Only
# tests/test_masking_filter.py runs these, as strict xfail, so fixing the
# cascade turns them into XPASS failures and forces promotion into
# NOT_MASKED. The shipped suite leaves them out: a project cannot fix
# them.
#
# The in-range 4-4-4-4 rows this list carried in the ported source are no
# longer affected — truncated-PAN masking claims the whole run before the
# CVV rule can see the groups — and now live in CARD_NUMBER_CASES.
# ---------------------------------------------------------------------------
OVER_MASKED_BECAUSE_OF_CVV = [
    ("card-11d-9-space", "9123 4567 891"),
    ("card-20d-9-space", "9123 4567 8912 34567891"),
    ("card-11d-other-space", "1123 4567 891"),
    ("card-20d-other-space", "1123 4567 8912 34567891"),
]


# ---------------------------------------------------------------------------
# Accepted leaks: unlike NOT_MASKED above (values that aren't sensitive, or
# don't match a rule's shape at all), every case here is genuinely
# sensitive-looking data (a real PAN, a real token) that a guard deliberately
# lets through unmasked. Each is a settled decision, not an open bug.
# ---------------------------------------------------------------------------
ACCEPTED_LEAK_CASES = [
    # The bare-space credential rule requires a digit in the value, so it can
    # tell a real token from prose — an all-letter value is left unmasked.
    ("cred-space-value-no-digit-unmasked", "Bearer abcdefghij"),
    # Keyword glued directly to its value with no separator at all is never
    # matched — required, since matching it would over-mask ordinary words
    # like "tokenization" that merely start with a keyword.
    ("cred-glued-no-separator-unmasked", "token12345"),
    # All card rules share one lead guard: a match may only start right after
    # a real prefix (quote, ":", "=", space, comma, dot, or start-of-string).
    # A letter isn't in that set, so a digit run glued to a preceding letter
    # matches no card rule at all.
    ("card-glued-to-letters-leading-9-unaffected", "REF9111111111111111 confirmed"),
    ("card-glued-to-letters-leading-other-unaffected", "REF4111111111111111 confirmed"),
    # The lead guard also blocks a match preceded by "<digit><space>", which
    # ordinary text ending in a digit ("point 1", "step 2") triggers.
    ("card-19d-9-preceded-by-digit-space-unaffected", "point 1 9123456789123456789"),
    ("card-19d-other-preceded-by-digit-space-unaffected", "point 1 1234567891234567891"),
    # The JWT rule's leading "\b" blocks a match when "eyJ" is glued directly
    # to a word character.
    ("jwt-glued-to-letter-prefix-unmasked", f"abc{_JWT}"),
    ("jwt-glued-to-digit-prefix-unmasked", f"123{_JWT}"),
    ("jwt-glued-to-underscore-prefix-unmasked", f"_{_JWT}"),
    # Phone shares the card lead guard — "+" glued to a preceding letter
    # doesn't match.
    ("phone-glued-plus-to-letter-unmasked", "call+963912345678"),
]


# Plain stdlib logging, where the handler interpolates the arguments:
# (label, message, args, expected message, pack the case needs). Only a filter
# on the handler sees these — a structlog processor runs too late.
STDLIB_ARGS_CASES: list[tuple[str, str, tuple, str, str]] = []


# Text an opt-in pack would mask, listed for the services that leave that pack
# off: (label, sample, the pack that must be off). Turning the pack on is what
# masks it, so the case runs only where it is off.
WITHOUT_PACK_CASES: list[tuple[str, object, str]] = []


MASKED_GROUPS = {
    "pem": PEM_MASKED_CASES,
    "credential": CREDENTIAL_MASKED_CASES,
    "cvv": CVV_KEYWORD_CASES,
    "payment_id": PAYMENT_ID_QUOTE_CASES,
    "iban": IBAN_MASKED_CASES,
    "phone": PHONE_MASKED_CASES,
    "email": EMAIL_MASKED_CASES,
    "jwt": JWT_MASKED_CASES,
    "card": CARD_NUMBER_CASES,
    "ssn": SSN_MASKED_CASES,
    "dict_key": DICT_KEY_VALUE_MASKING_CASES,
    "object_and_primitive": OBJECT_AND_PRIMITIVE_CASES,
}

UNCHANGED_GROUPS = {
    "not_masked": NOT_MASKED,
    "accepted_leaks": ACCEPTED_LEAK_CASES,
}

# The pack holding each group's content rule (ecsctx.masking.patterns).
CONTENT_PACK = {
    "pem": "default",
    "credential": "default",
    "cvv": "pci",
    "payment_id": "financial_ids",
    "iban": "financial_ids",
    "phone": "default",
    "email": "default",
    "jwt": "default",
    "card": "pci",
    "ssn": "financial_ids",
    "dict_key": "default",
    "object_and_primitive": "pci",
}


def _holds_object(value) -> bool:
    if isinstance(value, dict):
        return any(_holds_object(v) for v in value.values())
    if isinstance(value, list):
        return any(_holds_object(v) for v in value)
    return isinstance(value, _FakeCard)


# Key names are matched in every service, except payment-id names, which
# classify_key() only recognises with financial_ids on.
KEY_PACK = {"payment_id": "financial_ids"}


def case_pack(group: str, sample) -> str:
    """The pack a case needs. Text is caught by its group's content rule; a
    dict by its key names — unless the data sits in an object's repr, which
    only the content rule can read."""
    if group not in CONTENT_PACK:
        raise KeyError(
            f"unknown masking sample group {group!r}: expected one of "
            f"{', '.join(sorted(CONTENT_PACK))}"
        )
    if isinstance(sample, str) or _holds_object(sample):
        return CONTENT_PACK[group]
    return KEY_PACK.get(group, "default")
