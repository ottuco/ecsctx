"""Masking sample tables, shipped so a project can run them against its own logging.

Each case is (label, sample, expected). A string sample is logged as the event
message; a dict sample is logged as one field. MaskingTestsMixin runs them
through a project's real handlers, and ecsctx's own suite runs that mixin with
every pack on, so these tables are ecsctx's filter tests too.

A case masked by key name may add a fourth item, the key names it needs. A
project that lists one of them in ECSCTX_MASK_SAFE_KEYS skips the case, since
that key then keeps its value there.

Expected values are the [LABEL] form a project without PII tokenization emits.
Where tokenization is configured, a tokenizable value is logged as a bare
ptok:v1:… token instead; the test helper treats the two as equal.

Content rules come in packs: "default" is always on, "pci" and
"financial_ids" are opt-in (ecsctx.masking.config). case_pack() says which pack
a case needs, so a project is only held to the packs it has turned on.
"""

from decimal import Decimal


class _FakeCard:
    """Stand-in for a model whose ``__repr__`` embeds sensitive data (PAN/token)."""

    def __repr__(self) -> str:
        return "<Card(VISA, 512345******0008, 9584184138614802)>"


class _Owner:
    """Stand-in for an object whose text holds PII."""

    def __str__(self) -> str:
        return "owner a@b.co"


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
        ("Authorization",),
    ),
    (
        "auth-inside-headers-dict-bearer",
        {"headers": {"Authorization": f"Bearer {_JWT}"}},
        {"headers": {"Authorization": "[SECRET-MASKED]"}},
        ("Authorization",),
    ),
    (
        "auth-inside-headers-dict-token",
        {"headers": {"Authorization": "token abcd 1234 anything"}},
        {"headers": {"Authorization": "[SECRET-MASKED]"}},
        ("Authorization",),
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
    # one case per key name of this type, masked by the name alone
    ("key-name-bearer", {"bearer": "value1"}, {"bearer": "[SECRET-MASKED]"}, ("bearer",)),
    ("key-name-basic", {"basic": "value1"}, {"basic": "[SECRET-MASKED]"}, ("basic",)),
    ("key-name-digest", {"digest": "value1"}, {"digest": "[SECRET-MASKED]"}, ("digest",)),
    ("key-name-credentials", {"credentials": "value1"}, {"credentials": "[SECRET-MASKED]"}, ("credentials",)),
    ("key-name-authorization", {"authorization": "value1"}, {"authorization": "[SECRET-MASKED]"}, ("authorization",)),
    ("key-name-api-key", {"api_key": "value1"}, {"api_key": "[SECRET-MASKED]"}, ("api_key",)),
    ("key-name-access-token", {"access_token": "value1"}, {"access_token": "[SECRET-MASKED]"}, ("access_token",)),
    ("key-name-password", {"password": "value1"}, {"password": "[SECRET-MASKED]"}, ("password",)),
    # a service's own vocabulary: masked until the service lists it
    ("key-tokenization-status", {"tokenization_status": "value1"}, {"tokenization_status": "[SECRET-MASKED]"}, ("tokenization_status",)),
    # more spellings of a sensitive key name
    ("key-cardtoken", {"cardtoken": "value1"}, {"cardtoken": "[SECRET-MASKED]"}, ("cardtoken",)),
    ("key-x-api-key", {"x-api-key": "value1"}, {"x-api-key": "[SECRET-MASKED]"}, ("x-api-key",)),
    ("key-apikey", {"apiKey": "value1"}, {"apiKey": "[SECRET-MASKED]"}, ("apiKey",)),
    ("key-client-secret", {"client_secret": "value1"}, {"client_secret": "[SECRET-MASKED]"}, ("client_secret",)),
    ("cred-email-and-bearer-in-one-line", "a@b.co Bearer abc12345def", "[EMAIL-MASKED] Bearer [SECRET-MASKED]"),
    # glued and plural spellings a payload uses
    ("key-tokens", {"tokens": "value1"}, {"tokens": "[SECRET-MASKED]"}, ("tokens",)),
    ("key-passwordhash", {"passwordhash": "value1"}, {"passwordhash": "[SECRET-MASKED]"}, ("passwordhash",)),
    ("key-merchantapikey", {"merchantapikey": "value1"}, {"merchantapikey": "[SECRET-MASKED]"}, ("merchantapikey",)),
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
    (
        "cvv-dict-obj",
        {"processed_data": {"cvv": "100"}},
        {"processed_data": {"cvv": "[CVV-MASKED]"}},
        ("cvv",),
    ),
    (
        "cvv-dict-obj-long",
        {"processed_data": {"cvv": "not a cvv shape 123456789"}},
        {"processed_data": {"cvv": "[CVV-MASKED]"}},
        ("cvv",),
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
    # one case per key name of this type, masked by the name alone
    ("key-name-cvv", {"cvv": "value1"}, {"cvv": "[CVV-MASKED]"}, ("cvv",)),
    ("key-name-cvc", {"cvc": "value1"}, {"cvc": "[CVV-MASKED]"}, ("cvc",)),
    ("key-name-security-code", {"security_code": "value1"}, {"security_code": "[CVV-MASKED]"}, ("security_code",)),
    # a service's own vocabulary: masked until the service lists it
    ("key-cvv-required", {"cvv_required": "value1"}, {"cvv_required": "[CVV-MASKED]"}, ("cvv_required",)),
    # more spellings of a sensitive key name
    ("key-cvv2", {"cvv2": "value1"}, {"cvv2": "[CVV-MASKED]"}, ("cvv2",)),
    ("key-securitycode", {"securityCode": "value1"}, {"securityCode": "[CVV-MASKED]"}, ("securityCode",)),
    ("cvv-with-a-saved-card-token", "token=tok_9f8e7d cvv 123", "token=[SECRET-MASKED] cvv [CVV-MASKED]"),
    # glued and plural spellings a payload uses
    ("key-cardcvv", {"cardcvv": "value1"}, {"cardcvv": "[CVV-MASKED]"}, ("cardcvv",)),
    ("key-cvvnumber", {"cvvnumber": "value1"}, {"cvvnumber": "[CVV-MASKED]"}, ("cvvnumber",)),
    ("key-cvvcode", {"CVVCode": "value1"}, {"CVVCode": "[CVV-MASKED]"}, ("CVVCode",)),
    ("key-cardsecuritycode", {"cardsecuritycode": "value1"}, {"cardsecuritycode": "[CVV-MASKED]"}, ("cardsecuritycode",)),
    # a CVV key inside JSON text: the content pack is what parses it
    ("cvv-key-in-json-text", 'data {"cvv": 123}', 'data {"cvv": "[CVV-MASKED]"}', ("cvv",)),
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
        ("payment_id",),
    ),
    (
        "payment-id-dict-obj-long",
        {"processed_data": {"payment_id": "not a cvv shape abc12345"}},
        {"processed_data": {"payment_id": "[PAYMENT-ID-MASKED]"}},
        ("payment_id",),
    ),
    ("key-name-payment-id", {"payment_id": "value1"}, {"payment_id": "[PAYMENT-ID-MASKED]"}, ("payment_id",)),
    ("key-name-transaction-id", {"transaction_id": "value1"}, {"transaction_id": "[PAYMENT-ID-MASKED]"}, ("transaction_id",)),
    ("key-name-auth-id", {"auth_id": "value1"}, {"auth_id": "[PAYMENT-ID-MASKED]"}, ("auth_id",)),
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
    ("iban-keyworded", "iban GB33BUKB20201555555555", "iban [IBAN-MASKED]"),
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
    # one case per key name of this type, masked by the name alone
    ("key-name-phone", {"phone": "value1"}, {"phone": "[PHONE-MASKED]"}, ("phone",)),
    ("key-name-mobile", {"mobile": "value1"}, {"mobile": "[PHONE-MASKED]"}, ("mobile",)),
    ("key-name-tel", {"tel": "value1"}, {"tel": "[PHONE-MASKED]"}, ("tel",)),
    # more spellings of a sensitive key name
    ("key-telephone", {"telephone": "value1"}, {"telephone": "[PHONE-MASKED]"}, ("telephone",)),
    ("key-tel-no", {"tel_no": "value1"}, {"tel_no": "[PHONE-MASKED]"}, ("tel_no",)),
    ("key-telno", {"telNo": "value1"}, {"telNo": "[PHONE-MASKED]"}, ("telNo",)),
    ("key-customer-tel", {"customer_tel": "value1"}, {"customer_tel": "[PHONE-MASKED]"}, ("customer_tel",)),
    ("key-tel2", {"tel2": "value1"}, {"tel2": "[PHONE-MASKED]"}, ("tel2",)),
    # glued and plural spellings a payload uses
    ("key-phonenumber", {"phonenumber": "value1"}, {"phonenumber": "[PHONE-MASKED]"}, ("phonenumber",)),
    ("key-mobileno", {"mobileno": "value1"}, {"mobileno": "[PHONE-MASKED]"}, ("mobileno",)),
    ("key-customerphone", {"customerphone": "value1"}, {"customerphone": "[PHONE-MASKED]"}, ("customerphone",)),
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
    # one case per key name of this type, masked by the name alone
    ("key-name-email", {"email": "value1"}, {"email": "[EMAIL-MASKED]"}, ("email",)),
    ("email-bare", "a@b.com", "[EMAIL-MASKED]"),
    ("email-in-a-sentence", "contact a@b.com please", "contact [EMAIL-MASKED] please"),
    ("email-after-a-masked-like-fragment", "ha-MASKED] contact me at attacker@evil.com", "ha-MASKED] contact me at [EMAIL-MASKED]"),
    ("email-in-text-that-is-not-json", "{not json} a@b.com", "{not json} [EMAIL-MASKED]"),
    ("email-as-a-json-scalar", '"a@b.com"', '"[EMAIL-MASKED]"'),
    # glued and plural spellings a payload uses
    ("key-email", {"eMail": "value1"}, {"eMail": "[EMAIL-MASKED]"}, ("eMail",)),
    ("key-emailid", {"emailid": "value1"}, {"emailid": "[EMAIL-MASKED]"}, ("emailid",)),
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
    # one case per key name of this type, masked by the name alone
    ("key-name-card", {"card": "value1"}, {"card": "[CARD-MASKED]"}, ("card",)),
    ("key-name-pan", {"pan": "value1"}, {"pan": "[CARD-MASKED]"}, ("pan",)),
    ("key-name-card-number", {"card_number": "value1"}, {"card_number": "[CARD-MASKED]"}, ("card_number",)),
    ("key-name-cardno", {"cardno": "value1"}, {"cardno": "[CARD-MASKED]"}, ("cardno",)),
    # separators do not matter, and a truncated marker survives a second pass
    ("card-spaced-groups", "4111 1111 1111 1111", "[CARD-MASKED:411111******1111]"),
    ("card-dashed-groups", "4111-1111-1111-1111", "[CARD-MASKED:411111******1111]"),
    ("card-contiguous", "4111111111111111", "[CARD-MASKED:411111******1111]"),
    ("card-marker-unchanged", "[CARD-MASKED:411111******1111]", "[CARD-MASKED:411111******1111]"),
    # a PAN logged as a JSON number: the key rules leave it, the content rules take it
    (
        "card-json-number-in-text",
        '{"nameOnCard": "Jane Payer", "ref": 4111111111111111}',
        '{"nameOnCard": "[NAME-MASKED]", "ref": [CARD-MASKED:411111******1111]}',
    ),
    # more spellings of a sensitive key name
    ("key-cardnumber", {"cardNumber": "value1"}, {"cardNumber": "[CARD-MASKED]"}, ("cardNumber",)),
    # what the pci pack adds: PAN truncation in free text
    ("card-pan-and-cvv-in-text", "card 4111111111111111 cvv 123", "card [CARD-MASKED:411111******1111] cvv [CVV-MASKED]"),
    ("card-pan-between-separators", '"pan":"4111111111111111",', '"pan":"[CARD-MASKED:411111******1111]",'),
    ("card-short-pan-keeps-last-four", "pay 5018123456789 ok", "pay [CARD-MASKED:*********6789] ok"),
    ("card-track-2-data", "5413330089020011D2512601079360805F", "[CARD-MASKED:541333******0011]D2512601079360805F"),
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
        ("token",),
    ),
    ("key-cvv-int-value", {"cvv": 123}, {"cvv": "[CVV-MASKED]"}, ("cvv",)),
    ("key-cvv-string-value", {"cvv": "123"}, {"cvv": "[CVV-MASKED]"}, ("cvv",)),
    ("key-session-key-int-value", {"session_key": 12345}, {"session_key": "[SECRET-MASKED]"}, ("session_key",)),
    # A null holds nothing to mask: a marker there would read as a value.
    ("key-access-token-none-value", {"access_token": None}, {"access_token": None}),
    (
        "key-sensitive-nulls-stay-null",
        {"public_key": None, "customer_name": None, "card": None, "expiry": None, "cvv": None},
        {"public_key": None, "customer_name": None, "card": None, "expiry": None, "cvv": None},
    ),
    ("key-mixed-case-cvv", {"Cvv": "123"}, {"Cvv": "[CVV-MASKED]"}, ("Cvv",)),
    (
        "key-camelcase-security-code-int",
        {"securityCode": 999},
        {"securityCode": "[CVV-MASKED]"},
        ("securityCode",),
    ),
    (
        "key-nested-under-sensitive-key-blanket-masked",
        {"data": {"token": {"nested": "stuff", "more": 1}}},
        {"data": {"token": "[SECRET-MASKED]"}},
        ("token",),
    ),
    # one case per key name of this type, masked by the name alone
    ("key-name-expiry", {"expiry": "value1"}, {"expiry": "[EXPIRY-MASKED]"}, ("expiry",)),
    ("key-name-expiration", {"expiration": "value1"}, {"expiration": "[EXPIRY-MASKED]"}, ("expiration",)),
    ("key-name-exp-month", {"exp_month": "value1"}, {"exp_month": "[EXPIRY-MASKED]"}, ("exp_month",)),
    ("key-name-exp-year", {"exp_year": "value1"}, {"exp_year": "[EXPIRY-MASKED]"}, ("exp_year",)),
    ("key-name-exp-date", {"exp_date": "value1"}, {"exp_date": "[EXPIRY-MASKED]"}, ("exp_date",)),
    ("key-name-address", {"address": "value1"}, {"address": "[ADDRESS-MASKED]"}, ("address",)),
    ("key-name-name", {"name": "value1"}, {"name": "[NAME-MASKED]"}, ("name",)),
    ("key-name-cardholder", {"cardholder": "value1"}, {"cardholder": "[NAME-MASKED]"}, ("cardholder",)),
    ("key-name-beneficiary", {"beneficiary": "value1"}, {"beneficiary": "[NAME-MASKED]"}, ("beneficiary",)),
    ("key-name-recipient", {"recipient": "value1"}, {"recipient": "[NAME-MASKED]"}, ("recipient",)),
    ("key-name-payer", {"payer": "value1"}, {"payer": "[NAME-MASKED]"}, ("payer",)),
    ("key-name-billing", {"billing": "value1"}, {"billing": "[GENERIC-MASKED]"}, ("billing",)),
    ("key-name-shipping", {"shipping": "value1"}, {"shipping": "[GENERIC-MASKED]"}, ("shipping",)),
    ("key-name-customer", {"customer": "value1"}, {"customer": "[GENERIC-MASKED]"}, ("customer",)),
    ("key-name-contact", {"contact": "value1"}, {"contact": "[GENERIC-MASKED]"}, ("contact",)),
    ("key-name-udf", {"udf": "value1"}, {"udf": "[GENERIC-MASKED]"}, ("udf",)),
    ("key-customer-email", {"customer_email": "user@example.com"}, {"customer_email": "[EMAIL-MASKED]"}, ("customer_email",)),
    # a PII container keeps its shape: the email field is masked as an email
    (
        "key-email-under-a-container",
        {"contact": {"email": "user@example.com"}},
        {"contact": {"email": "[EMAIL-MASKED]"}},
        ("contact", "email"),
    ),
    (
        "key-never-tokenized-types-keep-their-label",
        {"cvv": "123", "expiry": "12/28", "card_number": "4111111111111111"},
        {"cvv": "[CVV-MASKED]", "expiry": "[EXPIRY-MASKED]", "card_number": "[CARD-MASKED:411111******1111]"},
        ("cvv", "expiry", "card_number"),
    ),
    ("nested-containers-are-walked", {"items": [{"notes": ["a@b.com"]}]}, {"items": [{"notes": ["[EMAIL-MASKED]"]}]}),
    # a service's own vocabulary: masked until the service lists it
    ("key-pg-name", {"pg_name": "value1"}, {"pg_name": "[NAME-MASKED]"}, ("pg_name",)),
    ("key-gateway-name", {"gateway_name": "value1"}, {"gateway_name": "[NAME-MASKED]"}, ("gateway_name",)),
    ("key-vendor-name", {"vendor_name": "value1"}, {"vendor_name": "[NAME-MASKED]"}, ("vendor_name",)),
    ("key-bank-name", {"bank_name": "value1"}, {"bank_name": "[NAME-MASKED]"}, ("bank_name",)),
    ("key-install-name", {"install_name": "value1"}, {"install_name": "[NAME-MASKED]"}, ("install_name",)),
    ("key-installation-name", {"installation_name": "value1"}, {"installation_name": "[NAME-MASKED]"}, ("installation_name",)),
    ("key-x-script-name", {"X-Script-Name": "value1"}, {"X-Script-Name": "[NAME-MASKED]"}, ("X-Script-Name",)),
    # more spellings of a sensitive key name
    ("key-first-name", {"first_name": "value1"}, {"first_name": "[NAME-MASKED]"}, ("first_name",)),
    ("key-cardholdername", {"cardHolderName": "value1"}, {"cardHolderName": "[NAME-MASKED]"}, ("cardHolderName",)),
    ("key-firstname", {"firstname": "value1"}, {"firstname": "[NAME-MASKED]"}, ("firstname",)),
    ("key-exp-month", {"exp_month": "value1"}, {"exp_month": "[EXPIRY-MASKED]"}, ("exp_month",)),
    ("key-expirationdate", {"expirationDate": "value1"}, {"expirationDate": "[EXPIRY-MASKED]"}, ("expirationDate",)),
    ("key-cardexpiry", {"cardExpiry": "value1"}, {"cardExpiry": "[EXPIRY-MASKED]"}, ("cardExpiry",)),
    ("key-nameoncard", {"nameOnCard": "value1"}, {"nameOnCard": "[NAME-MASKED]"}, ("nameOnCard",)),
    ("key-name-on-card", {"name_on_card": "value1"}, {"name_on_card": "[NAME-MASKED]"}, ("name_on_card",)),
    ("key-billing-address", {"billing_address": "value1"}, {"billing_address": "[ADDRESS-MASKED]"}, ("billing_address",)),
    ("key-customer-ref", {"customer_ref": "value1"}, {"customer_ref": "[GENERIC-MASKED]"}, ("customer_ref",)),
    # card, expiry and CVV keys mask in every service, pack or no pack
    (
        "key-card-fields-of-a-payment",
        {"card_number": "4111 1111 1111 1111", "expiry": "12/27", "cvv": "123"},
        {"card_number": "[CARD-MASKED:411111******1111]", "expiry": "[EXPIRY-MASKED]", "cvv": "[CVV-MASKED]"},
        ("card_number", "expiry", "cvv"),
    ),
    (
        "key-card-object-masked-whole",
        {"card": {"number": "4111111111111111", "expiry": {"month": "01", "year": "27"}}},
        {"card": "[CARD-MASKED]"},
        ("card",),
    ),
    ("key-card-without-a-number", {"pan": "n/a"}, {"pan": "[CARD-MASKED]"}, ("pan",)),
    # glued and plural spellings a payload uses
    ("key-nameoncard", {"nameoncard": "value1"}, {"nameoncard": "[NAME-MASKED]"}, ("nameoncard",)),
    ("key-customername", {"customername": "value1"}, {"customername": "[NAME-MASKED]"}, ("customername",)),
    ("key-accountholdername", {"accountholdername": "value1"}, {"accountholdername": "[NAME-MASKED]"}, ("accountholdername",)),
    ("key-addressline1", {"addressline1": "value1"}, {"addressline1": "[ADDRESS-MASKED]"}, ("addressline1",)),
    ("key-billingdetails", {"billingdetails": "value1"}, {"billingdetails": "[GENERIC-MASKED]"}, ("billingdetails",)),
    ("decimal-field-renders-as-text", {"amount": Decimal("100.000")}, {"amount": "100.000"}),
    # a PII container keeps its shape, and every leaf is masked on its own
    (
        "container-address-leaves",
        {"billing": {"line1": "1 Main St", "city": "Kuwait City", "zip": 12345}},
        {"billing": {"line1": "[GENERIC-MASKED]", "city": "[GENERIC-MASKED]", "zip": "[GENERIC-MASKED]"}},
        ("billing",),
    ),
    (
        "container-card-masked-whole",
        {"customer": {"id": 3, "card": {"number": "4111111111111111", "expiry": "12/27"}}},
        {"customer": {"id": 3, "card": "[CARD-MASKED]"}},
        ("customer", "card"),
    ),
    (
        "container-list-of-contacts",
        {"contacts": [{"name": "Jane", "email": "a@b.co"}]},
        {"contacts": [{"name": "[NAME-MASKED]", "email": "[EMAIL-MASKED]"}]},
        ("name", "email"),
    ),
    (
        "container-secret-masked-whole",
        {"credentials": {"user": "u", "password": "p"}},
        {"credentials": "[SECRET-MASKED]"},
        ("credentials",),
    ),
    ("container-empty-field-stays-empty", {"customer": {"id": 1, "image": None}}, {"customer": {"id": 1, "image": None}}),
    ("key-customer-name", {"customer_name": "John"}, {"customer_name": "[NAME-MASKED]"}, ("customer_name",)),
    # an int under a CVV key is the bare label, never a token, never the value
    ("key-cvv-int-under-a-container", {"source": {"securityCode": 123}}, {"source": {"securityCode": "[CVV-MASKED]"}}, ("securityCode",)),
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
    (
        "cvv-string-field",
        {"processed_data": {"cvv": "100"}},
        {"processed_data": {"cvv": "[CVV-MASKED]"}},
        ("cvv",),
    ),
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
    # already masked, so a second pass changes nothing
    ("marker-email-token", "[EMAIL-MASKED:ptok:v1:abc]"),
    # JSON text with no sensitive key and no sensitive content
    ("json-text-nothing-to-mask", '{"status":"ok","count":3}'),
    ("json-text-null-under-a-secret-key", 'body {"public_key": null, "a": 1}'),
    # "service" is ecsctx metadata at the top of a record only
    ("nested-service-key-is-ordinary", {"wrapper": {"service": "not really structural"}}),
    # words that only look sensitive
    ("key-namespace-unaffected", {"namespace": "value1"}),
    ("key-hostname-unaffected", {"hostname": "value1"}),
    ("key-filename-unaffected", {"filename": "value1"}),
    ("key-token-type-unaffected", {"token_type": "value1"}),
    ("key-card-id-unaffected", {"card_id": "value1"}),
    ("key-expires-in-unaffected", {"expires_in": "value1"}),
    ("key-cache-key-unaffected", {"cache_key": "value1"}),
    ("key-operation-unaffected", {"operation": "value1"}),
    ("key-sec-ch-ua-mobile-unaffected", {"Sec-Ch-Ua-Mobile": "value1"}),
    ("key-hotel-unaffected", {"hotel": "value1"}),
    ("key-hostel-unaffected", {"hostel": "value1"}),
    # a digit run touching letters is an id, not a phone number
    ("digits-then-hex-session-id", "8231045567ab34cd9f0e1a2b3c4d5e6f7a8b9c0d"),
    ("phone-shaped-run-glued-to-letters", "5551234567abc"),
    # order ids and timestamps a payment carries, none of them sensitive
    (
        "order-ids-and-timestamps",
        {"order": {"id": "deltabRKJ5X_0", "reference_number": "REF-2026-09187654"}, "timestamps": {"created": 1750000000}},
    ),
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


# ---------------------------------------------------------------------------
# A JSON object or list logged as a string gets the key-name rules a dict
# gets. Before, only the content rules saw it, so a cardholder name or an
# expiry date inside a callback body reached the index in clear.
# ---------------------------------------------------------------------------
JSON_TEXT_CASES = [
    ("json-text-secret-key", 'body {"session_key": 12345}', 'body {"session_key": "[SECRET-MASKED]"}', ("session_key",)),
    (
        "json-message-masked-by-key",
        '{"customer": {"nameOnCard": "Jane Payer"}}',
        '{"customer": {"nameOnCard": "[NAME-MASKED]"}}',
        ("customer", "nameOnCard"),
    ),
    # "log" is ecsctx metadata at the top of a record, not inside a payload
    (
        "json-message-under-a-record-skip-key",
        '{"log": {"nameOnCard": "Jane Payer"}}',
        '{"log": {"nameOnCard": "[NAME-MASKED]"}}',
        ("nameOnCard",),
    ),
    # a PSP callback body, as a gateway view logs it
    (
        "json-payload-name-camel",
        {"payload": '{"payer_details": {"nameOnCard": "Jane Payer"}, "status": "ok"}'},
        {"payload": '{"payer_details": {"nameOnCard": "[NAME-MASKED]"}, "status": "ok"}'},
        ("nameOnCard",),
    ),
    (
        "json-payload-name-snake",
        {"payload": '{"payer_details": {"name_on_card": "Jane Payer"}, "status": "ok"}'},
        {"payload": '{"payer_details": {"name_on_card": "[NAME-MASKED]"}, "status": "ok"}'},
        ("name_on_card",),
    ),
    (
        "json-payload-expiry-object",
        {"payload": '{"payer_details": {"expiry": {"month": "1", "year": "28"}}, "status": "ok"}'},
        {"payload": '{"payer_details": {"expiry": "[EXPIRY-MASKED]"}, "status": "ok"}'},
        ("expiry",),
    ),
    (
        "json-payload-expiry-month",
        {"payload": '{"payer_details": {"expiry_month": "01"}, "status": "ok"}'},
        {"payload": '{"payer_details": {"expiry_month": "[EXPIRY-MASKED]"}, "status": "ok"}'},
        ("expiry_month",),
    ),
    (
        "json-payload-expiry-year",
        {"payload": '{"payer_details": {"expiry_year": "39"}, "status": "ok"}'},
        {"payload": '{"payer_details": {"expiry_year": "[EXPIRY-MASKED]"}, "status": "ok"}'},
        ("expiry_year",),
    ),
]


# Plain stdlib logging, where the handler interpolates the arguments:
# (label, message, args, expected message, pack the case needs). Only a filter
# on the handler sees these — a structlog processor runs too late.
STDLIB_ARGS_CASES = [
    ("stdlib-email-arg", "user %s signed in", ("bob@example.com",), "user [EMAIL-MASKED] signed in", "default"),
    # a mapping arg, as logging's %(name)s form passes it
    (
        "stdlib-mapping-args",
        "login %(first_name)s pw=%(password)s",
        ({"first_name": "Jane", "password": "hunter2"},),
        "login [NAME-MASKED] pw=[SECRET-MASKED]",
        "default",
        ("first_name", "password"),
    ),
    ("stdlib-numeric-args-survive", "refunded %.3f of %d", (Decimal("12.5"), Decimal(3)), "refunded 12.500 of 3", "default"),
    ("stdlib-object-text-is-masked", "%s", (_Owner(),), "owner [EMAIL-MASKED]", "default"),
    ("stdlib-decimal-arg-holding-a-pan", "ref %s", (Decimal("4111111111111111"),), "ref [CARD-MASKED:411111******1111]", "pci"),
]


# Text an opt-in pack would mask, listed for the services that leave that pack
# off: (label, sample, the pack that must be off). Turning the pack on is what
# masks it, so the case runs only where it is off.
WITHOUT_PACK_CASES = [
    ("card-and-cvv-text-without-pci", "card 4111111111111111 cvv 123 HTTP 200 OK took 1500 ms", "pci"),
    ("iban-text-without-financial-ids", "iban GB33BUKB20201555555555", "financial_ids"),
    ("payment-id-key-without-financial-ids", {"transaction_id": "value1"}, "financial_ids"),
]


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
    "json_text": JSON_TEXT_CASES,
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
    "json_text": "default",
    "object_and_primitive": "pci",
}


def _holds_object(value) -> bool:
    if isinstance(value, dict):
        return any(_holds_object(v) for v in value.values())
    if isinstance(value, list):
        return any(_holds_object(v) for v in value)
    return isinstance(value, _FakeCard)


# The key names in these tables a service may list in ECSCTX_MASK_SAFE_KEYS.
# The rest name a card, CVV, expiry or credential, which
# ecsctx.masking.patterns.never_safe() refuses. Set them all to see every
# safe-key skip fire at once.
SAFE_LISTABLE_KEYS = (
    "payment_id",
    "transaction_id",
    "auth_id",
    "email",
    "phone",
    "mobile",
    "tel",
    "address",
    "name",
    "cardholder",
    "beneficiary",
    "recipient",
    "payer",
    "billing",
    "shipping",
    "customer",
    "contact",
    "udf",
)


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
