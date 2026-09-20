"""Masking sample tables, shipped so a project can run them against its own logging.

Each case is (label, sample, expected). A string sample is logged as the event
message; a dict sample is logged as one kwarg. The tables are ported from
ecsctx's own filter tests, so a project checks the same cases ecsctx does, but
through its real handlers, filters, formatter and exemptions.

Expected values are the bare [LABEL] form, which is what a project without PII
tokenization configured emits. With PII configured the same cases come out as
[LABEL:ptok:v1:…]; the test helper compares them with the token removed.
"""


class SampleCard:
    """Stand-in for a model whose repr embeds a PAN."""

    def __repr__(self) -> str:
        return "<Card(VISA, 512345******0008, 9584184138614802)>"


def pem(kind: str, body: str) -> str:
    return f"-----BEGIN {kind}-----\n{body}\n-----END {kind}-----"


JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.abc123def456ghi"
HEX = "1a2b3c4d5e6f7a8b9c0d1e2f"


PEM_CASES = [
    ("pem-private-key", pem("PRIVATE KEY", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"), "[PEM-KEY-MASKED]"),
    ("pem-rsa-private-key", pem("RSA PRIVATE KEY", "MIIEpAIBAAKCAQEA0abcDEF"), "[PEM-KEY-MASKED]"),
    ("pem-ec-private-key", pem("EC PRIVATE KEY", "MHcCAQEEIABxYZec012private"), "[PEM-KEY-MASKED]"),
    ("pem-public-key", pem("PUBLIC KEY", "MIIBIjANBgkqhkiG9w0pubKEY"), "[PEM-KEY-MASKED]"),
    ("pem-rsa-public-key", pem("RSA PUBLIC KEY", "MEgCQQCrsaPUBLICkeyXYZ"), "[PEM-KEY-MASKED]"),
]

CREDENTIAL_CASES = [
    ("cred-single-quoted-colon", "'token': 'abcd1234'", "'token': '[SECRET-MASKED]'"),
    ("cred-single-quoted-colon-tight", "'token':'abcd1234'", "'token':'[SECRET-MASKED]'"),
    ("cred-double-quoted-colon", '"token": "abcd1234"', '"token": "[SECRET-MASKED]"'),
    ("cred-double-quoted-colon-tight", '"token":"abcd1234"', '"token":"[SECRET-MASKED]"'),
    ("cred-colon", "token: abcd1234", "token: [SECRET-MASKED]"),
    ("cred-colon-tight", "token:abcd1234", "token:[SECRET-MASKED]"),
    ("cred-equals", "token= abcd1234", "token= [SECRET-MASKED]"),
    ("cred-equals-tight", "token=abcd1234", "token=[SECRET-MASKED]"),
    ("cred-equals-single-digit", "token=1", "token=[SECRET-MASKED]"),
    ("cred-equals-single-char", "token=a", "token=[SECRET-MASKED]"),
    ("cred-colon-single-digit", "token: 1", "token: [SECRET-MASKED]"),
    ("cred-colon-single-char", "token: a", "token: [SECRET-MASKED]"),
    ("cred-colon-hex", f"token:{HEX}", "token:[SECRET-MASKED]"),
    ("cred-equals-hex", f"token={HEX}", "token=[SECRET-MASKED]"),
    ("cred-colon-jwt", f"token:{JWT}", "token:[SECRET-MASKED]"),
    ("cred-equals-jwt", f"token={JWT}", "token=[SECRET-MASKED]"),
    ("cred-space-hex", f"token {HEX}", "token [SECRET-MASKED]"),
    ("cred-space-jwt", f"token {JWT}", "token [SECRET-MASKED]"),
    ("cred-space-8chars-4digits", "token abcd1234", "token [SECRET-MASKED]"),
    ("cred-short-token-equals-in-sentence", "message token=1", "message token=[SECRET-MASKED]"),
    ("cred-token", "token abcd1234", "token [SECRET-MASKED]"),
    ("cred-anyword_token", "anyword_token abcd1234", "anyword_token [SECRET-MASKED]"),
    ("cred-any_word_token", "any_word_token abcd1234", "any_word_token [SECRET-MASKED]"),
    ("cred-any-word_token", "any-word_token abcd1234", "any-word_token [SECRET-MASKED]"),
    ("cred-any-word-token", "any-word-token abcd1234", "any-word-token [SECRET-MASKED]"),
    ("cred-any_1-word_2-token", "any_1-word_2-token abcd1234", "any_1-word_2-token [SECRET-MASKED]"),
    ("cred-secret", "secret abcd1234", "secret [SECRET-MASKED]"),
    ("cred-any_1-word_2-secret", "any_1-word_2-secret abcd1234", "any_1-word_2-secret [SECRET-MASKED]"),
    ("cred-password", "password abcd1234", "password [SECRET-MASKED]"),
    ("cred-any_1-word_2-password", "any_1-word_2-password abcd1234", "any_1-word_2-password [SECRET-MASKED]"),
    ("cred-passwd", "passwd abcd1234", "passwd [SECRET-MASKED]"),
    ("cred-any_1-word_2-passwd", "any_1-word_2-passwd abcd1234", "any_1-word_2-passwd [SECRET-MASKED]"),
    ("cred-bearer", "bearer abcd1234", "bearer [SECRET-MASKED]"),
    ("cred-basic", "basic abcd1234", "basic [SECRET-MASKED]"),
    ("cred-digest", "digest abcd1234", "digest [SECRET-MASKED]"),
    ("cred-credential", "credential abcd1234", "credential [SECRET-MASKED]"),
    ("cred-credentials", "credentials abcd1234", "credentials [SECRET-MASKED]"),
    ("cred-authorization", "authorization abcd1234", "authorization [SECRET-MASKED]"),
    ("cred-authorization_header", "authorization_header abcd1234", "authorization_header [SECRET-MASKED]"),
    ("cred-authorization-header", "authorization-header abcd1234", "authorization-header [SECRET-MASKED]"),
    ("cred-authorisation", "authorisation abcd1234", "authorisation [SECRET-MASKED]"),
    ("cred-authorisation_header", "authorisation_header abcd1234", "authorisation_header [SECRET-MASKED]"),
    ("cred-authorisation-header", "authorisation-header abcd1234", "authorisation-header [SECRET-MASKED]"),
    ("cred-apikey", "apikey abcd1234", "apikey [SECRET-MASKED]"),
    ("cred-api_key", "api_key abcd1234", "api_key [SECRET-MASKED]"),
    ("cred-api-key", "api-key abcd1234", "api-key [SECRET-MASKED]"),
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
    ("cred-numeric-secret-in-card-digit-range", "secret_key=1234567890123456", "secret_key=[SECRET-MASKED]"),
    ("auth-header-line-single-quotes", f"'Authorization': 'Bearer {JWT}'", "'Authorization': '[SECRET-MASKED]'"),
    ("auth-header-line-double-quotes", f'"Authorization": "Bearer {JWT}"', '"Authorization": "[SECRET-MASKED]"'),
    ("auth-header-line-colon", f"Authorization: Bearer {JWT}", "Authorization: [SECRET-MASKED] [JWT-MASKED]"),
    ("auth-header-line-equal", f"Authorization= Bearer {JWT}", "Authorization= [SECRET-MASKED] [JWT-MASKED]"),
    ("auth-header-line-space", f"Authorization Bearer {JWT}", "Authorization Bearer [SECRET-MASKED]"),
    ("auth-header-quoted-kv", f'{{"Authorization": "{HEX}"}}', '{"Authorization": "[SECRET-MASKED]"}'),
    ("auth-header-quoted-kv-in-sentence", f'Here is {{"Authorization": "{HEX}"}}', 'Here is {"Authorization": "[SECRET-MASKED]"}'),
    ("auth-dict-value-with-spaces", f'{{"Authorization": "Bearer {HEX} more"}}', '{"Authorization": "[SECRET-MASKED]"}'),
    ("authorization-raw-colon", f"Authorization: {HEX}abcd", "Authorization: [SECRET-MASKED]"),
    ("authorisation-raw-dict", f'{{"Authorisation": "{HEX}abcd"}}', '{"Authorisation": "[SECRET-MASKED]"}'),
    (
        "auth-inside-headers-dict-apikey",
        {"headers": {"Authorization": f"API-Key {HEX}"}},
        {"headers": {"Authorization": "[SECRET-MASKED]"}},
    ),
    (
        "auth-inside-headers-dict-bearer",
        {"headers": {"Authorization": f"Bearer {JWT}"}},
        {"headers": {"Authorization": "[SECRET-MASKED]"}},
    ),
    (
        "auth-inside-headers-dict-token",
        {"headers": {"Authorization": "token abcd 1234 anything"}},
        {"headers": {"Authorization": "[SECRET-MASKED]"}},
    ),
    (
        "auth-interpolated-in-message",
        f"Authentication failed with key 'API-Key {HEX}'",
        "Authentication failed with key 'API-Key [SECRET-MASKED]'",
    ),
    ("access_token-kv", "access_token=abcd1234efgh5678", "access_token=[SECRET-MASKED]"),
    ("refresh_token-kv", "refresh_token=abcd1234efgh5678", "refresh_token=[SECRET-MASKED]"),
    ("client_secret-kv", "client_secret=sk_live_abcd1234ef", "client_secret=[SECRET-MASKED]"),
    ("private_key-kv", "private_key=abcd1234efgh5678", "private_key=[SECRET-MASKED]"),
    ("secret_key-kv", "secret_key=abcd1234efgh5678", "secret_key=[SECRET-MASKED]"),
    ("auth-basic-equals", f"basic= {HEX}", "basic= [SECRET-MASKED]"),
    ("auth-api-key-value", f"API-Key {HEX}", "API-Key [SECRET-MASKED]"),
    ("auth-basic-value", "Basic dXNlcjpwYXNzd29yZA==", "Basic [SECRET-MASKED]"),
]

CVV_CASES = [
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
    ("cvv-dict-obj", {"processed_data": {"cvv": "100"}}, {"processed_data": {"cvv": "[CVV-MASKED]"}}),
    (
        "cvv-dict-obj-long",
        {"processed_data": {"cvv": "not a cvv shape 123456789"}},
        {"processed_data": {"cvv": "[CVV-MASKED]"}},
    ),
    (
        "cvv-quoted-inside-json-string",
        '{"processed_data": {"cvv": "100"}}',
        '{"processed_data": {"cvv": "[CVV-MASKED]"}}',
    ),
]

PAYMENT_ID_CASES = [
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

IBAN_CASES = [
    ("iban", "account GB33BUKB20201555555555 credited", "account [IBAN-MASKED] credited"),
    ("iban-be-digit-run-collision", "acct BE68539007547034 debited", "acct [IBAN-MASKED] debited"),
    ("iban-fr-digit-run-collision", "acct FR1420041010050500013M02606 debited", "acct [IBAN-MASKED] debited"),
    ("iban-bh-digit-run-collision", "acct BH67BMAG00001299123456 debited", "acct [IBAN-MASKED] debited"),
    ("iban-qa-digit-run-collision", "acct QA58DOHB00001234567890ABCDEFG debited", "acct [IBAN-MASKED] debited"),
    ("iban-digit-run-13-just-over-card-floor", "acct GB1212345678901 debited", "acct [IBAN-MASKED] debited"),
    ("iban-digit-run-16-classic-pan-length", "acct GB3412345678901234 debited", "acct [IBAN-MASKED] debited"),
    ("iban-digit-run-19-top-of-card-range", "acct GB5612345678901234567 debited", "acct [IBAN-MASKED] debited"),
    ("iban-digit-run-20-past-card-range", "acct GB78123456789012345678 debited", "acct [IBAN-MASKED] debited"),
]

PHONE_CASES = [
    ("phone-local-space-separators", "091 234 5678", "[PHONE-MASKED]"),
    ("phone-local-dash-space-mixed", "091-234 5678", "[PHONE-MASKED]"),
    ("phone-local-space-dash-mixed", "091 234-5678", "[PHONE-MASKED]"),
    ("phone-local-dash-separators", "091-234-5678", "[PHONE-MASKED]"),
    ("phone-intl-plus-no-separators", "+963912345678", "[PHONE-MASKED]"),
    ("phone-intl-plus-space-after-code", "+963 912345678", "[PHONE-MASKED]"),
    ("phone-intl-plus-dash-after-code", "+963-912345678", "[PHONE-MASKED]"),
    ("phone-intl-country-code-in-card-digit-range", "call +44-555-123-4567 now", "call [PHONE-MASKED] now"),
    ("phone-intl-3digit-country-code-in-card-digit-range", "call +971-555-123-4567 now", "call [PHONE-MASKED] now"),
]

EMAIL_CASES = [
    ("email-plain", "user@example.com", "[EMAIL-MASKED]"),
    ("email-in-sentence", "contact john.doe@example.com now", "contact [EMAIL-MASKED] now"),
    ("email-mixed-case", "User.Name+tag@Example.CO.UK", "[EMAIL-MASKED]"),
    ("email-subdomain", "first.last@sub.domain.example.com", "[EMAIL-MASKED]"),
    ("email-underscore-local-part", "user_name@example.com", "[EMAIL-MASKED]"),
    ("email-hyphen-local-part", "user-name@example.com", "[EMAIL-MASKED]"),
    ("email-hyphenated-domain", "user@sub-domain.example.co.uk", "[EMAIL-MASKED]"),
    ("email-plus-tag-local-part", "disposable.style.email.with+symbol@example.com", "[EMAIL-MASKED]"),
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
    # "contact" is itself a sensitive key, so the whole subtree is replaced
    # rather than recursed into.
    ("email-under-sensitive-parent-key", {"contact": {"email": "user@example.com"}}, {"contact": "[GENERIC-MASKED]"}),
]

JWT_CASES = [
    ("jwt-standalone", JWT, "[JWT-MASKED]"),
    ("jwt-in-sentence-space-bounded", f"Here it's {JWT} failed!", "Here it's [JWT-MASKED] failed!"),
    ("jwt-in-sentence-parens-wrapped", f"Here it's ({JWT}) failed!", "Here it's ([JWT-MASKED]) failed!"),
    ("jwt-in-sentence-colon-prefixed", f"Here it's: {JWT} failed!", "Here it's: [JWT-MASKED] failed!"),
    ("jwt-hyphen-prefixed", f"-{JWT}", "-[JWT-MASKED]"),
    ("jwt-dot-prefixed", f".{JWT}", ".[JWT-MASKED]"),
    ("jwt-suffix-letter-swallowed", f"{JWT}abc", "[JWT-MASKED]"),
    ("jwt-suffix-digit-swallowed", f"{JWT}123", "[JWT-MASKED]"),
    ("jwt-suffix-underscore-swallowed", f"{JWT}_more", "[JWT-MASKED]"),
    ("jwt-suffix-hyphen-swallowed", f"{JWT}-more", "[JWT-MASKED]"),
    ("jwt-suffix-swallowed-in-sentence", f"token was {JWT}extra and more", "token was [JWT-MASKED] and more"),
]

CARD_CASES = [
    ("card-12d-9-continuous", "912345678912", "[CARD-MASKED]"),
    ("card-13d-9-continuous", "9123456789123", "[CARD-MASKED]"),
    ("card-14d-9-continuous", "91234567891234", "[CARD-MASKED]"),
    ("card-15d-9-continuous", "912345678912345", "[CARD-MASKED]"),
    ("card-16d-9-continuous", "9123456789123456", "[CARD-MASKED]"),
    ("card-17d-9-continuous", "91234567891234567", "[CARD-MASKED]"),
    ("card-18d-9-continuous", "912345678912345678", "[CARD-MASKED]"),
    ("card-19d-9-continuous", "9123456789123456789", "[CARD-MASKED]"),
    ("card-12d-9-space", "9123 4567 8912", "[CARD-MASKED]"),
    ("card-13d-9-space", "9123 4567 8912 3", "[CARD-MASKED]"),
    ("card-14d-9-space", "9123 4567 8912 34", "[CARD-MASKED]"),
    ("card-15d-9-space", "9123 4567 8912 345", "[CARD-MASKED]"),
    ("card-16d-9-space", "9123 4567 8912 3456", "[CARD-MASKED]"),
    ("card-17d-9-space", "9123 4567 8912 34567", "[CARD-MASKED]"),
    ("card-18d-9-space", "9123 4567 8912 345678", "[CARD-MASKED]"),
    ("card-19d-9-space", "9123 4567 8912 3456789", "[CARD-MASKED]"),
    ("card-12d-9-dash", "9123-4567-8912", "[CARD-MASKED]"),
    ("card-13d-9-dash", "9123-4567-8912-3", "[CARD-MASKED]"),
    ("card-14d-9-dash", "9123-4567-8912-34", "[CARD-MASKED]"),
    ("card-15d-9-dash", "9123-4567-8912-345", "[CARD-MASKED]"),
    ("card-16d-9-dash", "9123-4567-8912-3456", "[CARD-MASKED]"),
    ("card-17d-9-dash", "9123-4567-8912-34567", "[CARD-MASKED]"),
    ("card-18d-9-dash", "9123-4567-8912-345678", "[CARD-MASKED]"),
    ("card-19d-9-dash", "9123-4567-8912-3456789", "[CARD-MASKED]"),
    ("card-12d-other-continuous", "112345678912", "[CARD-MASKED]"),
    ("card-13d-other-continuous", "1123456789123", "[CARD-MASKED]"),
    ("card-14d-other-continuous", "11234567891234", "[CARD-MASKED]"),
    ("card-15d-other-continuous", "112345678912345", "[CARD-MASKED]"),
    ("card-16d-other-continuous", "1123456789123456", "[CARD-MASKED]"),
    ("card-17d-other-continuous", "11234567891234567", "[CARD-MASKED]"),
    ("card-18d-other-continuous", "112345678912345678", "[CARD-MASKED]"),
    ("card-19d-other-continuous", "1123456789123456789", "[CARD-MASKED]"),
    ("card-12d-other-space", "11234 56 78912", "[CARD-MASKED]"),
    ("card-13d-other-space", "11234 56 789123", "[CARD-MASKED]"),
    ("card-14d-other-space", "11234 56 7891234", "[CARD-MASKED]"),
    ("card-15d-other-space", "11234 56 78912345", "[CARD-MASKED]"),
    ("card-16d-other-space", "11234 56 789123456", "[CARD-MASKED]"),
    ("card-17d-other-space", "11234 56 7891234567", "[CARD-MASKED]"),
    ("card-18d-other-space", "11234 56 78912345678", "[CARD-MASKED]"),
    ("card-19d-other-space", "11234 56 789123456789", "[CARD-MASKED]"),
    ("card-12d-other-dash", "1123-4567-8912", "[CARD-MASKED]"),
    ("card-13d-other-dash", "1123-4567-8912-3", "[CARD-MASKED]"),
    ("card-14d-other-dash", "1123-4567-8912-34", "[CARD-MASKED]"),
    ("card-15d-other-dash", "1123-4567-8912-345", "[CARD-MASKED]"),
    ("card-16d-other-dash", "1123-4567-8912-3456", "[CARD-MASKED]"),
    ("card-17d-other-dash", "1123-4567-8912-34567", "[CARD-MASKED]"),
    ("card-18d-other-dash", "1123-4567-8912-345678", "[CARD-MASKED]"),
    ("card-19d-other-dash", "1123-4567-8912-3456789", "[CARD-MASKED]"),
    ("card-2groups-9-space", "90345 67812901256", "[CARD-MASKED]"),
    ("card-2groups-9-dash", "90345-67812901256", "[CARD-MASKED]"),
    ("card-2groups-other-space", "10345 67812901256", "[CARD-MASKED]"),
    ("card-2groups-other-dash", "10345-67812901256", "[CARD-MASKED]"),
    ("card-3groups-9-space", "90345 678129012 90345", "[CARD-MASKED]"),
    ("card-3groups-9-dash", "90345-678129012-90345", "[CARD-MASKED]"),
    ("card-3groups-other-space", "10345 678129012 10345", "[CARD-MASKED]"),
    ("card-3groups-other-dash", "10345-678129012-10345", "[CARD-MASKED]"),
    ("card-5groups-9-space", "90345 678 1290 12 56789", "[CARD-MASKED]"),
    ("card-5groups-9-dash", "90345-678-1290-12-56789", "[CARD-MASKED]"),
    ("card-5groups-other-space", "40345 678 1290 12 56789", "[CARD-MASKED]"),
    ("card-5groups-other-dash", "40345-678-1290-12-56789", "[CARD-MASKED]"),
    ("card-2-mixed-separator-9", "9034-5678 1290", "[CARD-MASKED]"),
    ("card-3-mixed-separator-9", "9034-5678 1290-125", "[CARD-MASKED]"),
    ("card-4-mixed-separator-9", "9034-5678 1290-1256 125", "[CARD-MASKED]"),
    ("card-2-mixed-separator-other", "4034-5678 1290", "[CARD-MASKED]"),
    ("card-3-mixed-separator-other", "4034-5678 1290-125", "[CARD-MASKED]"),
    ("card-4-mixed-separator-other", "4034-5678 1290-1256 125", "[CARD-MASKED]"),
    ("card-19d-9-space-prefixed-in-sentence", "Here is 9123456789123456789 card Number", "Here is [CARD-MASKED] card Number"),
    ("card-19d-9-paren-prefixed-in-sentence", "Here is (9123456789123456789) card Number", "Here is ([CARD-MASKED]) card Number"),
    ("card-19d-9-bracket-prefixed-in-sentence", "Here is [9123456789123456789] card Number", "Here is [[CARD-MASKED]] card Number"),
    ("card-19d-9-brace-prefixed-in-sentence", "Here is {9123456789123456789} card Number", "Here is {[CARD-MASKED]} card Number"),
    ("card-19d-9-colon-prefixed-in-sentence", "Here num:9123456789123456789 card Number", "Here num:[CARD-MASKED] card Number"),
    ("card-19d-9-equals-prefixed-in-sentence", "Here num=9123456789123456789 card Number", "Here num=[CARD-MASKED] card Number"),
    ("card-19d-9-comma-prefixed-in-sentence", "Here num,9123456789123456789 card Number", "Here num,[CARD-MASKED] card Number"),
    ("card-19d-9-dot-prefixed-in-sentence", "Here num.9123456789123456789 card Number", "Here num.[CARD-MASKED] card Number"),
    ("card-12d-other-space-4x4", "1123 4567 8912", "[CARD-MASKED]"),
    ("card-15d-other-space-4x4", "1123 4567 8912 345", "[CARD-MASKED]"),
    ("card-16d-other-space-4x4", "1123 4567 8912 3456", "[CARD-MASKED]"),
    ("card-17d-other-space-4x4", "1123 4567 8912 34567", "[CARD-MASKED]"),
    ("card-19d-other-space-4x4", "1123 4567 8912 3456789", "[CARD-MASKED]"),
    # trailing chunk is phone-shaped (10 bare digits): the phone rule runs
    # first, so the card rule needs its guard to still claim the full PAN.
    ("card-17d-space-trailing-chunk-is-phone-shaped", "11234 56 7891234567", "[CARD-MASKED]"),
    ("card-plain-pan-never-reveals-bin-or-last4", "4111111111111111", "[CARD-MASKED]"),
]

SSN_CASES = [
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

DICT_KEY_CASES = [
    (
        "key-token-string-value",
        {"action": "create payment", "token": "abcd1234"},
        {"action": "create payment", "token": "[SECRET-MASKED]"},
    ),
    ("key-cvv-int-value", {"cvv": 123}, {"cvv": "[CVV-MASKED]"}),
    ("key-cvv-string-value", {"cvv": "123"}, {"cvv": "[CVV-MASKED]"}),
    ("key-session-key-int-value", {"session_key": 12345}, {"session_key": "[SECRET-MASKED]"}),
    ("key-access-token-none-value", {"access_token": None}, {"access_token": "[SECRET-MASKED]"}),
    ("key-mixed-case-cvv", {"Cvv": "123"}, {"Cvv": "[CVV-MASKED]"}),
    ("key-camelcase-security-code-int", {"securityCode": 999}, {"securityCode": "[CVV-MASKED]"}),
    (
        "key-nested-under-sensitive-key-blanket-masked",
        {"data": {"token": {"nested": "stuff", "more": 1}}},
        {"data": {"token": "[SECRET-MASKED]"}},
    ),
]

OBJECT_AND_PRIMITIVE_CASES = [
    (
        "object-repr-pan-masked",
        {"card": SampleCard()},
        {"card": "<Card(VISA, 512345******0008, [CARD-MASKED])>"},
    ),
    (
        "object-nested-in-list-and-dict",
        {"data": {"cards": [{"instrument": SampleCard()}]}},
        {"data": {"cards": [{"instrument": "<Card(VISA, 512345******0008, [CARD-MASKED])>"}]}},
    ),
    (
        "numeric-primitives-not-mangled",
        {"status_code": 200, "count": 100, "ok": True, "nothing": None},
        {"status_code": 200, "count": 100, "ok": True, "nothing": None},
    ),
    ("plain-string-message-with-pan", "card 5123 4500 0000 0008", "card [CARD-MASKED]"),
]

# Values that must come through untouched — guards against over-masking.
NOT_MASKED_CASES = [
    ("cache-key", "cache_key=user_profile_v2"),
    ("sort-key", "sort_key=created_at_desc"),
    ("primary-key", "primary_key=customer_00042"),
    ("partition-key", "partition_key=eu_west_1a"),
    ("prose-basic", "Basic authentication required"),
    ("prose-bearer", "the bearer of this message"),
    ("prose-token", "token expired, please retry"),
    ("cred-char-session-id-unaffected", "session_id=abcdefghijklmn"),
    ("cred-both-session-id-unaffected", "session_id=6ea04d6db060f7ce414b6f5faa7119161e2214bc"),
    ("iban-fake-country", "order AB12CDEF3456GH78 shipped"),
    ("iban-non-iban-country", "ref US12INVOICE0000042 paid"),
    ("iban-lowercase", "acct gb33bukb20201555 done"),
    ("card-dot-separated-not-a-real-pan-format", "4111.1111.1111.1111"),
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
    ("email-no-tld-dot", "user@localhost"),
    ("email-trailing-dot-no-tld", "user@example."),
    ("email-no-domain-before-dot", "user@.com"),
    ("email-no-local-part", "@example.com"),
    ("email-no-domain", "user@"),
    ("email-single-char-tld", "user@example.c"),
    ("key-cache-key-unaffected", {"cache_key": "user_profile_v2"}),
]

# Sensitive-looking values a guard deliberately lets through. Settled
# decisions, not bugs — listed so a project sees them rather than assuming
# they are covered.
ACCEPTED_LEAK_CASES = [
    ("cred-space-value-no-digit-unmasked", "Bearer abcdefghij"),
    ("cred-glued-no-separator-unmasked", "token12345"),
    ("card-glued-to-letters-leading-9-unaffected", "REF9111111111111111 confirmed"),
    ("card-glued-to-letters-leading-other-unaffected", "REF4111111111111111 confirmed"),
    ("card-19d-9-preceded-by-digit-space-unaffected", "point 1 9123456789123456789"),
    ("card-19d-other-preceded-by-digit-space-unaffected", "point 1 1234567891234567891"),
    ("jwt-glued-to-letter-prefix-unmasked", f"abc{JWT}"),
    ("jwt-glued-to-digit-prefix-unmasked", f"123{JWT}"),
    ("jwt-glued-to-underscore-prefix-unmasked", f"_{JWT}"),
    ("phone-glued-plus-to-letter-unmasked", "call+963912345678"),
]

MASKED_GROUPS = {
    "pem": PEM_CASES,
    "credential": CREDENTIAL_CASES,
    "cvv": CVV_CASES,
    "payment_id": PAYMENT_ID_CASES,
    "iban": IBAN_CASES,
    "phone": PHONE_CASES,
    "email": EMAIL_CASES,
    "jwt": JWT_CASES,
    "card": CARD_CASES,
    "ssn": SSN_CASES,
    "dict_key": DICT_KEY_CASES,
    "object_and_primitive": OBJECT_AND_PRIMITIVE_CASES,
}

UNCHANGED_GROUPS = {
    "not_masked": NOT_MASKED_CASES,
    "accepted_leaks": ACCEPTED_LEAK_CASES,
}
