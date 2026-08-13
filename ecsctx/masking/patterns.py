"""Content and key-name rules for MaskPIIFilter.

Ported from ottu_pg's MaskPIIFilter (utils/log/filters.py), merged with
ecsctx's own PII key-name list. Two independent detection strategies:

1. Content-based (CONTENT_RULES): 19 ordered regexes applied to every string
   the filter reaches. Rule order is load-bearing — see the comments on each
   rule and the ordering invariants they protect. Do not reorder.
2. Key-based (key_label): in a dict, a key that is itself a sensitive keyword
   masks the whole value outright, regardless of the value's type or content.
   This is what catches structlog kwargs (log.info("x", token="abcd1234")),
   where the key and value never appear together in one string for a regex
   to match.

Every masked value becomes `[LABEL]` or `[LABEL:token]` via mask_by_label —
never a bare `***`. CVV is the one exception: it must never carry a token,
not even an HMAC digest, because PCI forbids storing CVV in any form.
"""

from __future__ import annotations

import re

from ecsctx.masking.tokens import mask

# ---------------------------------------------------------------------------
# Shared keyword/value fragments
# ---------------------------------------------------------------------------

SAFE_KEYS = frozenset({
    "gateway_name",
    "vendor_name",
    "module_name",
    "func_name",
    "task_name",
    "service_name",
    "app_name",
    "project_name",
    "class_name",
    "method_name",
    "view_name",
    "username",  # username usually safe/auditable
    "site_name",
    "domain_name",
    "bank_name",
    "display_name",
    "install_name",
    "installation_name",
    "event_name",
    "pathname",  # structlog CallsiteParameterAdder's source-file path, not PII
    "customer_id",
    "id",
    "pk",
})

# Sensitive credential keywords / auth schemes. Matched case-insensitively.
# Bare "key" is intentionally excluded — only sensitive *_key compounds — so
# cache_key / sort_key / primary_key are not over-masked.
_CRED_KEYWORD = (
    r"(?:"
    r"bearer|basic|digest|credentials?"  # auth schemes
    r"|authori[sz]ation(?:[_-]?header)?"  # Authorization / Authorisation (+ _header)
    r"|(?:[\w-]*[_-])?(?:token|secret|password|passwd)"  # *_token / *_secret / *_password
    r"|(?:secret|private|public|encryption|decryption|signing|"  # sensitive *_key compounds only
    r"access|master|root|session|api)[_-]?key"
    r")"
)

# Card verification code keywords — cvv/cvc/security code are all the same
# thing under different names depending on card scheme/vendor terminology.
_CVV_KEYWORD = r"(?:cvv|cvc|security[_\s]?code)"

# Payment/transaction/auth id keywords.
_PAYMENT_ID_KEYWORD = r"(?:payment|transaction|auth)[_\s-]?id"

_EMAIL_KEY_WORDS = r"email"

_PHONE_KEY_WORDS = r"phone|mobile|tel"

_ADDRESS_KEY_WORDS = r"address"

_NAME_KEY_WORDS = r"name|cardholder|beneficiary|recipient|payer"

_GENERIC_PII_KEY_WORDS = r"billing|shipping|customer|contact|udf"




# Credential value characters: token / base64url / JWT / hex (no whitespace).
_CRED_VALUE = r"[A-Za-z0-9._~+/\-]"

# ISO country codes in the SWIFT IBAN registry, as a regex alternation.
_IBAN_PREFIX = (
    "AD|AE|AL|AT|AZ|BA|BE|BG|BH|BR|BY|CH|CR|CY|CZ|DE|DK|DO|EE|EG|ES|FI|FO|FR|"
    "GB|GE|GI|GL|GR|GT|HR|HU|IE|IL|IQ|IS|IT|JO|KW|KZ|LB|LC|LI|LT|LU|LV|LY|MC|"
    "MD|ME|MK|MR|MT|MU|NL|NO|PK|PL|PS|PT|QA|RO|RS|SA|SC|SD|SE|SI|SK|SM|ST|SV|"
    "TL|TN|TR|UA|VA|VG|XK"
)

# Card number rules, shared building blocks. Real-world PANs range 12-19
# digits (ISO/IEC 7812 caps at 19; Maestro issues from 12). Only dash and
# space count as real-world separators.
#
# _CARD_LEAD_GUARD: a match may only start right after a real prefix (quote,
# "([{", ":", "=", space, comma, dot, or start-of-string), not mid-digit-run
# or glued to a letter. The extra (?<!\d ) blocks a space that's itself
# preceded by a digit, so a differently-grouped longer number's tail chunk
# isn't mistaken for a fresh match.
# _CARD_TAIL_GUARD: a match may not be followed by more digits.
_CARD_LEAD_GUARD = r"(?:^|(?<=[\s,.:=\"'([{]))(?<!\d )"
_CARD_TAIL_GUARD = r"(?![-\s]?\d)"
# 11 more digits after the leading one = 12 total; 18 more = 19 total.
_CARD_BODY = r"(?:[-\s]?\d){11,18}"


def _digits_only(text: str) -> str:
    return "".join(c for c in text if c.isdigit())


# ---------------------------------------------------------------------------
# Callables that turn a match into a labeled, tokenized replacement
# ---------------------------------------------------------------------------


def _mask_partial_pan(match: re.Match) -> str:
    """Reveal the first 6 digits (BIN) and last 4, mask the middle with a
    label carrying a token computed over the digits only (separators
    stripped), so `4111 1111 1111 1111` and `4111111111111111` produce the
    same token.

    Only fires cleanly for a single, consistent separator (or none at all):
    if more than one separator character is used, the match is returned
    unchanged so the fallback rule (which always fully masks) catches it
    instead — a mixed separator means the BIN's position can no longer be
    trusted.
    """
    text = match.group(0)
    seps = {c for c in text if c in " -"}
    if len(seps) > 1:
        return text
    digit_idx = [i for i, c in enumerate(text) if c.isdigit()]
    bin_end = digit_idx[5]
    tail_start = digit_idx[len(digit_idx) - 4]
    label = mask(_digits_only(text), "card")
    return text[: bin_end + 1] + label + text[tail_start:]


def _mask_full_card(match: re.Match) -> str:
    return mask(_digits_only(match.group(0)), "card")


def _mask_pem(match: re.Match) -> str:
    """Token computed over the base64 body only — strip the BEGIN/END lines
    and all whitespace first, so the same key re-wrapped at a different line
    width (or with CRLF instead of LF) still produces the same token.
    """
    body = match.group(0)
    stripped = re.sub(r"-----(BEGIN|END)[^-]*-----", "", body)
    stripped = re.sub(r"\s+", "", stripped)
    return mask(stripped, "pem_key")


def _cred_quoted(m: re.Match) -> str:
    q, kw, sep, val = m.group(1), m.group(2), m.group(3), m.group(4)
    return f"{q}{kw}{q}{sep}{q}{mask(val, 'secret')}{q}"


def _cred_kv(m: re.Match) -> str:
    prefix, val = m.group(1), m.group(2)
    return f"{prefix}{mask(val, 'secret')}"


def _cred_space(m: re.Match) -> str:
    kw, val = m.group(1), m.group(2)
    return f"{kw} {mask(val, 'secret')}"


def _cvv_quoted(m: re.Match) -> str:
    q, kw, sep = m.group(1), m.group(2), m.group(3)
    return f"{q}{kw}{q}{sep}{q}{mask('', 'cvv')}{q}"


def _cvv_kv(m: re.Match) -> str:
    return f"{m.group(1)}{mask('', 'cvv')}"


def _cvv_space(m: re.Match) -> str:
    return f"{m.group(1)} {mask('', 'cvv')}"


def _standalone_cvv(_m: re.Match) -> str:
    return mask('', 'cvv')


def _payid_quoted(m: re.Match) -> str:
    q, kw, sep, val = m.group(1), m.group(2), m.group(3), m.group(4)
    return f"{q}{kw}{q}{sep}{q}{mask(val, 'payment_id')}{q}"


def _payid_kv(m: re.Match) -> str:
    prefix, val = m.group(1), m.group(2)
    return f"{prefix}{mask(val, 'payment_id')}"


def _payid_space(m: re.Match) -> str:
    kw, val = m.group(1), m.group(2)
    return f"{kw} {mask(val, 'payment_id')}"


def _iban(m: re.Match) -> str:
    return mask(m.group(0), "iban")


def _phone(m: re.Match) -> str:
    return mask(m.group(0), "phone")


def _email(m: re.Match) -> str:
    return mask(m.group(0), "email")


def _jwt(m: re.Match) -> str:
    return mask(m.group(0), "jwt")


def _ssn(m: re.Match) -> str:
    return mask(_digits_only(m.group(0)), "ssn")


# ---------------------------------------------------------------------------
# The 19 content rules, in execution order. DO NOT REORDER — several rules
# only behave correctly because a more specific rule ran first:
#   1. Credential/CVV/payment-id keyword rules before all shape rules —
#      otherwise a numeric secret in the card-digit range gets partially
#      "revealed" as if it were a PAN.
#   2. Quoted-key form before ":"/"=" form before bare-space form, per
#      keyword family.
#   3. IBAN before the card rules — many IBANs contain a letter-free 12-19
#      digit run that the card rules would otherwise partially reveal.
#   4. Phone before the card rules — same reason.
#   5. Email before card/CVV/SSN — a numeric-heavy address must mask as one
#      email rather than fragment.
#   6. SSN before standalone-CVV — a space-separated SSN's outer groups are
#      each individually CVV-standalone-shaped.
#   7. Standalone-CVV last — it is the loosest rule in the file (any bare
#      3-4 digit group); widening its boundary set beyond whitespace/string-
#      boundary over-masks.
# ---------------------------------------------------------------------------

REGEX_TO_MASKER_MAP = [
    # 1. PEM key block.
    (
        r"-----BEGIN [A-Z ]*KEY-----[\s\S]*?-----END [A-Z ]*KEY-----",
        _mask_pem,
    ),
    # 2. Credential — quoted key ("token": "abc123").
    (
        rf"([\"'])({_CRED_KEYWORD})\1(\s*:\s*)\1([^\"']*)\1",
        _cred_quoted,
    ),
    # 3. Credential — ":" / "=" (secret_key=abc123).
    (
        rf"\b({_CRED_KEYWORD}[\"'\s]*[:=][\"'\s]*)({_CRED_VALUE}+={{0,2}})",
        _cred_kv,
    ),
    # 4. CVV — quoted key ("cvv": "123").
    (
        rf"([\"'])({_CVV_KEYWORD})\1(\s*:\s*)\1\d{{3,4}}\1",
        _cvv_quoted,
    ),
    # 5. CVV — ":" / "=" (cvv=123).
    (
        rf"\b({_CVV_KEYWORD}[\"'\s]*[:=][\"'\s]*)\d{{3,4}}",
        _cvv_kv,
    ),
    # 6. Payment/transaction/auth id — quoted key ("payment_id": "abc12345").
    (
        rf"([\"'])({_PAYMENT_ID_KEYWORD})\1(\s*:\s*)\1([A-Za-z0-9_\-]+)\1",
        _payid_quoted,
    ),
    # 7. Payment/transaction/auth id (payment_id: abc12345).
    (
        rf"\b({_PAYMENT_ID_KEYWORD}\s*[:=]\s*)([A-Za-z0-9_\-]{{8,}})\b",
        _payid_kv,
    ),
    # 8. Credential — bare space (Bearer abc12345).
    (
        
        rf"\b({_CRED_KEYWORD})\s+(?=(?:{_CRED_VALUE})*\d)({_CRED_VALUE}{{8,}}={{0,2}})",
        _cred_space,
    ),
    # 9. CVV — bare space (CVV 123).
    (
        rf"\b({_CVV_KEYWORD})\s+\d{{3,4}}\b",
        _cvv_space,
    ),
    # 10. Payment/transaction/auth id — bare space (payment_id abc12345).
    (
        
        rf"\b({_PAYMENT_ID_KEYWORD})\s+(?=[A-Za-z0-9_\-]*\d)([A-Za-z0-9_\-]{{8,}})\b",
        _payid_space,
    ),
    # 11. IBAN (GB33BUKB20201555555555).
    (
        rf"(?-i:\b(?:{_IBAN_PREFIX})\d{{2}}[A-Z0-9]{{11,30}}\b)",
        _iban,
    ),
    # 12. Phone — international E.164-style or a bare local number. Union of
    # ecsctx's and the ported filter's patterns: dash/space/dot all count as
    # separators, since real phone numbers appear with all three and neither
    # source pattern alone caught every real case.
    (
        
        _CARD_LEAD_GUARD
        + r"(?:\+[1-9]\d{0,2}(?:[-.\s]?\d){6,13}|\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})"
        + _CARD_TAIL_GUARD,
        _phone,
    ),
    # 13. Email (user@example.com).
    (
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        _email,
    ),
    # 14. JWT (eyJhbGciOi....).
    (
        r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{3,}\.[A-Za-z0-9_\-]{3,}",
        _jwt,
    ),
    # 15. Card rule 1 — leading 9 (9123456789012).
    (
        _CARD_LEAD_GUARD + r"9" + _CARD_BODY + _CARD_TAIL_GUARD,
        _mask_full_card,
    ),
    # 16. Card rule 2 — leading 0-8, partial reveal (4111111111111111).
    (
        _CARD_LEAD_GUARD + r"[0-8]" + _CARD_BODY + _CARD_TAIL_GUARD,
        _mask_partial_pan,
    ),
    # 17. Card rule 3 — mixed separator fallback (4111-1111 1111-1111).
    (
        _CARD_LEAD_GUARD + r"\d" + _CARD_BODY + _CARD_TAIL_GUARD,
        _mask_full_card,
    ),
    # 18. SSN (123-45-6789).
    (
        _CARD_LEAD_GUARD + r"\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
        _ssn,
    ),
    # 19. CVV standalone — bare 3-4 digit group, no keyword (call 123 now).
    (
        r"(?:^|(?<=\s))\d{3,4}(?=\s|$)",
        _standalone_cvv,
    ),
]

PATTERN_TO_MASKER_MAP = {
    re.compile(regex, re.IGNORECASE): masker
    for regex, masker in REGEX_TO_MASKER_MAP.items()
}


def apply_all_patterns_masking(text: str):
    for pattern, repl in PATTERN_TO_MASKER_MAP.items():
        text = pattern.sub(repl, text)
    return text


KEYWORD_REGEX_TO_FIELD_TYPE_MAP = {
    _CVV_KEYWORD: "cvv",
    _CRED_KEYWORD: "secret",
    _PAYMENT_ID_KEYWORD: "payment_id",
    _EMAIL_KEY_WORDS: "email",
    _PHONE_KEY_WORDS: "phone",
    _ADDRESS_KEY_WORDS: "address",
    _NAME_KEY_WORDS: "name",
    _GENERIC_PII_KEY_WORDS: "generic",
}

KEYWORD_PATTERN_TO_FIELD_TYPE_MAP = {
    re.compile(regex, re.IGNORECASE): field_type
    for regex, field_type in KEYWORD_REGEX_TO_FIELD_TYPE_MAP.items()
}


def check_if_sensitive_keyword(dict_key: str) -> str | None:
    low_dict_key = dict_key.lower()
    if low_dict_key in SAFE_KEYS:
        return None
    for pattern, field_type in KEYWORD_PATTERN_TO_FIELD_TYPE_MAP.items():
        if pattern.search(low_dict_key):
            return field_type
    return None
