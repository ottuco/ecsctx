"""Content and key-name rules for MaskPIIFilter.

Ported from ottu_pg's MaskPIIFilter (utils/log/filters.py), merged with
ecsctx's own PII key-name list. Two independent detection strategies:

1. Content-based (CONTENT_RULES): 17 ordered regexes applied to every string
   the filter reaches. Rule order is load-bearing — see the comments on each
   rule and the ordering invariants they protect. Do not reorder.
2. Key-based (key_label): in a dict, a key that is itself a sensitive keyword
   masks the whole value outright, regardless of the value's type or content.
   This is what catches structlog kwargs (log.info("x", token="abcd1234")),
   where the key and value never appear together in one string for a regex
   to match.

Every masked value becomes `[LABEL]` or `[LABEL:token]` via mask_by_field_type —
never a bare `***`. Two exceptions: CVV must never carry a token, not even
an HMAC digest, because PCI forbids storing CVV in any form; card numbers
are truncated to first 6 + last 4 (`[CARD-MASKED:411111******1111]`, PCI DSS
3.4.1) with no token alongside.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Callable, NamedTuple

from ecsctx.masking.tokens import already_masked, make_label, mask_by_field_type

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
    # OAuth token metadata and network addresses, not secrets or postal addresses.
    "token_type",
    "ip_address",
    "mac_address",
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


def _truncate_pan(digits: str) -> str:
    """Keep at most the first 6 (BIN) and last 4 digits of a PAN.

    PCI DSS 3.4.1 permits showing at most the BIN + last 4 when a PAN is
    displayed — enough to identify the card for support without ever storing
    the full number. Separators are already stripped by the caller, so
    grouped input comes back as one contiguous masked value. No token is
    emitted alongside: an unkeyed hash next to a truncated PAN would itself
    be a finding, and a keyed one buys nothing over BIN/last-4.
    """
    return f"{digits[:6]}{'*' * (len(digits) - 10)}{digits[-4:]}"


def _mask_truncated_card(match: re.Match) -> str:
    # The content rule only matches 12-19 digit runs, so digits always
    # carries a BIN and a last-4 to preserve — no short-input path needed.
    # Deliberately not mask_by_field_type: that would tokenize (or, with
    # PII unconfigured, collapse to a bare label), losing the truncation.
    return f"[{make_label('card')}:{_truncate_pan(_digits_only(match.group(0)))}]"


_PAN_VALUE = re.compile(r"\d(?:[-\s]?\d){11,18}")


def mask_card_value(value) -> str:
    """The value of a card-named key: truncated when it is a PAN, else a label.

    Never tokenized — a keyed hash of a PAN next to its truncated form is the
    correlation FAQ 1117 warns about. A whole card object (number, expiry,
    holder) is one label.
    """
    if isinstance(value, str) and already_masked(value):
        return value
    if isinstance(value, (str, int)) and not isinstance(value, bool):
        text = str(value).strip()
        if _PAN_VALUE.fullmatch(text):
            return f"[{make_label('card')}:{_truncate_pan(_digits_only(text))}]"
    return f"[{make_label('card')}]"


def _mask_pem(match: re.Match) -> str:
    """Token computed over the base64 body only — strip the BEGIN/END lines
    and all whitespace first, so the same key re-wrapped at a different line
    width (or with CRLF instead of LF) still produces the same token.
    """
    body = match.group(0)
    stripped = re.sub(r"-----(BEGIN|END)[^-]*-----", "", body)
    stripped = re.sub(r"\s+", "", stripped)
    return mask_by_field_type(stripped, "pem_key")


def _cred_quoted(m: re.Match) -> str:
    q, kw, sep, val = m.group(1), m.group(2), m.group(3), m.group(4)
    return f"{q}{kw}{q}{sep}{q}{mask_by_field_type(val, 'secret')}{q}"


def _cred_kv(m: re.Match) -> str:
    prefix, val = m.group(1), m.group(2)
    return f"{prefix}{mask_by_field_type(val, 'secret')}"


def _cred_space(m: re.Match) -> str:
    kw, val = m.group(1), m.group(2)
    return f"{kw} {mask_by_field_type(val, 'secret')}"


def _cvv_quoted(m: re.Match) -> str:
    q, kw, sep = m.group(1), m.group(2), m.group(3)
    return f"{q}{kw}{q}{sep}{q}{mask_by_field_type('', 'cvv')}{q}"


def _cvv_kv(m: re.Match) -> str:
    return f"{m.group(1)}{mask_by_field_type('', 'cvv')}"


def _cvv_space(m: re.Match) -> str:
    return f"{m.group(1)} {mask_by_field_type('', 'cvv')}"


def _standalone_cvv(_m: re.Match) -> str:
    return mask_by_field_type('', 'cvv')


def _payid_quoted(m: re.Match) -> str:
    q, kw, sep, val = m.group(1), m.group(2), m.group(3), m.group(4)
    return f"{q}{kw}{q}{sep}{q}{mask_by_field_type(val, 'payment_id')}{q}"


def _payid_kv(m: re.Match) -> str:
    prefix, val = m.group(1), m.group(2)
    return f"{prefix}{mask_by_field_type(val, 'payment_id')}"


def _payid_space(m: re.Match) -> str:
    kw, val = m.group(1), m.group(2)
    return f"{kw} {mask_by_field_type(val, 'payment_id')}"


def _iban(m: re.Match) -> str:
    return mask_by_field_type(m.group(0), "iban")


def _phone(m: re.Match) -> str:
    return mask_by_field_type(m.group(0), "phone")


def _email(m: re.Match) -> str:
    return mask_by_field_type(m.group(0), "email")


def _jwt(m: re.Match) -> str:
    return mask_by_field_type(m.group(0), "jwt")


def _ssn(m: re.Match) -> str:
    return mask_by_field_type(_digits_only(m.group(0)), "ssn")


# ---------------------------------------------------------------------------
# Rules, packs and pre-checks
# ---------------------------------------------------------------------------
# Each rule belongs to one pack. `default` is always on; `pci` (card numbers,
# CVV) and `financial_ids` (IBAN, SSN, payment ids) are opt-in: only a PCI
# service ever sees that data, and scanning every string of every log line
# for it costs every other service CPU and mangles its numeric ids.
PACK_NAMES = ("default", "pci", "financial_ids")
ALL_PACKS = frozenset(PACK_NAMES)


class Rule(NamedTuple):
    name: str
    pack: str
    pattern: re.Pattern
    repl: Callable[[re.Match], str]
    # Cheap test on (text, text.lower()) that must pass before the regex runs.
    # Each one only checks for something its rule cannot match without, so a
    # gate can skip work but never change a result.
    gate: Callable[[str, str], bool]


# Spelled the way the credential rules spell them: "authori" would also match
# "AUTHORIZED", which appears in most gateway responses, while the rule itself
# needs "authorization". "key" covers the *_key compounds.
_CRED_LITERALS = (
    "token", "secret", "password", "passwd", "bearer", "basic", "digest",
    "credential", "authorization", "authorisation", "key",
)
_CVV_LITERALS = ("cvv", "cvc", "security")
_PHONE_SHAPE = re.compile(r"\+\d|\d{3}\D{0,2}\d{3}\D?\d{4}")
_CARD_SHAPE = re.compile(r"\d(?:[-\s]?\d){11}")
_SSN_SHAPE = re.compile(r"\d{3}[-\s]?\d{2}[-\s]?\d{4}")
_IBAN_SHAPE = re.compile(r"[A-Za-z]{2}\d{2}")
_THREE_DIGITS = re.compile(r"\d{3}")


def _has_pem(_text: str, lowered: str) -> bool:
    return "-----begin" in lowered


def _has_credential(_text: str, lowered: str) -> bool:
    return any(word in lowered for word in _CRED_LITERALS)


def _has_cvv_keyword(_text: str, lowered: str) -> bool:
    return any(word in lowered for word in _CVV_LITERALS)


def _has_id(_text: str, lowered: str) -> bool:
    return "id" in lowered


def _has_iban_shape(text: str, _lowered: str) -> bool:
    return _IBAN_SHAPE.search(text) is not None


def _has_phone_shape(text: str, _lowered: str) -> bool:
    return _PHONE_SHAPE.search(text) is not None


def _has_at(text: str, _lowered: str) -> bool:
    return "@" in text


def _has_jwt_prefix(text: str, _lowered: str) -> bool:
    return "eyJ" in text


def _has_card_shape(text: str, _lowered: str) -> bool:
    return _CARD_SHAPE.search(text) is not None


def _has_ssn_shape(text: str, _lowered: str) -> bool:
    return _SSN_SHAPE.search(text) is not None


def _has_three_digits(text: str, _lowered: str) -> bool:
    return _THREE_DIGITS.search(text) is not None


def _rule(pack, regex, repl, gate):
    return (pack, regex, repl, gate)


# ---------------------------------------------------------------------------
# The 17 content rules, in execution order. DO NOT REORDER — several rules
# only behave correctly because a more specific rule ran first:
#   1. Credential/CVV/payment-id keyword rules before all shape rules —
#      otherwise a numeric secret in the card-digit range gets masked as a
#      card number instead of by its own (more specific) rule.
#   2. Quoted-key form before ":"/"=" form before bare-space form, per
#      keyword family.
#   3. IBAN before the card rule — many IBANs contain a letter-free 12-19
#      digit run that the card rule would otherwise catch first.
#   4. Phone before the card rule — same reason.
#   5. Email before card/CVV/SSN — a numeric-heavy address must mask as one
#      email rather than fragment.
#   6. SSN before standalone-CVV — a space-separated SSN's outer groups are
#      each individually CVV-standalone-shaped.
#   7. Standalone-CVV last — it is the loosest rule in the file (any bare
#      3-4 digit group); widening its boundary set beyond whitespace/string-
#      boundary over-masks.
# ---------------------------------------------------------------------------

_RULE_TABLE = (
    # 1. PEM key block.
    _rule(
        "default",
        r"-----BEGIN [A-Z ]*KEY-----[\s\S]*?-----END [A-Z ]*KEY-----",
        _mask_pem,
        _has_pem,
    ),
    # 2. Credential — quoted key ("token": "abc123").
    _rule(
        "default",
        rf"([\"'])({_CRED_KEYWORD})\1(\s*:\s*)\1([^\"']*)\1",
        _cred_quoted,
        _has_credential,
    ),
    # 3. Credential — ":" / "=" (secret_key=abc123).
    _rule(
        "default",
        rf"\b({_CRED_KEYWORD}[\"'\s]*[:=][\"'\s]*)({_CRED_VALUE}+={{0,2}})",
        _cred_kv,
        _has_credential,
    ),
    # 4. CVV — quoted key ("cvv": "123").
    _rule(
        "pci",
        rf"([\"'])({_CVV_KEYWORD})\1(\s*:\s*)\1\d{{3,4}}\1",
        _cvv_quoted,
        _has_cvv_keyword,
    ),
    # 5. CVV — ":" / "=" (cvv=123).
    _rule(
        "pci",
        rf"\b({_CVV_KEYWORD}[\"'\s]*[:=][\"'\s]*)\d{{3,4}}",
        _cvv_kv,
        _has_cvv_keyword,
    ),
    # 6. Payment/transaction/auth id — quoted key ("payment_id": "abc12345").
    _rule(
        "financial_ids",
        rf"([\"'])({_PAYMENT_ID_KEYWORD})\1(\s*:\s*)\1([A-Za-z0-9_\-]+)\1",
        _payid_quoted,
        _has_id,
    ),
    # 7. Payment/transaction/auth id (payment_id: abc12345).
    _rule(
        "financial_ids",
        rf"\b({_PAYMENT_ID_KEYWORD}\s*[:=]\s*)([A-Za-z0-9_\-]{{8,}})\b",
        _payid_kv,
        _has_id,
    ),
    # 8. Credential — bare space (Bearer abc12345).
    _rule(
        "default",
        
        rf"\b({_CRED_KEYWORD})\s+(?=(?:{_CRED_VALUE})*\d)({_CRED_VALUE}{{8,}}={{0,2}})",
        _cred_space,
        _has_credential,
    ),
    # 9. CVV — bare space (CVV 123).
    _rule(
        "pci",
        rf"\b({_CVV_KEYWORD})\s+\d{{3,4}}\b",
        _cvv_space,
        _has_cvv_keyword,
    ),
    # 10. Payment/transaction/auth id — bare space (payment_id abc12345).
    _rule(
        "financial_ids",
        
        rf"\b({_PAYMENT_ID_KEYWORD})\s+(?=[A-Za-z0-9_\-]*\d)([A-Za-z0-9_\-]{{8,}})\b",
        _payid_space,
        _has_id,
    ),
    # 11. IBAN (GB33BUKB20201555555555).
    _rule(
        "financial_ids",
        rf"(?-i:\b(?:{_IBAN_PREFIX})\d{{2}}[A-Z0-9]{{11,30}}\b)",
        _iban,
        _has_iban_shape,
    ),
    # 12. Phone — international E.164-style or a bare local number. Union of
    # ecsctx's and the ported filter's patterns: dash/space/dot all count as
    # separators, since real phone numbers appear with all three and neither
    # source pattern alone caught every real case.
    _rule(
        "default",
        
        _CARD_LEAD_GUARD
        + r"(?:\+[1-9]\d{0,2}(?:[-.\s]?\d){6,13}|\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})"
        + _CARD_TAIL_GUARD,
        _phone,
        _has_phone_shape,
    ),
    # 13. Email (user@example.com).
    _rule(
        "default",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        _email,
        _has_at,
    ),
    # 14. JWT (eyJhbGciOi....).
    _rule(
        "default",
        r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{3,}\.[A-Za-z0-9_\-]{3,}",
        _jwt,
        _has_jwt_prefix,
    ),
    # 15. Card number — truncated to first 6 + last 4
    # ([CARD-MASKED:411111******1111]). PCI DSS 3.4.1 allows at most the
    # BIN + last 4 on display; the middle never survives, starred or not.
    # The output stays inside the [LABEL…] convention so already_masked()
    # idempotency holds, and the stars break the digit run so a second
    # pass cannot re-match it.
    _rule(
        "pci",
        _CARD_LEAD_GUARD + r"\d" + _CARD_BODY + _CARD_TAIL_GUARD,
        _mask_truncated_card,
        _has_card_shape,
    ),
    # 16. SSN (123-45-6789).
    _rule(
        "financial_ids",
        _CARD_LEAD_GUARD + r"\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
        _ssn,
        _has_ssn_shape,
    ),
    # 17. CVV standalone — bare 3-4 digit group, no keyword (call 123 now).
    _rule(
        "pci",
        r"(?:^|(?<=\s))\d{3,4}(?=\s|$)",
        _standalone_cvv,
        _has_three_digits,
    ),
)


RULES: tuple[Rule, ...] = tuple(
    Rule(f"{index}:{repl.__name__}", pack, re.compile(regex, re.IGNORECASE), repl, gate)
    for index, (pack, regex, repl, gate) in enumerate(_RULE_TABLE, start=1)
)


@lru_cache(maxsize=16)
def rules_for(packs: frozenset[str]) -> tuple[Rule, ...]:
    """The rules of `packs`, in the global order above.

    Keeping the global order within any combination is what keeps the
    ordering invariants true whichever packs a service enables.
    """
    return tuple(rule for rule in RULES if rule.pack in packs)


def mask_by_patterns(text: str, rules: tuple[Rule, ...]) -> str:
    lowered = text.lower()
    for rule in rules:
        if not rule.gate(text, lowered):
            continue
        masked = rule.pattern.sub(rule.repl, text)
        if masked != text:
            text = masked
            lowered = text.lower()
    return text


def mask_by_all_patterns(text: str) -> str:
    """Every rule of every pack — what the engine did before packs existed."""
    return mask_by_patterns(text, rules_for(ALL_PACKS))


# ---------------------------------------------------------------------------
# Key-name rules
# ---------------------------------------------------------------------------
# A key is split into words ("cardHolderName" -> card, holder, name;
# "x-api-key" -> x, api, key; trailing digits dropped, so "cvv2" -> cvv) and
# matched word by word. Matching a substring of the whole key is what made
# "namespace", "hostname" and "telemetry" read as a name and a phone number.
# Glued spellings that real payloads use ("cardtoken", "firstname") are
# listed or suffix-matched explicitly instead.
_KEY_SPLIT = re.compile(r"[_\-.\s]+|(?<=[a-z0-9])(?=[A-Z])")
_TRAILING_DIGITS = re.compile(r"\d+$")

_CVV_WORDS = frozenset({"cvv", "cvc", "cvn", "csc", "securitycode"})
_CARD_WORDS = frozenset({"pan", "cardnumber", "cardno"})
_EXPIRY_PREFIXES = ("expiry", "expiration")
_EXP_PARTS = frozenset({"month", "year", "date", "mm", "yy", "yyyy"})
_SECRET_WORDS = frozenset({
    "bearer", "basic", "digest", "credential", "credentials",
    "authorization", "authorisation",
})
_SECRET_SUFFIXES = ("token", "secret", "password", "passwd")
_KEY_PREFIXES = frozenset({
    "secret", "private", "public", "encryption", "decryption", "signing",
    "access", "master", "root", "session", "api",
})
_GLUED_KEYS = frozenset(prefix + "key" for prefix in _KEY_PREFIXES)
_PAYMENT_ID_PREFIXES = frozenset({"payment", "transaction", "auth"})
_GLUED_PAYMENT_IDS = frozenset(prefix + "id" for prefix in _PAYMENT_ID_PREFIXES)
_PHONE_WORDS = frozenset({"phone", "mobile", "tel", "telephone", "msisdn", "cellphone"})
_NAME_WORDS = frozenset({
    "name", "cardholder", "beneficiary", "recipient", "payer",
    "firstname", "lastname", "fullname", "middlename", "surname",
    "givenname", "familyname", "holdername", "cardholdername",
})
_GENERIC_WORDS = frozenset({"billing", "shipping", "customer", "contact", "udf"})


def _key_words(key: str) -> tuple[str, ...]:
    words = []
    for part in _KEY_SPLIT.split(key):
        word = _TRAILING_DIGITS.sub("", part.lower())
        if word:
            words.append(word)
    return tuple(words)


def _follows(words: tuple[str, ...], first: frozenset[str], second: str | frozenset[str]) -> bool:
    seconds = second if isinstance(second, frozenset) else frozenset({second})
    return any(a in first and b in seconds for a, b in zip(words, words[1:]))


@lru_cache(maxsize=4096)
def classify_key(key: str, packs: frozenset[str]) -> str | None:
    """The field type a key name marks its value as, or None.

    Cached: a service logs a small, fixed set of key names, so after warm-up
    this is a dict lookup instead of a scan per key per line.
    """
    lowered = key.lower()
    if lowered in SAFE_KEYS:
        return None
    words = _key_words(key)
    if not words:
        return None
    word_set = frozenset(words)
    if word_set & _CVV_WORDS or _follows(words, frozenset({"security"}), "code"):
        return "cvv"
    if words == ("card",) or word_set & _CARD_WORDS or _follows(
        words, frozenset({"card"}), frozenset({"number", "no"})
    ):
        return "card"
    if any(word.startswith(_EXPIRY_PREFIXES) for word in words) or _follows(
        words, frozenset({"exp"}), _EXP_PARTS
    ):
        return "expiry"
    if (
        word_set & _SECRET_WORDS
        or word_set & _GLUED_KEYS
        or any(word.endswith(_SECRET_SUFFIXES) for word in words)
        or _follows(words, _KEY_PREFIXES, "key")
    ):
        return "secret"
    if "financial_ids" in packs and (
        word_set & _GLUED_PAYMENT_IDS or _follows(words, _PAYMENT_ID_PREFIXES, "id")
    ):
        return "payment_id"
    if any(word.endswith("email") for word in words):
        return "email"
    if word_set & _PHONE_WORDS:
        return "phone"
    if any(word.endswith("address") for word in words):
        return "address"
    if word_set & _NAME_WORDS:
        return "name"
    if word_set & _GENERIC_WORDS:
        return "generic"
    return None


def check_if_sensitive_keyword(dict_key: str) -> str | None:
    """classify_key with every pack on."""
    return classify_key(dict_key, ALL_PACKS)
