"""Content and key-name rules for MaskPIIFilter.

Ported from ottu_pg's MaskPIIFilter (utils/log/filters.py), merged with
ecsctx's own PII key-name list. Two independent detection strategies:

1. Content-based (RULES): 17 ordered regexes in three packs — `default`
   always on, `pci` and `financial_ids` opt-in (ecsctx.masking.config) — each
   behind a literal pre-check, applied to every string the filter reaches.
   Rule order is load-bearing — see the comments on each rule and the
   ordering invariants they protect. Do not reorder.
2. Key-based (classify_key): in a dict, a key whose words name a sensitive
   field masks the whole value outright, regardless of the value's type or
   content.
   This is what catches structlog kwargs (log.info("x", token="abcd1234")),
   where the key and value never appear together in one string for a regex
   to match.

Every masked value becomes a bare token or a `[LABEL]` via mask_by_field_type —
never a bare `***`. Cardholder data never carries a token: CVV and expiry
are bare labels, because PCI forbids storing CVV in any form; card numbers
are truncated — first 6 + last 4 from 15 digits up, last 4 only below
(`[CARD-MASKED:411111******1111]`, PCI DSS 3.5.1, FAQ 1091).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from functools import lru_cache
from typing import NamedTuple

from ecsctx.masking.tokens import make_label, mask_by_field_type

# ---------------------------------------------------------------------------
# Shared keyword/value fragments
# ---------------------------------------------------------------------------

# Names that mean the same in every service: logging and code metadata, web
# and standard HTTP names. A service's own vocabulary (a gateway's name field,
# a status flag) is the service's to list: ECSCTX_MASK_SAFE_KEYS
# (ecsctx.masking.config), which extends this set and cannot shrink it.
SAFE_KEYS = frozenset({
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
    "display_name",
    "event_name",
    "pathname",  # structlog CallsiteParameterAdder's source-file path, not PII
    "customer_id",
    "id",
    "pk",
    # Substring matching's known false positives: a namespace, a host or file
    # name, OAuth token metadata (RFC 6749), a client-hint header ("?0", W3C
    # User-Agent Client Hints).
    "namespace",
    "hostname",
    "filename",
    "token_type",
    "sec-ch-ua-mobile",
})

# Sensitive credential keywords / auth schemes. Matched case-insensitively.
# Bare "key" is intentionally excluded — only sensitive *_key compounds — so
# cache_key / sort_key / primary_key are not over-masked.
_CRED_KEYWORD = (
    r"(?:"
    r"bearer|basic|digest|credentials?"  # auth schemes
    r"|authori[sz]ation(?:[_-]?header)?"  # Authorization / Authorisation (+ _header)
    r"|(?:[\w-]{0,128}[_-])?(?:token|secret|password|passwd)"  # *_token / *_secret / *_password
    r"|(?:secret|private|public|encryption|decryption|signing|"  # sensitive *_key compounds only
    r"access|master|root|session|api)[_-]?key"
    r")"
)

# Card verification code keywords — cvv/cvc/security code are all the same
# thing under different names depending on card scheme/vendor terminology.
_CVV_KEYWORD = r"(?:cvv|cvc|security[_\s]?code)"

# Payment/transaction/auth id keywords.
_PAYMENT_ID_KEYWORD = r"(?:payment|transaction|auth)[_\s-]?id"

# The key prefix before a credential word is bounded ({0,128}) in the content
# rules: unbounded, "a-a-a-…token" backtracks quadratically, seconds for one
# 20 KB string. A key-name match searches a short key, where the bound would
# only get in the way, so it keeps the unbounded form.
_CRED_KEY_NAME = _CRED_KEYWORD.replace("[\\w-]{0,128}", "[\\w-]*")

# Substring matching on the lowercased key, as since 0.7.0: it fails closed on
# glued and plural names payloads use (phonenumber, cardcvv, nameoncard,
# tokens). Its known false positives are listed in SAFE_KEYS instead.
_EMAIL_KEY_WORDS = r"email"
# "tel" is matched as a word of the key (_is_tel_key), not as a substring:
# hotel, hostel and intel are not phone numbers.
_PHONE_KEY_WORDS = r"phone|mobile"
_ADDRESS_KEY_WORDS = r"address"
_NAME_KEY_WORDS = r"name|cardholder|beneficiary|recipient|payer"
_GENERIC_PII_KEY_WORDS = r"billing|shipping|customer|contact|udf"




# Credential value characters: token / base64url / JWT / hex (no whitespace).
_CRED_VALUE = r"[A-Za-z0-9._~+/\-]"

# A value that is already a PII token (ptok:v1:…), which a key rule or an
# earlier pass put there: masking it again would tokenize "ptok" and break it.
_TOKEN_START = r"ptok:"

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
# The phone, card and SSN rules put a one-character lookahead for their first
# character in front of the lead guard: it rejects most positions before the
# costlier lookbehind runs, without changing what matches.
#
# _CARD_LEAD_GUARD: a match may only start right after a real prefix (quote,
# "([{", ":", "=", space, comma, dot, or start-of-string), not mid-digit-run
# or glued to a letter. The extra (?<!\d ) blocks a space that's itself
# preceded by a digit, so a differently-grouped longer number's tail chunk
# isn't mistaken for a fresh match.
# _CARD_TAIL_GUARD: a match may not be followed by more digits. A letter may
# follow: Track 2 equivalent data puts a "D" separator straight after the PAN.
# _PHONE_TAIL_GUARD also refuses a following letter — a digit run that runs
# into letters is part of an id (a hex session_id starting with digits), and
# the phone rule runs in every service, not only PCI ones.
_CARD_LEAD_GUARD = r"(?:^|(?<=[\s,.:=\"'([{]))(?<!\d )"
_CARD_TAIL_GUARD = r"(?![-\s]?\d)"
_PHONE_TAIL_GUARD = _CARD_TAIL_GUARD + r"(?![A-Za-z])"
# 11 more digits after the leading one = 12 total; 18 more = 19 total.
_CARD_BODY = r"(?:[-\s]?\d){11,18}"


def _digits_only(text: str) -> str:
    return "".join(c for c in text if c.isdigit())


# ---------------------------------------------------------------------------
# Callables that turn a match into a labeled, tokenized replacement
# ---------------------------------------------------------------------------


def _truncate_pan(digits: str) -> str:
    """Keep at most the first 6 (BIN) and last 4 digits of a PAN.

    Logs are stored data, so PCI DSS 3.5.1 truncation applies. FAQ 1091
    allows first 6 + last 4 for the 15- and 16-digit PANs of every brand it
    lists, and covers shorter PANs only for Discover — so below 15 digits
    only the last 4 survive. Separators are already stripped by the caller.
    No token is emitted alongside: a hash of the full PAN next to its
    truncated form is the correlation FAQ 1117 warns about.
    """
    if len(digits) >= 15:
        return f"{digits[:6]}{'*' * (len(digits) - 10)}{digits[-4:]}"
    return f"{'*' * (len(digits) - 4)}{digits[-4:]}"


def _mask_truncated_card(match: re.Match) -> str:
    # The content rule only matches 12-19 digit runs, so digits always
    # carries a BIN and a last-4 to preserve — no short-input path needed.
    # Deliberately not mask_by_field_type: that would tokenize (or, with
    # PII unconfigured, collapse to a bare label), losing the truncation.
    return f"[{make_label('card')}:{_truncate_pan(_digits_only(match.group(0)))}]"


_PAN_VALUE = re.compile(r"\d(?:[-\s]?\d){11,18}")
# A value that is exactly one marker ecsctx itself produces: a bare label, a
# label with a token, or a truncated card. A marker somewhere inside a longer
# value, or brackets around anything else, do not make it safe.
_SINGLE_MARKER = re.compile(
    r"\[[A-Z0-9-]+-MASKED(?::ptok:[\w:.-]+)?\]|\[CARD-MASKED:(?:\d{6})?\*+\d{4}\]|ptok:[\w:.-]+"
)


def mask_card_value(value) -> str:
    """The value of a card-named key: truncated when it is a PAN, else a label.

    Never tokenized — a keyed hash of a PAN next to its truncated form is the
    correlation FAQ 1117 warns about. A whole card object (number, expiry,
    holder) is one label.
    """
    if isinstance(value, str) and _SINGLE_MARKER.fullmatch(value):
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


# Values a quoted key can hold that are literals, not text: JSON's and a
# Python repr's. None of them is a secret.
_LITERALS = frozenset({"null", "true", "false", "None", "True", "False"})
_SEPARATOR = re.compile(r"[:=]")


def _unquoted_value_quote(prefix: str) -> str:
    """The quote closing the key in ``prefix`` (key, separator, spacing) when
    the value after it is unquoted — JSON or a repr, whose text must stay
    parseable once masked. Empty for ``key=value`` text, or when the value's
    own opening quote is in the prefix."""
    separator = _SEPARATOR.search(prefix)
    if separator is None:
        return ""
    before, after = prefix[: separator.start()], prefix[separator.end() :]
    if any(q in after for q in "\"'"):
        return ""
    return next((q for q in before if q in "\"'"), "")


def _cred_kv(m: re.Match) -> str:
    prefix, val = m.group(1), m.group(2)
    if quote := _unquoted_value_quote(prefix):
        if val in _LITERALS:
            return m.group(0)
        return f"{prefix}{quote}{mask_by_field_type(val, 'secret')}{quote}"
    return f"{prefix}{mask_by_field_type(val, 'secret')}"


def _cred_space(m: re.Match) -> str:
    kw, val = m.group(1), m.group(2)
    return f"{kw} {mask_by_field_type(val, 'secret')}"


def _cvv_quoted(m: re.Match) -> str:
    q, kw, sep = m.group(1), m.group(2), m.group(3)
    return f"{q}{kw}{q}{sep}{q}{mask_by_field_type('', 'cvv')}{q}"


def _cvv_kv(m: re.Match) -> str:
    quote = _unquoted_value_quote(m.group(1))
    return f"{m.group(1)}{quote}{mask_by_field_type('', 'cvv')}{quote}"


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
    # Replaces pattern.sub for rules whose matches can only start at a few
    # positions it can find cheaply; same output as pattern.sub.
    scan: Callable[[re.Pattern, Callable, str], str] | None = None


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


def _has_jwt_prefix(_text: str, lowered: str) -> bool:
    # The rules compile with IGNORECASE, so the JWT rule matches "EYJ…" too.
    return "eyj" in lowered


def _has_card_shape(text: str, _lowered: str) -> bool:
    return _CARD_SHAPE.search(text) is not None


def _has_ssn_shape(text: str, _lowered: str) -> bool:
    return _SSN_SHAPE.search(text) is not None


def _has_three_digits(text: str, _lowered: str) -> bool:
    return _THREE_DIGITS.search(text) is not None


# Every credential match contains one of these words, and starts inside the
# run of [\w-] characters holding it, or on the quote right before that run
# (rule 2's quoted key). So the credential rules only need trying at those
# positions, not at every position of a long body — re.sub tries every one,
# and at ~16 µs per rule per gateway body that was most of the masking cost.
# The words are found with str.find on the lowercased text: a case-insensitive
# regex alternation gets no literal-prefix speedup and costs as much as the
# rule it would be saving.
_CRED_WORDS = (
    "bearer", "basic", "digest", "credential", "authorization", "authorisation",
    "token", "secret", "password", "passwd", "key",
)
_KEY_CHAR = re.compile(r"[\w-]")


def _credential_word_starts(lowered: str) -> list[int]:
    starts = set()
    for word in _CRED_WORDS:
        index = lowered.find(word)
        while index != -1:
            starts.add(index)
            index = lowered.find(word, index + 1)
    return sorted(starts)


# A credential match starts at most this far before its credential word: the
# bounded key prefix (128), its separator, and rule 2's opening quote.
_CRED_REACH = 130


def _sub_near_credential_words(pattern: re.Pattern, repl, text: str) -> str:
    """pattern.sub(repl, text), trying only positions a credential match can start at."""
    lowered = _folded_lower(text)
    if lowered is None:
        return pattern.sub(repl, text)
    parts = []
    copied = 0  # text[:copied] is already in parts
    tried = 0  # every position below this has been tried or lies inside a match
    run_start = run_end = -1  # the [\w-] run found for the previous word
    for word_start in _credential_word_starts(lowered):
        if word_start < tried:
            continue
        if not run_start <= word_start <= run_end:
            # Walk back once per run, not once per word: a run holding many
            # credential words ("keykeykey…") would otherwise be quadratic.
            run_start = word_start
            while run_start > 0 and _KEY_CHAR.match(text, run_start - 1):
                run_start -= 1
            run_end = word_start
            while run_end < len(text) and _KEY_CHAR.match(text, run_end):
                run_end += 1
        first = max(tried, run_start - 1, word_start - _CRED_REACH)
        for position in range(first, word_start + 1):
            match = pattern.match(text, position)
            if match:
                parts.append(text[copied:match.start()])
                parts.append(repl(match))
                copied = tried = match.end()
                break
        else:
            tried = word_start + 1
    if not parts:
        return text
    parts.append(text[copied:])
    return "".join(parts)


def _rule(pack, regex, repl, gate, scan=None):
    return (pack, regex, repl, gate, scan)


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
        _sub_near_credential_words,
    ),
    # 3. Credential — ":" / "=" (secret_key=abc123).
    _rule(
        "default",
        rf"\b({_CRED_KEYWORD}[\"'\s]*[:=][\"'\s]*)(?!{_TOKEN_START})({_CRED_VALUE}+={{0,2}})",
        _cred_kv,
        _has_credential,
        _sub_near_credential_words,
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
        
        rf"\b({_CRED_KEYWORD})\s+(?!{_TOKEN_START})(?=(?:{_CRED_VALUE})*\d)({_CRED_VALUE}{{8,}}={{0,2}})",
        _cred_space,
        _has_credential,
        _sub_near_credential_words,
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
        
        r"(?=[+(\d])"
        + _CARD_LEAD_GUARD
        + r"(?:\+[1-9]\d{0,2}(?:[-.\s]?\d){6,13}|\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})"
        + _PHONE_TAIL_GUARD,
        _phone,
        _has_phone_shape,
    ),
    # 13. Email (user@example.com).
    _rule(
        "default",
        # Bounded by RFC 5321's limits (64-char local part, 255-char domain):
        # unbounded, a long run of "a-a-a-" before an "@" backtracks
        # quadratically — seconds for one 20 KB string.
        r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}\b",
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
    # 15. Card number — truncated ([CARD-MASKED:411111******1111]; last 4
    # only below 15 digits, see _truncate_pan); the middle never survives,
    # starred or not.
    # The output stays inside the [LABEL…] convention so already_masked()
    # idempotency holds, and the stars break the digit run so a second
    # pass cannot re-match it.
    _rule(
        "pci",
        r"(?=\d)" + _CARD_LEAD_GUARD + r"\d" + _CARD_BODY + _CARD_TAIL_GUARD,
        _mask_truncated_card,
        _has_card_shape,
    ),
    # 16. SSN (123-45-6789).
    _rule(
        "financial_ids",
        r"(?=\d)" + _CARD_LEAD_GUARD + r"\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
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
    Rule(f"{index}:{repl.__name__}", pack, re.compile(regex, re.IGNORECASE), repl, gate, scan)
    for index, (pack, regex, repl, gate, scan) in enumerate(_RULE_TABLE, start=1)
)


@lru_cache(maxsize=16)
def rules_for(packs: frozenset[str]) -> tuple[Rule, ...]:
    """The rules of `packs`, in the global order above.

    Keeping the global order within any combination is what keeps the
    ordering invariants true whichever packs a service enables.
    """
    return tuple(rule for rule in RULES if rule.pack in packs)


# Fixed points of masking under a given rule set — strings a full pass leaves
# unchanged — so the next time they are seen (the formatter's pass over what
# the filter produced, the same values on the next line) they are not scanned
# again. Only a verified fixed point goes in: one pass over a masked result
# can still change it (see _MAX_PASSES). Bounded, and emptied, not evicted.
_CLEAN_LIMIT = 2048
_CLEAN_MAX_LENGTH = 8192
_clean: dict[int, tuple[tuple, dict[str, None]]] = {}

# The non-ASCII letters IGNORECASE matches to ASCII ones — the same four on
# Python 3.10–3.14. Folding them before lowercasing lets the pre-checks and the
# credential word search see what the case-insensitive rules see.
_ASCII_FOLDS = str.maketrans({"\u0130": "i", "\u0131": "i", "\u017f": "s", "\u212a": "k"})


def _folded_lower(text: str) -> str | None:
    """text lowercased with the IGNORECASE folds applied, or None when that
    would move positions (a few characters lowercase to two)."""
    lowered = text.translate(_ASCII_FOLDS).lower()
    return lowered if len(lowered) == len(text) else None


def _clean_set(rules: tuple) -> dict[str, None]:
    entry = _clean.get(id(rules))
    if entry is None or entry[0] is not rules:
        # Keeping `rules` in the entry keeps its id from being reused.
        entry = _clean[id(rules)] = (rules, {})
    return entry[1]


# Passes over one string until nothing changes. Masking a CVV-shaped group
# after a PAN frees the PAN for the card rule on the next pass; two passes
# settle every case seen, and the cap only guards against a cycle.
_MAX_PASSES = 4


def _mask_once(text: str, rules: tuple[Rule, ...]) -> str:
    lowered = _folded_lower(text)
    if lowered is None:
        for rule in rules:
            text = rule.pattern.sub(rule.repl, text)
        return text
    return _mask_gated(text, lowered, rules)


def known_clean(text: str, rules: tuple[Rule, ...]) -> bool:
    """Whether ``text`` is the output of an earlier full pass with ``rules``.

    The filter checks this before parsing a string as JSON: the formatter's
    second pass then costs a lookup, not a parse, for a body the handler's
    filter has already masked by key.
    """
    return text in _clean_set(rules)


def mask_by_patterns(text: str, rules: tuple[Rule, ...]) -> str:
    """Mask ``text`` to a fixed point, so the result is complete on its own —
    what reads the record the filter masked (Sentry, handleError) does not
    depend on the formatter's later pass."""
    clean = _clean_set(rules)
    if text in clean:
        return text
    for _ in range(_MAX_PASSES):
        masked = _mask_once(text, rules)
        if masked == text:
            break
        text = masked
    else:
        return text  # still changing: return it, but do not vouch for it
    if len(text) <= _CLEAN_MAX_LENGTH:
        if len(clean) >= _CLEAN_LIMIT:
            clean.clear()
        clean[text] = None
    return text


@lru_cache(maxsize=16)
def _distinct_gates(rules: tuple[Rule, ...]) -> tuple:
    return tuple(dict.fromkeys(rule.gate for rule in rules))


def _passing_gates(text: str, lowered: str, gates: tuple) -> set:
    return {gate for gate in gates if gate(text, lowered)}


def _mask_gated(text: str, lowered: str, rules: tuple[Rule, ...]) -> str:
    gates = _distinct_gates(rules)
    # Each distinct pre-check runs once per version of the text, and most
    # strings in a log line (a pg code, an operation name) pass none of them.
    passed = _passing_gates(text, lowered, gates)
    if not passed:
        return text
    # After a substitution the text changed, so each later gate is asked again
    # on the new text — lazily, only when a rule behind it comes up.
    verdicts = {gate: gate in passed for gate in gates}
    for rule in rules:
        verdict = verdicts.get(rule.gate)
        if verdict is None:
            verdict = verdicts[rule.gate] = rule.gate(text, lowered)
        if not verdict:
            continue
        if rule.scan is not None:
            masked = rule.scan(rule.pattern, rule.repl, text)
        else:
            masked = rule.pattern.sub(rule.repl, text)
        if masked != text:
            text = masked
            lowered = _folded_lower(text)
            if lowered is None:
                # The substitution made the text unsafe to gate: finish plainly.
                later = rules[rules.index(rule) + 1 :]
                for rest in later:
                    text = rest.pattern.sub(rest.repl, text)
                return text
            verdicts.clear()
    return text


def mask_by_all_patterns(text: str) -> str:
    """Every rule of every pack — what the engine did before packs existed."""
    return mask_by_patterns(text, rules_for(ALL_PACKS))


# ---------------------------------------------------------------------------
# Key-name rules
# ---------------------------------------------------------------------------
# A key whose lowercased name contains a sensitive keyword masks its whole
# value. Substring matching fails closed on the glued and plural names real
# payloads use (phonenumber, cardcvv, nameoncard, tokens); its known false
# positives are SAFE_KEYS. Card and expiry keys are matched precisely instead:
# "card" alone is in card_id and discard, and "exp" in export and expected.
KEYWORD_REGEX_FIELD_TYPE = (
    (_CVV_KEYWORD, "cvv"),
    (_CRED_KEY_NAME, "secret"),
    (_PAYMENT_ID_KEYWORD, "payment_id"),
    (_EMAIL_KEY_WORDS, "email"),
    (_PHONE_KEY_WORDS, "phone"),
    (_ADDRESS_KEY_WORDS, "address"),
    (_NAME_KEY_WORDS, "name"),
    (_GENERIC_PII_KEY_WORDS, "generic"),
)

KEYWORD_PATTERN_FIELD_TYPE = tuple(
    (re.compile(regex, re.IGNORECASE), field_type)
    for regex, field_type in KEYWORD_REGEX_FIELD_TYPE
)

_KEY_SEPARATORS = re.compile(r"[_\-.\s]+")
_KEY_SPLIT = re.compile(r"[_\-.\s]+|(?<=[a-z0-9])(?=[A-Z])")


def _is_card_key(lowered: str, joined: str, words: list[str]) -> bool:
    return (
        lowered == "card"
        or "pan" in words
        or "cardnumber" in joined
        or joined.endswith("cardno")
    )


def _is_tel_key(words: list[str]) -> bool:
    # tel, tel_no, telNo, customer_tel, and the numbered form fields tel1, tel2.
    return any(word == "tel" or (word.startswith("tel") and word[3:].isdigit()) for word in words)


def _is_expiry_key(joined: str) -> bool:
    return (
        "expiry" in joined
        or "expiration" in joined
        or joined in {"expmonth", "expyear", "expdate", "cardexpmonth", "cardexpyear"}
    )


# A name ending in one of these names the CVV or credential itself, which no
# service may list as safe; "cvv_required" or "tokenization_status" only
# describe one. Matched on the lowercased key with separators removed.
_NEVER_SAFE_ENDING = re.compile(
    r"(?:cvv2?|cvc2?|securitycode"
    r"|token|secret|password|passwd|credentials?|authori[sz]ation|bearer|basic|digest"
    r"|(?:secret|private|public|encryption|decryption|signing|access|master|root|session|api)key)$"
)


def never_safe(key: str) -> bool:
    """Whether no service may list ``key`` as safe: a card or expiry key as the
    classifier finds them, or a name ending in a CVV or credential word."""
    lowered = key.lower()
    joined = _KEY_SEPARATORS.sub("", lowered)
    words = [word.lower() for word in _KEY_SPLIT.split(key) if word]
    return (
        _is_card_key(lowered, joined, words)
        or _is_expiry_key(joined)
        or _NEVER_SAFE_ENDING.search(joined) is not None
    )


@lru_cache(maxsize=4096)
def classify_key(key: str, packs: frozenset[str], safe: frozenset[str] = frozenset()) -> str | None:
    """The field type a key name marks its value as, or None.

    ``safe`` holds the service's own safe keys (ECSCTX_MASK_SAFE_KEYS),
    lowercased, on top of SAFE_KEYS.

    Cached: a service logs a small, fixed set of key names, so after warm-up
    this is a dict lookup instead of a regex scan per key per line.
    """
    lowered = key.lower()
    if lowered in SAFE_KEYS or lowered in safe:
        return None
    joined = _KEY_SEPARATORS.sub("", lowered)
    words = [word.lower() for word in _KEY_SPLIT.split(key) if word]
    for pattern, field_type in KEYWORD_PATTERN_FIELD_TYPE:
        if field_type == "secret":
            # Card and expiry are checked after CVV and before credentials,
            # so "card_expiry" is expiry and "cardtoken" stays a secret.
            if _is_card_key(lowered, joined, words):
                return "card"
            if _is_expiry_key(joined):
                return "expiry"
        if field_type == "payment_id" and "financial_ids" not in packs:
            continue
        if field_type == "phone" and _is_tel_key(words):
            return "phone"
        if pattern.search(lowered):
            return field_type
    return None


def check_if_sensitive_keyword(dict_key: str) -> str | None:
    """classify_key with every pack on."""
    return classify_key(dict_key, ALL_PACKS)
