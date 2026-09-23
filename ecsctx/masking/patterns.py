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
never a bare `***`. Cardholder data never carries a token: a CVV
are bare labels, because PCI forbids storing CVV in any form; card numbers
are truncated — first 6 + last 4 from 15 digits up, last 4 only below
(`411111******1111`, bare, PCI DSS 3.5.1, FAQ 1091 — brackets mean
nothing survived, and a truncation carries the BIN and the last four).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from functools import lru_cache
from typing import NamedTuple

from ecsctx.masking.tokens import _TRUNCATED_PAN, make_label, mask_by_field_type

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
    # Not `display_name`: under a customer it is the customer's name, and a
    # safe key escapes its container.
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
    # OAuth token metadata (RFC 6749), like `token_type`: read through when a
    # token response is walked under its credential key.
    "expires_in",
    "expires_at",
    "refresh_expires_in",
    "scope",
    # What a card object says about itself without being the card: the network
    # and the BIN, which PCI DSS 3.4.1 lets anyone display. Listed so they read
    # through a credential container too -- the saved card under `token`.
    "brand",
    "scheme",
    "bin",
    # Record bookkeeping timestamps: never PII or a card, but fourteen digits,
    # which the card rule refuses under a card key as "not a clean PAN" --
    # `Card.as_dict()` carries both.
    "created",
    "modified",
    "created_at",
    "updated_at",
    # Expiry. Cardholder Data rather than Sensitive Authentication Data, so
    # PCI DSS permits storing it and ecsctx no longer classifies it. Listed
    # here as well so it escapes a PII container's sweep: inside a `payer` or
    # `customer` object an unclassified key is masked as the container's type,
    # which would turn an expiry's month and year into [NAME-MASKED] -- less
    # readable than the label it replaced. Both separator forms, since this set
    # is matched on the lowercased key as written.
    "expiry",
    "expiry_date",
    "expirydate",
    "expiry_month",
    "expirymonth",
    "expiry_year",
    "expiryyear",
    "expiration",
    "expiration_date",
    "expirationdate",
    "exp_month",
    "expmonth",
    "exp_year",
    "expyear",
    "exp_date",
    "expdate",
    "card_expiry",
    "cardexpiry",
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
_CVV_KEYWORD = r"(?:cvv|cvc|security[-_.\s]?code)"

# Payment/transaction/auth id keywords.
_PAYMENT_ID_KEYWORD = r"(?:payment|transaction|auth)[_\s-]?id"

# Substring matching on the lowercased key, as since 0.7.0: it fails closed on
# glued and plural names payloads use (phonenumber, cardcvv, nameoncard,
# tokens). Its known false positives are listed in SAFE_KEYS instead.
_EMAIL_KEY_WORDS = r"email"
# "tel" is matched as a word of the key (_is_tel_key), not as a substring:
# hotel, hostel and intel are not phone numbers.
_PHONE_KEY_WORDS = r"phone|mobile"
# An address field named on its own -- a street, a numbered line, EMV 3DS's
# `billAddrCity` -- not only under an `address` key. `line1` only as the whole
# key or after `addr`/a separator, so `pipeline1` and `timeline_2` are not.
_ADDRESS_KEY_WORDS = r"address|street|(?:^|addr|_)line_?[1-3]$|^(?:bill|ship)addr"
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
# The shortest PAN issued. A value with fewer digits than this cannot be one.
_MIN_PAN_DIGITS = 12


def _digits_only(text: str) -> str:
    return "".join(c for c in text if c.isdigit())


# Every CVV rule replaces the match with this, whatever it matched: PCI forbids
# keeping a CVV in any form, so there is no value to carry and nothing to
# tokenize. Stated directly rather than via mask_by_field_type('', 'cvv'),
# which made these rules depend on how an empty value is rendered.
_CVV_LABEL = f"[{make_label('cvv')}]"



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
    # Emitted bare: the truncation IS the value, and the stars alone make it a
    # fixed point — they break the digit run so no later pass re-matches it.
    return _truncate_pan(_digits_only(match.group(0)))


_PAN_VALUE = re.compile(r"\d(?:[-\s]?\d){11,18}")
# A value that is exactly one marker ecsctx itself produces: a bare label, a
# label with a token, or a truncated card. A marker somewhere inside a longer
# value, or brackets around anything else, do not make it safe.
_SINGLE_MARKER = re.compile(
    rf"\[[A-Z0-9-]+-MASKED(?::ptok:[\w:.-]+)?\]|{_TRUNCATED_PAN}"
    rf"|\[CARD-MASKED:{_TRUNCATED_PAN}\]|ptok:[\w:.-]+"
)


def _luhn_valid(digits: str) -> bool:
    total = 0
    for position, character in enumerate(reversed(digits)):
        number = int(character)
        if position % 2:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def int_is_pan(value: int) -> bool:
    """Whether an int is a card number: 12-19 digits, a payment-network issuer
    prefix (2-6), and a Luhn pass. Numbers are otherwise never content-scanned,
    so this is what stops `{"ref": 4111111111111111}` shipping whole -- without
    reading an epoch-millisecond timestamp (it starts with 1) as a card."""
    digits = str(abs(value))
    return _MIN_PAN_DIGITS <= len(digits) <= 19 and digits[0] in "23456" and _luhn_valid(digits)


def pan_shaped(text: str) -> bool:
    """Whether ``text`` is, in its entirety, a PAN.

    Public because the filter asks it of a value that a PII key already
    claimed: a card number typed into the name box is still a card number.
    """
    return _PAN_VALUE.fullmatch(text.strip()) is not None


def mask_card_value(value) -> str:
    """The value of a card-named key: the PAN truncated, the rest readable.

    Never tokenized — a keyed hash of a PAN next to its truncated form is the
    correlation FAQ 1117 warns about.

    Scalars only. A card *object* is walked leaf by leaf in `_mask_dict`, which
    re-enters here for each leaf, so `number` truncates while `expiry` and
    `scheme` read through. Collapsing the object was how `holder`, `track2` and
    `pinBlock` stayed out of a log without ever being classified; they are
    classified now, and this function is deliberately permissive below twelve
    digits, so it must not be handed a whole container again.

    What is *not* a PAN is shown. Collapsing every non-PAN value to a label
    made a gateway token, a scheme name and an error string all look identical
    under `card_number`, which is the one place someone debugging a declined
    payment goes looking.
    """
    if isinstance(value, str) and not value:
        return value  # nothing was there; see mask_by_field_type
    if isinstance(value, str) and _SINGLE_MARKER.fullmatch(value):
        return value
    if isinstance(value, (str, int)) and not isinstance(value, bool):
        text = str(value).strip()
        if _PAN_VALUE.fullmatch(text):
            return _truncate_pan(_digits_only(text))
        if sum(character.isdigit() for character in text) < _MIN_PAN_DIGITS:
            # Too few digits to be a PAN whatever else it holds: 12 is the
            # shortest one issued (ISO/IEC 7812; Maestro issues from 12).
            return value
        # Enough digits to hide one, but not a clean PAN: scan rather than
        # collapse, so an embedded PAN is truncated and its context survives.
        scanned = mask_by_patterns(text, _CARD_RULE_ONLY)
        if scanned != text:
            return scanned
        # The scan found nothing to truncate, yet the value carries twelve or
        # more digits under a card key. `4508750**0001019` is the shape that
        # matters: 14 of 16 digits kept, far past what PCI DSS 3.5.1 allows,
        # and no contiguous run for the card rule to catch. Refuse it.
        return f"[{make_label('card')}]"
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
    return f"{q}{kw}{q}{sep}{q}{_CVV_LABEL}{q}"


def _cvv_kv(m: re.Match) -> str:
    quote = _unquoted_value_quote(m.group(1))
    return f"{m.group(1)}{quote}{_CVV_LABEL}{quote}"


def _cvv_space(m: re.Match) -> str:
    return f"{m.group(1)} {_CVV_LABEL}"


def _standalone_cvv(_m: re.Match) -> str:
    return _CVV_LABEL


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
    # Unlike `gate`, this one DOES change the result: it says whether the rule
    # applies to this text at all. Only the standalone-CVV rule has one.
    precondition: Callable[[str, str], bool] | None = None
    # True for a rule that may only run over prose -- a human message, a
    # serialised body -- and never over a whole scalar field value. A field
    # value has a key to be judged by; applying a keyless shape rule to it
    # destroys legitimate data (a PSP response code, a Content-Length) that
    # the same rule leaves alone when it arrives as an int. See
    # MaskPIIFilter._mask_value, which has always skipped ints for this
    # reason.
    prose_only: bool = False


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


# Rules 15 and 16 have already run by the time rule 17 does, so a PAN in the
# text is now a bare truncation rather than a digit run. _TRUNCATED_PAN_RE
# below is what recognises it; these words cover a "card"/"pan" key name
# serialised into the text, and the prose cases.
# _CVV_LITERALS too: text that says "cvv" anywhere is card context even when
# the keyword rules cannot reach the digits ("the cvv is 123" -- rule 9 needs
# them adjacent).
_CARD_CONTEXT = ("card", "pan", "cardholder", "credit", *_CVV_LITERALS)
_TRUNCATED_PAN_RE = re.compile(_TRUNCATED_PAN)


def _text_has_card_context(text: str, lowered: str) -> bool:
    """Whether this text holds anything a CVV could belong to.

    A 3-4 digit group with no card anywhere near it is a status code, a count
    or an amount, and a CVV is worth nothing without its PAN. Rules 15 and 16
    have already run, so a PAN is a bare truncation by now -- the star run is
    what recognises it, as the words cover a card-named key in the text.
    """
    if any(word in lowered for word in _CARD_CONTEXT):
        return True
    # A PAN the card rule has already truncated: rule 15 runs first, so by now
    # the digit run _CARD_SHAPE looks for is gone and the truncation is the
    # only card context left in the text. Without this, a CVV sitting beside a
    # masked PAN stops being masked -- which is a leak, not a formatting bug.
    return _CARD_SHAPE.search(text) is not None or _TRUNCATED_PAN_RE.search(text) is not None


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


def _rule(pack, regex, repl, gate, scan=None, prose_only=False, precondition=None):
    return (pack, regex, repl, gate, scan, prose_only, precondition)


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
    # 15. Card number — truncated, bare (411111******1111; last 4
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
    # The loosest rule in the file, and now doubly fenced. It never sees a
    # whole scalar field value (prose_only): there, "000" is a PSP response
    # code, not a CVV, and the key says which. In prose it fires only when the
    # same text carries card context, because a 3-4 digit group with no card
    # anywhere near it is a status, a count or an amount -- and a CVV is worth
    # nothing without the PAN it belongs to. A keyword-anchored CVV is already
    # rules 4, 5 and 9's job, whatever else the text holds.
    _rule(
        "pci",
        r"(?:^|(?<=\s))\d{3,4}(?=\s|$)",
        _standalone_cvv,
        _has_three_digits,
        prose_only=True,
        precondition=_text_has_card_context,
    ),
)


RULES: tuple[Rule, ...] = tuple(
    Rule(f"{index}:{repl.__name__}", pack, re.compile(regex, re.IGNORECASE), repl, gate, scan, pre, prose)
    for index, (pack, regex, repl, gate, scan, prose, pre) in enumerate(_RULE_TABLE, start=1)
)


# Just the card rule, for mask_card_value: the value already has a card key
# saying what it is, so the other rules have nothing to add and applying them
# would mask by shape inside a field that is not about them.
_CARD_RULE_ONLY: tuple[Rule, ...] = tuple(
    rule for rule in RULES if rule.repl is _mask_truncated_card
)


@lru_cache(maxsize=64)
def scalar_rules(rules: tuple[Rule, ...]) -> tuple[Rule, ...]:
    """``rules`` minus the ones that may only run over prose.

    Cached on the rule tuple so the result is a stable object: mask_by_patterns
    keys its known-clean set on tuple identity.
    """
    return tuple(rule for rule in rules if not rule.prose_only)


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
        # No case-folded text to judge a precondition by, so every rule runs:
        # masking more than necessary is the safe direction to fail in.
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
        # Re-asked on every version of the text, like a gate: masking a PAN
        # replaces it with a bare truncation, which still reads as card context
        # rather than removing it, so a later pass can only become more
        # permissive — never less.
        if rule.precondition is not None and not rule.precondition(text, lowered):
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
# payloads use (phonenumber, cardcvv, nameoncard); its known false positives are
# SAFE_KEYS.
#
# Five types are NOT here, because a substring was the wrong test for them and
# each has a named predicate instead (see classify_key, which spells the order
# out): `card` and `sad`, matched precisely -- "card" alone is in card_id and
# discard; `cvv`, which is released when the key is about one
# (`cvv_required`); `secret`, where the credential word must END the key, so
# `schemeTokenProvisioningMode` is not a token; and `name`, which needs a person
# qualifier, so `domainName` is not a person.
KEYWORD_REGEX_FIELD_TYPE = (
    (_PAYMENT_ID_KEYWORD, "payment_id"),
    (_EMAIL_KEY_WORDS, "email"),
    (_PHONE_KEY_WORDS, "phone"),
    (_ADDRESS_KEY_WORDS, "address"),
    (_GENERIC_PII_KEY_WORDS, "generic"),
)

KEYWORD_PATTERN_FIELD_TYPE = tuple(
    (re.compile(regex, re.IGNORECASE), field_type)
    for regex, field_type in KEYWORD_REGEX_FIELD_TYPE
)

_KEY_SEPARATORS = re.compile(r"[_\-.\s]+")
_KEY_SPLIT = re.compile(r"[_\-.\s]+|(?<=[a-z0-9])(?=[A-Z])")


@lru_cache(maxsize=32)
def _joined_names(names: frozenset[str]) -> frozenset[str]:
    """The same names with separators removed, so a key listed as `pg_name`
    also matches `pgName`. Cached on the set: a service has one."""
    return frozenset(_KEY_SEPARATORS.sub("", name) for name in names)


_SAFE_KEYS_JOINED = _joined_names(SAFE_KEYS)


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


# Sensitive Authentication Data that is not the CVV: the magnetic-stripe image,
# its chip equivalent, and the PIN. PCI DSS forbids storing these after
# authorization in ANY form — unlike a PAN there is no truncation to keep, so
# the value is destroyed outright. They matter most inside a card object, whose
# leaves are walked since 0.13.0; before that the container collapsed and these
# never reached a log by name.
_SAD_KEY_WORDS = frozenset({
    "track1", "track2", "track3", "trackdata", "track1data", "track2data", "track3data",
    "track2equivalent", "track2equivalentdata",
    "magstripe", "magstripedata", "magneticstripe", "magneticstripedata",
    "pin", "pinblock", "pincode", "cardpin", "atmpin",
    "emvrequest", "emvresponse", "emvdata", "emvtags", "iccdata", "chipdata", "de55", "field55",
})

# `track` and `magnetic` on their own are the stripe only as the head of a key
# that names the data -- `track`, `raw_track`, `trackTwo`. Followed by an id-ish
# word they name a payment: KNET's `track_id` and the "Track ID" line in every
# Connect payment's details went out as [SAD-MASKED] in 0.13.0, and SAD can
# never be listed as safe, so nothing could undo it.
_TRACK_HEADS = ("track", "magnetic")
_TRACK_TAILS = frozenset({
    "", "1", "2", "3", "one", "two", "three", "data", "equivalent", "equivalentdata", "image", "raw", "stripe",
})

# A wallet's payment cryptogram and a 3DS authentication value: one-time values
# that authenticate a transaction, which nothing reads in a log. Matched at the
# END of the key, so a verdict about one (`cavvResponseCode`) is not one.
_SAD_KEY_ENDING = re.compile(r"(?:cryptogram|cavv|tavv|aav|ucaf(?:authenticationdata)?)(?:value|data)?$")


def _is_sad_key(joined: str, words: list[str]) -> bool:
    # Whole words, never substrings: "pin" is inside shipping and mapping,
    # "track" inside backtrack. The glued form is checked too, for track2data.
    if joined in _SAD_KEY_WORDS or any(word in _SAD_KEY_WORDS for word in words):
        return True
    if _SAD_KEY_ENDING.search(joined):
        return True
    for head in _TRACK_HEADS:
        if head in words:
            at = len(words) - 1 - words[::-1].index(head)
            if "".join(words[at + 1 :]) in _TRACK_TAILS:
                return True
    return False


# A CVV word anywhere in the key names the value -- unless what follows it names
# something ABOUT one. Fail closed: `cvv_input`, `cvv_hash` and a plural are the
# value, because a new spelling of a CVV must not read through for want of a
# list entry; only a recognised "about" tail (`cvv_required`, MPGS's
# `cardSecurityCodeError`) is released. Matched on the separator-free key: the
# old substring search ran on the lowercased key, where `-` survives, so
# `security-code` shipped in clear.
_CVV_GLUED = re.compile(r"cvv|cvc|securitycode|verificationvalue")
_CVV_WORDS = frozenset({"csc", "cvd", "cvd2", "cvn", "cvn2", "cav2", "cvnumber", "cardcode"})
_CVV_WORD_PAIRS = (("card", "code"), ("cv", "number"))
_CVV_ABOUT = re.compile(
    r"(?:is|was)?(?:required|requirement|present|presence|provided|indicator|result|response|check|"
    r"status|match|error|policy|enabled|disabled|mode|supported|length|len|size|format|type|verified|"
    r"verification|valid|invalid|attempt|allowed|optional|mandatory|label|placeholder|message|hint|"
    r"description|for|iframe|only)\w*"
)


def _is_cvv_key(joined: str, words: list[str]) -> bool:
    last = None
    for last in _CVV_GLUED.finditer(joined):
        pass
    if last is not None:
        tail = joined[last.end() :]
    else:
        at = next((i for i, word in enumerate(words) if word in _CVV_WORDS), None)
        if at is None:
            at = next(
                (i + 1 for i in range(len(words) - 1) if (words[i], words[i + 1]) in _CVV_WORD_PAIRS),
                None,
            )
        if at is None:
            return False
        tail = "".join(words[at + 1 :])
    return not (tail and _CVV_ABOUT.fullmatch(tail))


# A person's national identity number, named by its key. Words for the short
# forms (`qid`, `cpr`, `nid` are too short to find inside a longer word),
# substrings for the glued ones (`customer_civil_id`, `nationalIdNumber`).
# Kuwait's civil id is 12 digits, which the `pci` card rule truncates only by
# accident; a service without that pack shipped it whole.
_NATIONAL_ID_WORDS = frozenset({"ssn", "sin", "tin", "cpr", "nid", "qid", "iqama", "aadhaar", "passport"})
_NATIONAL_ID_GLUED = re.compile(r"socialsecurity|nationalid|civilid|taxid|emiratesid")


def _is_national_id_key(joined: str, words: list[str]) -> bool:
    return (
        any(word in _NATIONAL_ID_WORDS for word in words)
        or _NATIONAL_ID_GLUED.search(joined) is not None
        or joined == "idnumber"
    )


def _is_holder_key(words: list[str]) -> bool:
    # The cardholder's name. A word, not a substring: "holder" is inside
    # placeholder. The glued "cardholder" is already a name keyword.
    return "holder" in words


# Key names only. The content rules have to find a credential anywhere in a
# line; a key name *is* the name of its value, so the credential word is
# matched at the END -- `scheme_token` and `api_token` name a token, while
# `schemeTokenProvisioningMode` and `tokenization_status` name something about
# one. `authorization` must be the whole key: `authorizationCode` is the
# acquirer's approval code, a payment verdict field that Connect's own masking
# deliberately keeps readable.
_CRED_KEY_JOINED = re.compile(
    r"^(?:bearer|basic|digest|credentials?)$"
    # The header under its WSGI (`HTTP_AUTHORIZATION`) and proxy spellings too.
    r"|^(?:http)?(?:proxy)?authori[sz]ation(?:header)?$"
    # A cookie carries the session id, which is a credential.
    r"|^(?:http|set|httpset|session|auth)?cookies?$"
    # The credential word ends the key, or is followed only by a word naming a
    # derivative of it -- `password_hash` is still the password's secret, while
    # `tokenization_status` and `schemeTokenProvisioningMode` are metadata about
    # a token and carry none of it.
    r"|(?:token|secret|password|passwd|passphrase|passcode|pwd)s?(?:hash|digest|value|blob|data)?$"
    r"|(?:secret|private|public|encryption|decryption|signing|"
    r"access|master|root|session|api|hmac|aes|merchant|shared|client)keys?$"
    # MIGS's `vpc_AccessCode`: the merchant access code, a gateway credential.
    r"|accesscode$"
)


def _is_cred_key(joined: str) -> bool:
    return _CRED_KEY_JOINED.search(joined) is not None


# A `*name` key names a PERSON only when something else in the name says which
# person. Matching "name" anywhere made people of `domainName`, `merchantName`,
# `requestorName` and `schemeName`. A bare role word is a person too -- `payer`
# is a container of one -- but `payerInteraction` is an enum about the
# interaction, not a payer.
_PERSON_ROLES = frozenset({"name", "names", "cardholder", "beneficiary", "recipient", "payer", "holder"})
_PERSON_QUALIFIERS = (
    "customer", "payer", "payee", "holder", "card", "first", "last", "middle",
    "full", "given", "family", "sur", "nick", "account", "beneficiary",
    "recipient", "sender", "buyer", "shopper", "billing", "shipping", "contact",
    "person", "owner", "applicant", "guest", "passenger", "user",
)


def _is_name_key(joined: str) -> bool:
    if joined in _PERSON_ROLES:
        return True
    if "name" not in joined:
        return False
    return any(qualifier in joined for qualifier in _PERSON_QUALIFIERS)


# A bare `name` is a person's unless its container names a thing: the payment
# method's `name` is "Visa/Mastercard", MPGS's `interaction.merchant.name` is
# the merchant's display name. Words, singular or plural, never substrings --
# `profile` is not `file`, `upgrade` is not `pg` -- and a person word anywhere
# in the container's name wins (`merchant_owner`, `bank_account`, `card`).
_THING_WORDS = frozenset({
    "method", "gateway", "pg", "bank", "brand", "scheme", "network", "product", "item", "merchant",
    "store", "plugin", "provider", "service", "currency", "country", "interaction", "device", "browser",
    "acquirer", "issuer", "wallet", "plan", "option", "header", "queue", "task", "event", "file",
    "category", "template", "theme",
})
# These describe fields AND carry submitted ones: `form_fields.name` is the name
# field's settings, `params.name` is what someone typed. Only a `name` holding a
# container is a thing here.
_DEFINITION_WORDS = frozenset({"form", "field", "param", "parameter", "attribute"})
_PERSON_CONTEXT = frozenset({
    *_PERSON_QUALIFIERS, *_PERSON_ROLES,
    "owner", "member", "subscriber", "attendee", "employee", "staff", "director", "representative",
    "signatory", "profile", "kyc", "driver", "patient",
})


def _singular(word: str) -> str:
    if word.endswith("ies") and len(word) > 4:
        return word[:-3] + "y"
    if word.endswith("s") and len(word) > 3 and not word.endswith("ss"):
        return word[:-1]
    return word


@lru_cache(maxsize=1024)
def name_context(container: str) -> str | None:
    """What a bare `name` directly under ``container`` names: ``"thing"``,
    ``"definition"`` (a thing only if it holds a container), or None -- a
    person, which is also the answer for a container nothing recognises."""
    words = [_singular(word.lower()) for word in _KEY_SPLIT.split(container) if word]
    if any(word in _PERSON_CONTEXT for word in words):
        return None
    if any(word in _THING_WORDS for word in words):
        return "thing"
    if any(word in _DEFINITION_WORDS for word in words):
        return "definition"
    return None


# A name ending in one of these names the CVV or credential itself, which no
# service may list as safe; "cvv_required" or "tokenization_status" only
# describe one. Matched on the lowercased key with separators removed.
_NEVER_SAFE_ENDING = re.compile(
    r"(?:cvv2?|cvc2?|securitycode"
    r"|token|secret|password|passwd|credentials?|authori[sz]ation|bearer|basic|digest"
    r"|(?:secret|private|public|encryption|decryption|signing|access|master|root|session|api)key)$"
)


# What a service may never list as safe, by the type the classifier gives it.
_NEVER_SAFE_TYPES = frozenset({"card", "cvv", "sad", "secret"})


def never_safe(key: str) -> bool:
    """Whether no service may list ``key`` as safe: anything the classifier
    calls a card, CVV, SAD or credential, or a name ending in a CVV or
    credential word.

    It asks the classifier rather than repeating it: the separate suffix list
    had drifted, and accepted `cvv_number`, `password_hash` and `tokens` --
    names the classifier masks -- so listing one switched its mask off.

    Expiry is not here. It is no longer masked at all, so refusing to let a
    service whitelist a key that nothing masks would say nothing.
    """
    lowered = key.lower()
    joined = _KEY_SEPARATORS.sub("", lowered)
    words = [word.lower() for word in _KEY_SPLIT.split(key) if word]
    return (
        _is_card_key(lowered, joined, words)
        or _is_sad_key(joined, words)
        or _NEVER_SAFE_ENDING.search(joined) is not None
        or classify_key(key, ALL_PACKS) in _NEVER_SAFE_TYPES
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
    joined = _KEY_SEPARATORS.sub("", lowered)
    # Both spellings. A safe key is listed one way ("domain_name") and the
    # payload writes it the other ("domainName"); looking up only the
    # lowercased key meant every safe key silently stopped working in camelCase.
    if lowered in SAFE_KEYS or lowered in safe:
        return None
    if joined in _SAFE_KEYS_JOINED or joined in _joined_names(safe):
        return None
    words = [word.lower() for word in _KEY_SPLIT.split(key) if word]
    # Order is load-bearing, so it is written out rather than left implicit in a
    # table. Card is checked after CVV and before credentials, so "cardtoken"
    # stays a secret. Expiry is NOT classified: it is Cardholder Data, not
    # Sensitive Authentication Data, so PCI DSS permits storing it and masking
    # it only cost the ability to read an expired-card decline. Unclassified,
    # its value still reaches the content rules, so a PAN pasted into an expiry
    # field is still truncated.
    if _is_sad_key(joined, words):
        return "sad"
    if _is_cvv_key(joined, words):
        return "cvv"
    for pattern, field_type in KEYWORD_PATTERN_FIELD_TYPE:
        if field_type == "payment_id":
            # The two name-matched types sit here, between CVV and payment_id,
            # which is where their regexes used to sit in the table.
            if _is_card_key(lowered, joined, words):
                return "card"
            if _is_cred_key(joined):
                return "secret"
            # Before the pack gate and before `generic`: a person's identity
            # number is PII in every service (`customer_civil_id` too).
            if _is_national_id_key(joined, words):
                return "ssn"
            if "financial_ids" not in packs:
                continue
        if field_type == "phone" and _is_tel_key(words):
            return "phone"
        if field_type == "generic" and (_is_name_key(joined) or _is_holder_key(words)):
            # Also between address and generic, as before.
            return "name"
        if pattern.search(lowered):
            return field_type
    return None


def check_if_sensitive_keyword(dict_key: str) -> str | None:
    """classify_key with every pack on."""
    return classify_key(dict_key, ALL_PACKS)
