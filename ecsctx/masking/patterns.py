"""Content and key-name rules for MaskPIIFilter.

Ported from ottu_pg's MaskPIIFilter (utils/log/filters.py), merged with
ecsctx's own PII key-name list. Two independent detection strategies:

1. Content-based (RULES): 24 ordered rules in three packs — `default`
   always on, `pci` and `financial_ids` opt-in (ecsctx.masking.config) — each
   behind a literal pre-check, applied to every string the filter reaches.
   Rule order is load-bearing — see the comments on each rule and the
   ordering invariants they protect. Do not reorder. Before any of them reads
   a string, what a service's keep rule ships as sent is set aside
   (stash_kept), and put back after.
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

import ast
import contextlib
import html
import json
import re
from bisect import bisect_left
from collections import deque
from collections.abc import Callable, Iterator, Mapping
from functools import lru_cache
from heapq import merge
from itertools import accumulate, pairwise
from operator import methodcaller
from typing import Any, NamedTuple
from urllib.parse import unquote

from ecsctx.masking.tokens import (
    _CARDLESS_TOKEN,
    _TOKEN,
    _TOKEN_LENGTH,
    _TOKEN_SHAPE,
    _TOKEN_START,
    _TRUNCATED_PAN,
    already_masked,
    make_label,
    mask_by_field_type,
)
from ecsctx.masking.value_rules import (
    KEEP,
    DuplicateKey,
    applicable,
    hinted,
    is_keep_rule,
    json_as_written,
    keep_rules,
    label_rules,
    rule_of,
    ruling,
    text_ruling,
)

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

# Authorization / Authorisation (+ _header). Apart from the other keywords:
# its value is a scheme and a credential, one value (rule 7).
_AUTH_KEYWORD = r"authori[sz]ation(?:[_-]?header)?"
# The HTTP authentication schemes an Authorization header's credential
# follows (RFC 9110 11.4), and the one Ottu's API names `Api-Key`.
_AUTH_SCHEME = r"(?:bearer|basic|digest|token|negotiate|api[_-]?key)"
# Sensitive credential keywords / auth schemes, but Authorization. Matched
# case-insensitively. Bare "key" is intentionally excluded — only sensitive
# *_key compounds — so cache_key / sort_key / primary_key are not over-masked.
_OTHER_CRED_KEYWORD = (
    r"(?:"
    r"bearer|basic|digest|credentials?"  # auth schemes
    r"|(?:[\w-]{0,128}[_-])?(?:token|secret|password|passwd)"  # *_token / *_secret / *_password
    r"|(?:secret|private|public|encryption|decryption|signing|"  # sensitive *_key compounds only
    r"access|master|root|session|api)[_-]?key"
    # Key material named for its algorithm, size or mode (`aes256_key`), or
    # written out in an encoding (`private_key_pem`), for text that is not valid
    # JSON. One size and one mode at most: a repeated `\d+` group backtracks
    # exponentially.
    r"|(?:aes|3?des|triple[_-]?des|hmac|rsa)(?:[_-]?\d+)?(?:[_-]?(?:gcm|cbc|sha\d*))?[_-]?key(?:[_-]?(?:pem|der|hex|base64|b64))?"
    r"|(?:secret|private|public)[_-]?key[_-]?(?:pem|der|hex|base64|b64)"
    r")"
)
_CRED_KEYWORD = rf"(?:{_AUTH_KEYWORD}|{_OTHER_CRED_KEYWORD})"

# Card verification code keywords — cvv/cvc/security code are all the same
# thing under different names depending on card scheme/vendor terminology. The
# key rule's words (_is_cvv_key): cvv, cvc, cvn, cvd and their "2"s, csc, cav2,
# security code, verification value, card code, cv number; glued to "card"
# (`cardCvv`, `CardSecurityCode`), after a prefix ending in `_` or `-`
# (`vpc_CardSecurityCode`, `x-cvv`), or after a camelCase word (`paymentCvv`,
# `savedCardCvv`: a lower-case letter or digit, then the keyword's capital,
# case-sensitive), where `\b` cannot find the word. The rules need the keyword
# to end the key, so `cvv_required=true` names something about one and is left
# alone.
_CVV_KEYWORD = (
    r"(?:[\w-]{0,64}[_-]|(?-i:[A-Za-z0-9]{0,63}[a-z0-9](?=[A-Z])))?(?:card[-_]?)?"
    r"(?:cv[vcnd]2?|csc|cav2|security[-_.\s]?code|verification[-_.\s]?value|card[-_.\s]?code|cv[-_.\s]?number)"
)

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




# Where a credential value in text ends: as a form value does in
# contrib.net's redact_body, at its delimiter, not at the first character
# outside a fixed class -- a backslash, `@` or an apostrophe left the rest of
# the value in clear. An unquoted value ends at whitespace, `&`, `;`, `,`, a
# closing bracket or a closing quote; `#` and anything else stays inside it,
# since masking too much is the safe side to err on.
_VALUE_END = r"\s&;,)\]}>"
# A character of an unquoted value: neither an end, a quote nor a backslash.
_PLAIN = rf"[^{_VALUE_END}\"'\\]"
# A backslash and the character it escapes, unless that is a quote.
_ESCAPED = r"\\[^\"']"
# A value never runs into a label masking wrote (`abc[SECRET-MASKED]`): a `]`
# ends it, so it would cut the label (`[SECRET-MASKED]]`), and a label that
# redact_body wrote after a short value made it long enough to mask again.
_NOT_A_LABEL = r"(?!(?-i:\[[A-Z0-9-]+-MASKED[\]:]))"
# ...nor into an end tag: in `<note>password=abc</note>` the element's text,
# and so the value, ends there, as a form value in redact_body does. Read on,
# the value took the tag with it, and the next pass hashed its token again.
_NOT_AN_END_TAG = r"(?!</)"
# Quotes, escaped or not, with more of the value after them: `abc\"def` is
# one value. A quote closes the string the value sits in where nothing of the
# value follows it (`{"note": "password=abc"}`), or where what follows is the
# structure redact_body keeps at a value's end: a JSON key's `":`, or an XML
# element's `/>` (`<Auth apikey=\"…\"/>` in a JSON string).
_INNER_QUOTES = rf"(?:\\?[\"'])+(?!:|/>)(?={_NOT_A_LABEL}{_NOT_AN_END_TAG}(?:{_PLAIN}|{_ESCAPED}))"
_VALUE_UNIT = rf"(?:{_NOT_A_LABEL}{_NOT_AN_END_TAG}(?:{_PLAIN}|{_ESCAPED}|{_INNER_QUOTES}))"
# A value's first character: never a quote, which is the structure around a
# value, nor an opening bracket: `{` and `[` open a container (JSON text the
# key walk re-serialised), `[` also a label masking already wrote.
_VALUE_START = rf"(?:[^{_VALUE_END}\"'\\\[{{(<]|{_ESCAPED})"
_UNQUOTED_VALUE = rf"{_VALUE_START}{_VALUE_UNIT}*"


# A character of a URL's userinfo in text: the netloc ends at a path, query,
# fragment, whitespace or a quote or angle bracket around the URL.
_USERINFO_PART = r"[^\s/?#\"'<>]"


# A character of a value between escaped quotes -- JSON in a JSON string,
# `{\"password\": \"a b\"}` -- read as the inner string reads it: an
# escaped backslash with the (escaped) character it escapes, another escape, or
# a plain character. The value ends at an escaped quote no inner backslash
# escapes.
_ESCAPED_QUOTED_UNIT = r'(?:\\\\(?:\\\\|\\"|\\[^\\"]|[^\\"])|\\[^\\"]|[^\\"])'


def _quoted_body(quote: str) -> str:
    """A quoted value's characters, up to the unescaped closing quote the named
    group ``quote`` opened: escape-aware, so `ab\"cd` is one value."""
    return rf"(?:(?!(?P={quote}))[^\\]|\\[\s\S])"


def _quoted_value_body(quote: str) -> str:
    """...for a value after `key=`: never into an end tag, as an unquoted one
    and redact_body's form value are not. Read across one, the value that
    redact_body left before a tag (`token="<token>></token>"`) was hashed
    again."""
    return rf"(?:(?!(?P={quote})|</)[^\\]|\\[\s\S])"


# A value that is already a PII token (ptok:v1:…), which a key rule or an
# earlier pass put there: masking it again would tokenize "ptok" and break it.
# Only the exact shape, all of it (case-sensitive, as ecsctx emits it), though
# a sentence may go on after it: "password=ptok:v1:…." ends at the full stop.
# Not one with a card-number run in it: that is `ptok:v1:` typed before a card
# number, and the rule masks it as any other value (mask_by_field_type). A `#`
# after it opens a URL's fragment (redact_url's `?password=<token>#…`): `#` is
# part of a value, but read on into the fragment the token was hashed again.
_WHOLE_TOKEN = rf"(?-i:{_CARDLESS_TOKEN})(?=\.*(?:#|(?!{_VALUE_UNIT})))"

# ISO country codes in the SWIFT IBAN registry, and the length of each one's
# IBANs.
_IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BR": 29, "BY": 28,
    "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18,
    "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22,
    "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20,
    "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18,
    "NO": 15, "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "SA": 24, "SC": 31, "SD": 18,
    "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25, "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22,
    "VG": 24, "XK": 20,
}
# The country codes, as a regex alternation.
_IBAN_PREFIX = "|".join(_IBAN_LENGTHS)

# Card number rules, shared building blocks. Real-world PANs range 12-19
# digits (ISO/IEC 7812 caps at 19; Maestro issues from 12). Whitespace, a
# hyphen and the invisible characters a copy or an editor leaves between digits
# separate their groups. A Unicode dash does between card-style groups -- an
# editor turns a typed "-" into an en dash -- and elsewhere joins a range of two
# numbers. A dot, comma or underscore never does.
#
# The phone and SSN rules put a one-character lookahead for their first
# character in front of the lead guard: it rejects most positions before the
# costlier lookbehind runs, without changing what matches.
#
# _CARD_LEAD_GUARD (the phone and SSN rules): a match may only start right
# after a real prefix (quote, "([{", ":", "=", space, comma, dot, or
# start-of-string), not mid-digit-run or glued to a letter. The extra (?<!\d )
# blocks a space that's itself preceded by a digit, so a differently-grouped
# longer number's tail chunk isn't mistaken for a fresh match. The card rule
# reads a whole run of groups instead, and judges it with Luhn: _CardRun.
# _PHONE_TAIL_GUARD: a match may not be followed by more digits, nor by a
# letter — a digit run that runs into letters is part of an id (a hex
# session_id starting with digits), and the phone rule runs in every service,
# not only PCI ones — nor by a truncation's stars and last four: digits running
# into those are a truncated card number's first six.
_UNICODE_DASHES = "\u2010\u2011\u2012\u2013\u2014\u2015\u2212\ufe58\ufe63\uff0d"
_INVISIBLE_SEPARATORS = "\u00ad\u200b\u200c\u200d\u2060\ufeff"
_CARD_SEP = rf"[\s\-{_UNICODE_DASHES}{_INVISIBLE_SEPARATORS}]"
_NUMBER_PREFIX = ",.:=\"'([{"
_CARD_LEAD_GUARD = rf"(?:^|(?<=[\s{re.escape(_NUMBER_PREFIX)}]))(?<!\d )"
_PHONE_TAIL_GUARD = r"(?![-\s]?\d)(?![A-Za-z])(?!\*{4,}\d{4})"
# The shortest PAN issued. A value with fewer digits than this cannot be one.
_MIN_PAN_DIGITS = 12
_MAX_PAN_DIGITS = 19
# E.164: a phone number has at most 15 digits, country code included.
_PHONE_MAX_DIGITS = 15
# What the card rule reads, as a whole: a run of digits joined by single
# separators, with at least a card number's digits in it. A letter may end it:
# Track 2 equivalent data puts a "D" separator straight after the PAN.
_CARD_RUN = rf"(?<!\d)(?=\d(?:{_CARD_SEP}?\d){{{_MIN_PAN_DIGITS - 1}}})\d(?:{_CARD_SEP}?\d)*"


def _digits_only(text: str) -> str:
    return "".join(c for c in text if c.isdigit())


# Every CVV rule replaces the match with this, whatever it matched: PCI forbids
# keeping a CVV in any form, so there is no value to carry and nothing to
# tokenize. Stated directly rather than via mask_by_field_type('', 'cvv'),
# which made these rules depend on how an empty value is rendered.
_CVV_LABEL = f"[{make_label('cvv')}]"
_SECRET_LABEL = f"[{make_label('secret')}]"



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


_DIGIT_GROUP = re.compile(r"\d+")
_NOT_DIGIT = re.compile(r"\D")
# A truncation's stars and last four, which its first six run into. Matched
# from the first star only: tried from every star of a long run, each attempt
# read to the end of it.
_MASKED_REST = re.compile(r"(?<!\*)\*{4,}\d{4}")
_DASH_CHARS = "-" + _UNICODE_DASHES
# An ASCII digit's value, and the value Luhn doubles it to (its digits summed).
_DIGIT_VALUE = bytes.maketrans(b"0123456789", bytes(range(10)))
_DOUBLED_VALUE = bytes.maketrans(b"0123456789", bytes((0, 2, 4, 6, 8, 1, 3, 5, 7, 9)))
# An IBAN's country code and two check digits, at the start of a word, as the
# first two digits of a run. Case-sensitive, as rule 16 is.
_IBAN_HEAD = re.compile(rf"(?<![^\W_])(?:{_IBAN_PREFIX})\d\d(?!\d)")
# ...or with groups of four after them, and part of one, ending right before a
# run: the bank code has letters in it ("GB33 BUKB 2020 ...", "IT60 X054 ...").
_IBAN_BEFORE_RUN = re.compile(rf"(?<![^\W_])(?:{_IBAN_PREFIX})\d\d(?: [A-Z0-9]{{4}})*(?: [A-Z0-9]{{0,3}})\Z")
# One group of an IBAN printed in fours: after a single space, and not running
# into more letters or digits.
_IBAN_GROUP = re.compile(r" ([A-Z0-9]{1,4})(?![A-Z0-9])")
# The longest IBAN in groups of four, spaces included, before a run in it.
_IBAN_REACH = 44


def _iban_end(text: str, head: int) -> int | None:
    """Where the IBAN whose country code is at ``head`` ends: at its country's
    length, printed in groups of four joined by single spaces, when its check
    digits hold (ISO 13616: the number with its first four characters moved to
    the end, letters as 10-35, is 1 mod 97). None when the groups there do not
    make that length, or the check digits do not hold: then it is no IBAN."""
    wanted = _IBAN_LENGTHS[text[head : head + 2]] - 4
    characters, position = [], head + 4
    while wanted:
        group = _IBAN_GROUP.match(text, position)
        if group is None or len(group.group(1)) != min(4, wanted):
            return None
        characters.append(group.group(1))
        wanted -= len(group.group(1))
        position = group.end()
    rearranged = "".join(characters) + text[head : head + 4]
    return position if int("".join(str(int(character, 36)) for character in rearranged)) % 97 == 1 else None


def _card_style(sizes: list[int]) -> bool:
    """Grouped the way card numbers are printed: in fours with a last group of
    any length, or Amex's 4-6-5."""
    return (len(sizes) >= 3 and all(size == 4 for size in sizes[:-1])) or sizes == [4, 6, 5]


class _CardRun:
    """One run of digit groups joined by separators, as the card rule reads it.

    Two readings of the same digits, and the output truncates both:

    - The rule's own, from where a number may start (_read): an unbroken run
      of 12-19 digits is a card number wherever it stands; a number written in
      groups is one card when it is 12-19 digits to the end of the run and does
      not follow digits that could start the same, longer number.
    - Every stretch of whole groups, 12-19 digits long, that passes Luhn
      (_windows). Where a separator admits one card or a card beside another
      number, Luhn decides; truncating each such stretch, overlapping ones as
      one span, means no output shows more than the first six and last four of
      a Luhn-valid reading -- but for the digits neither reads, which belong
      to something else: an IBAN's, a word's own or a truncation's, a phone
      number's after "+", and a range's across its dash (_windows).
    """

    def __init__(self, text: str, start: int, end: int) -> None:
        self.text = text
        self.start = start
        run = text[start:end]
        groups = _DIGIT_GROUP.findall(run)
        # One separator character between each two groups, so a group's place
        # in the text follows from the digits and separators before it.
        self.seps = _NOT_DIGIT.findall(run)
        self.sizes = list(map(len, groups))
        self.offsets = [0, *accumulate(self.sizes)]
        digits = "".join(groups)
        if not digits.isascii():
            digits = "".join(str(int(digit)) for digit in digits)
        plain = list(digits.encode().translate(_DIGIT_VALUE))
        doubled = list(digits.encode().translate(_DOUBLED_VALUE))
        # Luhn sums with the odd, or the even, positions doubled, as prefix
        # sums: any stretch's Luhn sum is one subtraction.
        odd, even = plain[:], doubled[:]
        odd[1::2], even[1::2] = doubled[1::2], plain[1::2]
        self.odd, self.even = [0, *accumulate(odd)], [0, *accumulate(even)]
        # A truncation the rule made, read again by a later pass: its last four
        # follow its stars, its first six run into them. Neither is a number.
        self.lo = 1 if self.sizes[0] == 4 and text[max(0, start - 4) : start] == "****" else 0
        self.masked_after = self.sizes[-1] == 6 and _MASKED_REST.match(text, end) is not None
        self.hi = len(self.sizes) - 1 if self.masked_after else len(self.sizes)
        self.before = text[start - 1] if start else ""
        # The run's leading groups that are an IBAN's: one whose country code
        # is right before its first two digits, or before its groups right
        # before the run. Only the IBAN itself, never what follows it. After a
        # bank code with letters ("GB33 BUKB "), a run is read as any other
        # unless the IBAN holds all of it: those digits could start a number of
        # their own.
        # Every such head is tried: a group can itself look like a country code
        # and check digits ("GE52 GT35 7010 ...", the bank code "GT35").
        self.iban_groups = 0
        heads = []
        if self.sizes[0] == 2 and start >= 2 and _IBAN_HEAD.match(text, start - 2) is not None:
            heads.append((start - 2, start))
        position = max(0, start - _IBAN_REACH)
        while (before := _IBAN_BEFORE_RUN.search(text, position, start)) is not None:
            heads.append((before.start(), end))
            position = before.start() + 1
        for head, reach in heads:
            if (iban_end := _iban_end(text, head)) is not None and iban_end >= reach:
                # Its groups end where a group of the run does: one separator
                # character between each two.
                covered = 0
                while covered < len(self.sizes) and start + self.offsets[covered + 1] + covered <= iban_end:
                    covered += 1
                self.iban_groups = covered
                break

    def spans(self) -> list[tuple[int, int]]:
        """The character spans to truncate, overlapping readings merged."""
        if self.lo >= self.hi:
            return []
        # A Unicode dash between groups that are not card-style joins a range
        # of two numbers: each side is read on its own, and no stretch crosses
        # the dash.
        cuts = [] if _card_style(self.sizes) else [
            index + 1 for index, sep in enumerate(self.seps) if sep in _UNICODE_DASHES
        ]
        readings: list[tuple[int, int]] = []
        for first, last in pairwise([self.lo, *(cut for cut in cuts if self.lo < cut < self.hi), self.hi]):
            readings += self._read(first, last)
        merged: list[tuple[int, int]] = []
        # Both lists come in order of their first group.
        for first, last in merge(readings, self._windows(cuts)):
            if merged and first <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], last))
            else:
                merged.append((first, last))
        return [(self.start + self.offsets[first] + first, self.start + self.offsets[last + 1] + last) for first, last in merged]

    def luhn(self, first: int, last: int) -> bool:
        begin, end = self.offsets[first], self.offsets[last + 1]
        sums = self.odd if (end - 1) % 2 == 0 else self.even
        return (sums[end] - sums[begin]) % 10 == 0

    def _read(self, first: int, last: int) -> list[tuple[int, int]]:
        """Groups first..last-1, scanned for where a card number may start, as
        the rule's regex did: an unbroken run is one on its own; the rest of the
        run, 12-19 digits, is one in groups. Luhn decides between the two: the
        unbroken run alone is the card only when it passes Luhn and the whole
        does not (a "15-digit card and a 1" that is really one 16-digit card
        otherwise shows the card's middle)."""
        found: list[tuple[int, int]] = []
        # A reading must not end on digits running into a truncation's stars.
        end_ok = last < self.hi or not self.masked_after
        index = max(first, self.iban_groups)  # none starts inside an IBAN
        while index < last:
            size = self.sizes[index]
            total = self.offsets[last] - self.offsets[index]
            if size < _MIN_PAN_DIGITS and total > _MAX_PAN_DIGITS:
                index += 1  # no reading starts here: too short, and too long to the end
                continue
            kind = self._start(index, first)
            if kind is None:
                index += 1
                continue
            refused = self._refused(index)
            fits = end_ok and _MIN_PAN_DIGITS <= total <= _MAX_PAN_DIGITS
            whole = (
                kind != "plus" and fits and not refused and (kind != "letter" or _card_style(self.sizes[index:last]))
            )
            if kind != "letter" and _MIN_PAN_DIGITS <= size <= _MAX_PAN_DIGITS and (
                kind != "plus" or size > _PHONE_MAX_DIGITS
            ):
                if whole and last - index > 1 and not (self.luhn(index, index) and not self.luhn(index, last - 1)):
                    found.append((index, last - 1))
                    break
                found.append((index, index))
                index += 1
                continue
            if whole:
                long = next((k for k in range(index, last) if self.sizes[k] >= _MIN_PAN_DIGITS), None)
                if long is not None and self.luhn(long, long) and not self.luhn(index, last - 1):
                    found.append((long, long))
                else:
                    found.append((index, last - 1))
                break
            if refused and fits and kind != "plus":
                # One longer number, left whole but for an unbroken run in it.
                found += [(k, k) for k in range(index, last) if _MIN_PAN_DIGITS <= self.sizes[k] <= _MAX_PAN_DIGITS]
                break
            index += 1
        return found

    def _start(self, index: int, first: int) -> str | None:
        """How a card number may start at group ``index``: "free" (after a real
        prefix), "plus" (after a "+" -- only an unbroken run longer than a phone
        number), "letter" (glued to a word -- only in card-style groups), or not
        at all."""
        if index > first:
            return "free" if self.seps[index - 1].isspace() else None
        if first > self.lo:
            return None  # after a dash that joins a range
        if self.lo == 1:
            return "free" if self.seps[0].isspace() else None  # after a truncation
        before = self.before
        if not before or before.isspace() or before in _NUMBER_PREFIX:
            return "free"
        if before == "+":
            ahead = self.text[self.start - 2] if self.start >= 2 else ""
            return "plus" if not ahead or ahead.isspace() or ahead in _NUMBER_PREFIX else None
        return "letter" if before.isalpha() else None

    def _refused(self, index: int) -> bool:
        """Whether a number in groups starting at ``index`` would be the tail of
        one longer number: the digits before the space could start the same
        number when they stand free, are a hyphenated group, a word's own
        ("req42") or an IBAN's last group -- unless they are a card number
        themselves. Digits glued to a "+", a truncation's stars or other
        punctuation end there, as do "INV-2026"'s: a hyphenated id."""
        if index == 0 or self.seps[index - 1] != " ":
            return False
        previous = index - 1
        if _MIN_PAN_DIGITS <= self.sizes[previous] <= _MAX_PAN_DIGITS:
            return False
        if previous > 0:
            return True  # a group of a longer number
        if self.lo == 1:
            return False  # a truncation's last four
        before = self.before
        if not before or before.isspace() or before in _NUMBER_PREFIX or before.isalpha():
            return True
        if before in _DASH_CHARS:
            return not (self.start >= 2 and self.text[self.start - 2].isalpha())
        return False

    def _windows(self, cuts: list[int]) -> list[tuple[int, int]]:
        """Every stretch of whole groups, 12-19 digits long, that passes Luhn,
        except over digits that belong to something else: an IBAN's; a word's
        own ("REF4111...", "INV-2026", a UUID's "a456-4266..."); a
        truncation's last four; a phone number's after "+", on their own; and
        across a range's dash (``cuts``). Digits glued to a letter or to a
        truncation's stars that start a Luhn-valid card number of their own, in
        card-style groups ("Payer5123 4500 0000 0008 12 25"), are a card's, not
        the word's or the truncation's: stretches start in them as anywhere."""
        free = max(self.lo, self.iban_groups)  # where a stretch may start
        if free == 0 and (
            self.before.isalpha()
            or (self.before in _DASH_CHARS and self.start >= 2 and self.text[self.start - 2].isalpha())
        ):
            # A word's own digits: the group glued to it, and those it joins by
            # dashes.
            while free + 1 < self.hi and not self.seps[free].isspace():
                free += 1
            free += 1
        bounds = [0, *(cut for cut in cuts if 0 < cut < self.hi), self.hi]
        glued = self.lo == 1 or self.before.isalpha()
        if free and glued and not self.iban_groups and self._starts_a_card(bounds[1]):
            free = 0
        phone = self.before == "+" and self.sizes[0] <= _PHONE_MAX_DIGITS
        found: list[tuple[int, int]] = []
        for first, last in pairwise(bounds):
            if self.offsets[last] - self.offsets[first] < _MIN_PAN_DIGITS:
                continue  # one side of a range, too short for a card number
            for widest, stop in self._widest(first, last, max(first, free)):
                if widest == stop == 0 and phone:
                    continue
                # Merged as they come: ends only grow, so a stretch reaching
                # back over earlier ones swallows them.
                while found and found[-1][1] >= widest:
                    widest = min(widest, found.pop()[0])
                found.append((widest, stop))
        return found

    def _starts_a_card(self, last: int) -> bool:
        """Whether the run's first groups, before ``last``, are a Luhn-valid
        card number in card-style groups: 4-4-x, 4-4-4-x, 4-4-4-4-x or 4-6-5."""
        return any(
            _card_style(self.sizes[: stop + 1])
            and _MIN_PAN_DIGITS <= self.offsets[stop + 1] <= _MAX_PAN_DIGITS
            and self.luhn(0, stop)
            for stop in range(2, min(last, 5))
        )

    def overexposed(self, shown: list[bool]) -> bool:
        """Whether a Luhn-valid stretch of whole groups, 12-19 digits long,
        anywhere in the run -- nothing excluded -- shows more than its first six
        and last four, when ``shown`` says which of the run's digits show. The
        widest stretch ending at a group has the most digits between its first
        six and last four, so it is the only one to look at."""
        count = [0, *accumulate(shown)]
        ends = self.offsets
        return any(
            count[ends[stop + 1] - 4] > count[ends[widest] + 6]
            for widest, stop in self._widest(0, len(self.sizes), 0)
        )

    def _widest(self, first: int, last: int, free: int) -> Iterator[tuple[int, int]]:
        """For each group first..last-1 that ends a stretch passing Luhn, the
        widest such stretch starting at ``free`` or later."""
        ends, odd, even = self.offsets, self.odd, self.even
        # A stretch passes Luhn when its prefix sums at both ends agree, mod
        # 10, in the array that doubles the positions its end leaves doubled.
        # So for each end, the starts 12-19 digits back wait in a queue by
        # their residue, one per array, and the first one waiting that is not
        # yet too far back is the widest stretch ending there.
        waiting = ([deque() for _ in range(10)], [deque() for _ in range(10)])
        begin = free
        for stop in range(first, last):
            end = ends[stop + 1]
            while begin <= stop and end - ends[begin] >= _MIN_PAN_DIGITS:
                waiting[0][odd[ends[begin]] % 10].append(begin)
                waiting[1][even[ends[begin]] % 10].append(begin)
                begin += 1
            doubled_odd = (end - 1) % 2 == 0
            queue = waiting[0 if doubled_odd else 1][(odd if doubled_odd else even)[end] % 10]
            while queue and end - ends[queue[0]] > _MAX_PAN_DIGITS:
                queue.popleft()
            if queue:
                yield queue[0], stop


# A canonical UUID: 8-4-4-4-12 hex digits, with a hex letter among them, and
# nothing alphanumeric touching it. Its hyphens join digit groups as a card
# number's separators do, and 3.4% of random ones hold a run of twelve digits
# or more; it is an id, never a card number. An all-digit string in that shape
# gets no exemption: it is read as any other run of digits.
_UUID = re.compile(
    r"(?<![0-9A-Za-z])(?=[0-9-]{0,35}[A-Fa-f])"
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
    r"(?![0-9A-Za-z])"
)
# How far before a run a UUID holding its first digit can start, and how far
# past its end a UUID's closing boundary is read.
_UUID_LENGTH = 36


def _truncated(text: str, start: int, end: int) -> str:
    """``text[start:end]``, one run the card rule reads, with each card number
    in it truncated and the rest as written."""
    spans = _CardRun(text, start, end).spans()
    parts, copied = [], start
    for first, last in spans:
        parts.append(text[copied:first])
        parts.append(_truncate_pan(_digits_only(text[first:last])))
        copied = last
    parts.append(text[copied:end])
    return "".join(parts)


def _truncated_outside(text: str, start: int, end: int) -> str:
    """``text[start:end]`` with every run in it truncated: the runs are read
    again within these bounds only, so none reaches into a UUID beside them."""
    parts, copied = [], start
    for run in _RUN.finditer(text, start, end):
        parts.append(text[copied : run.start()])
        parts.append(_truncated(text, run.start(), run.end()))
        copied = run.end()
    parts.append(text[copied:end])
    return "".join(parts)


def _mask_card_run(match: re.Match) -> str:
    """The card rule's replacement: each card number in the run truncated, the
    rest as written. Deliberately not mask_by_field_type: that would tokenize
    (or, with PII unconfigured, collapse to a bare label), losing the
    truncation. Emitted bare: the truncation IS the value, and the stars alone
    make it a fixed point -- they break the digit run, and a later pass leaves
    a truncation's first six and last four alone.

    The digits of a canonical UUID are left as written, and the rest of the
    run is read without them: a card number beside a UUID is still truncated,
    and never reads on into it."""
    text, start, end = match.string, match.start(), match.end()
    uuids = [
        found.span()
        for found in _UUID.finditer(text, max(0, start - _UUID_LENGTH + 1), end + _UUID_LENGTH)
        if found.start() < end and found.end() > start
    ]
    if not uuids:
        return _truncated(text, start, end)
    parts, copied = [], start
    for first, last in uuids:
        parts.append(_truncated_outside(text, copied, max(copied, first)))
        parts.append(text[max(copied, first) : min(last, end)])
        copied = min(last, end)
    parts.append(_truncated_outside(text, copied, end))
    return "".join(parts)


# A value made only of digit groups: pan_shaped reads it with the card rule.
_CARD_VALUE = re.compile(rf"\d(?:{_CARD_SEP}?\d)*")
# A value that is exactly one marker ecsctx itself produces: a bare label, a
# label with a token, or a truncated card. A marker somewhere inside a longer
# value, or brackets around anything else, do not make it safe.
_SINGLE_MARKER = re.compile(
    rf"\[[A-Z0-9-]+-MASKED(?::{_TOKEN})?\]|{_TRUNCATED_PAN}"
    rf"|\[CARD-MASKED:{_TRUNCATED_PAN}\]|{_TOKEN}"
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
    """Whether ``text`` is, in its entirety, one card number: 12-19 digits in
    groups that the card rule reads as one card, not as a card beside another
    number ("5123450000000008 12").

    Public because the filter asks it of a value that a PII key already
    claimed: a card number typed into the name box is still a card number.
    """
    value = text.strip()
    if not _CARD_VALUE.fullmatch(value):
        return False
    if not _MIN_PAN_DIGITS <= sum(character.isdigit() for character in value) <= _MAX_PAN_DIGITS:
        return False
    return _CardRun(value, 0, len(value)).spans() == [(0, len(value))]


# A run of digits joined by single separators, as the card rule reads one, with
# the "+" an international phone number starts with.
_DIGIT_RUN = re.compile(rf"\+?\d(?:{_CARD_SEP}?\d)*")


def holds_pan_run(text: str, *, phone: bool = False) -> bool:
    """Whether ``text`` holds, anywhere in it, a run of digits long enough to
    be a PAN.

    Looser than the card rule on purpose: the rule must find where a PAN ends
    to truncate it, and cannot when more digits follow. In a phone field
    (``phone``) a run written after "+" is the phone number, unless it is
    longer than E.164 allows -- a PAN, or a phone number with a PAN after it.
    Anywhere else "+" changes nothing: in an email address it is
    plus-addressing.

    A value that is a canonical UUID holds none: its hyphens join digits as a
    card number's separators do, but it is an id (see ``_UUID``).
    """
    if _UUID.fullmatch(text.strip()):
        return False
    for run in _DIGIT_RUN.findall(text):
        digits = sum(character.isdigit() for character in run)
        if phone and run.startswith("+") and digits <= _PHONE_MAX_DIGITS:
            continue
        if digits >= _MIN_PAN_DIGITS:
            return True
    return False


# A run the card rule reads, wherever it is in a value; and what a truncation
# keeps one of per digit: the digit, or a star.
_RUN = re.compile(_CARD_RUN)
_MARK = re.compile(r"[\d*]")
# A run of digits as a card number may be written under a card key: joined as
# the card rule joins them, or by the dots and slashes it never reads
# ("4111.1111.1111.1111").
_WRITTEN_RUN = re.compile(rf"\d(?:(?:{_CARD_SEP}|[./])?\d)*")


def _holds_a_written_run(text: str) -> bool:
    return any(sum(character.isdigit() for character in run) >= _MIN_PAN_DIGITS for run in _WRITTEN_RUN.findall(text))


# A group of digits and stars, a truncation keeping one per digit; and a
# truncation the card rule writes: the first six, stars and the last four of 15
# digits or more, or eight stars or more and the last four (of fewer, or of one
# whose stars run into an earlier truncation's).
_MARK_GROUP = re.compile(r"[\d*]+")
_WRITTEN_TRUNCATION = re.compile(r"\d{6}\*{5,}\d{4}|\*{8,}\d{4}")
# What any truncation may show, the card rule's or an upstream system's: the
# first six digits at most, four stars or more, the last four at most -- no
# more than PCI DSS 3.5.1 lets anyone keep -- with stars before or after hiding
# more (test_masking_bare_pan pins an upstream `123456****7890`). Written so
# each run of stars has one reading: a long one never backtracks.
_TRUNCATION_SHAPE = re.compile(r"(?:\**\d{1,6})?\*{4,}(?:\d{1,4}\**)?")
# Groups of four to six digits or stars, one card separator apart, as a card
# number is written: 4-4-4-4, Amex 4-6-5, Diners 4-6-4. Each group is read
# whole -- a separator or the end must follow it -- so a run has one reading.
_CARD_GROUPS = re.compile(rf"(?<![\d*])[\d*]{{4,6}}(?:{_CARD_SEP}[\d*]{{4,6}})+(?![\d*])")


def _hides_as_truncations(masked: str) -> bool:
    """Whether the stars in ``masked`` hide what a truncation hides.

    Where twelve digits or more show, every group of digits and stars that
    holds both is a truncation the card rule writes: beside other digits even
    a short one completes a card number (another masker's `4508750****001019`
    shows thirteen digits of seventeen, and `****1111 1234 5670` twelve of
    sixteen). Where fewer show, a group long enough to stand for a card number
    has a truncation's shape (`_TRUNCATION_SHAPE`), a card number's groups
    read as one (`_CARD_GROUPS`): another masker's `45087****001019` shows the
    last six of fifteen, `4508-750*-****-1019` the first seven of sixteen and
    `3782 822*** *0005` seven and the last four of fifteen, while `****1234`
    completes none."""
    if sum(character.isdigit() for character in masked) >= _MIN_PAN_DIGITS:
        shape, shortest = _WRITTEN_TRUNCATION, 1
    else:
        shape, shortest = _TRUNCATION_SHAPE, _MIN_PAN_DIGITS
        masked = _CARD_GROUPS.sub(lambda groups: "".join(_MARK_GROUP.findall(groups.group())), masked)
    return all(
        shape.fullmatch(group)
        for group in _MARK_GROUP.findall(masked)
        if len(group) >= shortest and "*" in group and group.strip("*")
    )


def _digits_beside_truncations(masked: str) -> int:
    """How many digits of ``masked`` show outside the truncations the card
    rule writes, whatever joins them. Group by group: a search for the shape
    tried from every star of a long run, reading to its end each time."""
    return sum(
        character.isdigit()
        for group in _MARK_GROUP.findall(masked)
        if not _WRITTEN_TRUNCATION.fullmatch(group)
        for character in group
    )


# A letter of a word, which ends the digits shown in a row. Not an `X`: a run
# of them joins digits as stars do -- another masker writes `4508750XXX001019`.
_WORD_LETTER = re.compile(r"[^\W\d_Xx]")


def _card_digits_showing(masked: str) -> int:
    """The most digits ``masked`` shows in a row, however they are joined --
    bare digits, a truncation's last four, and the first six ending them --
    as a card number could be read across them. A truncation's own stars
    separate its first six from its last four; a word ends a row.
    `4111111111  111111******1111` shows sixteen, and
    `411111******5018  00  000009******0001` the Maestro 501800000009."""
    most = run = end = 0
    for group in _MARK_GROUP.finditer(masked):
        if _WORD_LETTER.search(masked, end, group.start()):
            run = 0
        end = group.end()
        marks = group.group()
        if _WRITTEN_TRUNCATION.fullmatch(marks):
            if marks[0] != "*":
                # Its first six end what shows before them; its own stars
                # separate them from its last four, which start what follows.
                most = max(most, run + 6)
                run = 0
            run += 4
        else:
            run += sum(character.isdigit() for character in marks)
        most = max(most, run)
    return most


def _overexposes_a_card(text: str, masked: str) -> bool:
    """Whether ``masked``, the card rule's output for ``text``, shows more than
    the first six and last four of a Luhn-valid reading of ``text``: any stretch
    of whole groups, 12-19 digits long, wherever it stands. The rule leaves an
    IBAN's digits, a word's own and each side of a range, which in free text
    are not a card number; under a card key they may be one."""
    # A truncation keeps one character per digit it hides or keeps, and the
    # rule leaves stars as they were: the digits and stars of the two line up.
    marks = [mark != "*" for mark in _MARK.findall(masked)]
    if len(marks) != len(_MARK.findall(text)):
        return True
    before = position = 0  # marks before the run, and where counting stopped
    for run in _RUN.finditer(text):
        before += len(_MARK.findall(text, position, run.start()))
        digits = len(_MARK.findall(text, run.start(), run.end()))  # no star in a run
        shown = marks[before : before + digits]
        # A digit showing among the run's first six or last four is among those
        # of any stretch inside it too: only one between them can show more.
        if any(shown[6 : digits - 4]) and _CardRun(text, run.start(), run.end()).overexposed(shown):
            return True
        before += digits
        position = run.end()
    return False


def mask_card_value(value) -> str:
    """The value of a card-named key: the PAN truncated, the rest readable.

    Never tokenized — a keyed hash of a PAN next to its truncated form is the
    correlation FAQ 1117 warns about.

    Scalars only. A card *object* is walked leaf by leaf in `_mask_dict`, which
    re-enters here for each leaf, so `number` truncates while `expiry` and
    `scheme` read through. Collapsing the object was how `holder`, `track2` and
    `pinBlock` stayed out of a log without ever being classified; they are
    classified now, and this function is deliberately permissive below twelve
    digits -- only stars that could stand for a card number's other digits are
    judged there -- so it must not be handed a whole container again.

    What is *not* a PAN is shown. Collapsing every non-PAN value to a label
    made a gateway token, a scheme name and an error string all look identical
    under `card_number`, which is the one place someone debugging a declined
    payment goes looking.
    """
    if isinstance(value, str) and not value:
        return value  # nothing was there; see mask_by_field_type
    if isinstance(value, str) and _SINGLE_MARKER.fullmatch(value) and not holds_pan_run(value):
        # A marker, not a token-shaped string with a card number in it.
        return value
    if isinstance(value, (str, int)) and not isinstance(value, bool):
        text = str(value).strip()
        if pan_shaped(text):
            return _truncate_pan(_digits_only(text))
        if sum(character.isdigit() for character in text) < _MIN_PAN_DIGITS:
            # Too few digits to be a PAN whatever else it holds: 12 is the
            # shortest one issued (ISO/IEC 7812; Maestro issues from 12) --
            # unless stars stand for the rest of one in no truncation's shape.
            return value if _hides_as_truncations(text) else f"[{make_label('card')}]"
        # Enough digits to hide one, but not a clean PAN: scan rather than
        # collapse, so an embedded PAN is truncated and its context survives --
        # unless what the scan shows could still be one: a run of card-number
        # length beside the truncations, dots and slashes joining it too (each
        # truncation's first six stay in place for this, so digits showing
        # before it count with them), or a Luhn-valid reading the rule leaves
        # in free text, showing more than its first six and last four.
        scanned = mask_by_patterns(text, _CARD_RULE_ONLY)
        # This function's own output on a later pass -- the formatter's,
        # redact_body's over a card param -- is a value the scan leaves as it
        # is, holding a truncation the card rule writes. It is refused for a
        # run of card-number length, for digits and stars in another shape
        # (_hides_as_truncations), or for twelve digits or more showing
        # outside its truncations, however they are joined (double spaces,
        # commas, another masker's `X`s): the first pass refuses those too,
        # so each output is a fixed point. Its Luhn readings were judged by
        # the pass that truncated it; read again, a truncation's last four
        # join the digits after them into readings that pass never saw.
        truncated_before = scanned == text and any(
            _WRITTEN_TRUNCATION.fullmatch(group) for group in _MARK_GROUP.findall(text)
        )
        if (
            (scanned != text or truncated_before)
            and not _holds_a_written_run(_MASKED_REST.sub(" ", scanned))
            and (truncated_before or not _overexposes_a_card(text, scanned))
            and _hides_as_truncations(scanned)
            and _digits_beside_truncations(scanned) < _MIN_PAN_DIGITS
            and _card_digits_showing(scanned) < _MIN_PAN_DIGITS
        ):
            return scanned
        # The scan found nothing to truncate, yet the value carries twelve or
        # more digits under a card key -- or it truncated one card number and
        # left another, in a shape the rule does not read ("REF5123450000000008
        # 5123450000000008"). `4508750**0001019` is the shape that matters: 14
        # of 16 digits kept, far past what PCI DSS 3.5.1 allows, and no
        # contiguous run for the card rule to catch. Refuse it.
        return f"[{make_label('card')}]"
    return f"[{make_label('card')}]"


def mask_secret(value: Any) -> Any:
    """A credential masked as a credential key's value is: its bare token
    (``ptok:v1:…``) where PII tokenization is configured, ``[SECRET-MASKED]``
    where it is not, and ``[SECRET-MASKED]`` either way for a value shaped
    like a card number, a placeholder another masker left, a value in a
    token's shape with a card number in it (``ptok:v1:`` typed before one),
    and -- with ``pci`` among the call's packs, and the process's (a
    filter's own while it masks, with the process's) -- any value that
    holds a card-number run (``holds_pan_run``). Without ``pci`` among them
    such a value is hashed: a default-pack service receives no card numbers.

    For a credential that reaches a log outside a mapping, where no key sits
    next to it: a URL's path or query, a body masked before it is logged, a
    value a service masks itself. A null or a flag comes back as it is, as
    under a key; anything else is masked as its text.
    """
    if value is None or isinstance(value, bool):
        return value
    text = str(value)
    return mask_by_field_type(text, "secret")


def _mask_url_part(part: str) -> str:
    """One part of a URL's userinfo, masked as a credential as it decodes
    (`unquote`): the token the same value gets under a key. An empty part
    stays empty, and one masking leaves as it is stays as it was written."""
    if not part:
        return part
    decoded = unquote(part)
    masked = mask_secret(decoded)
    return part if masked == decoded else masked


def _mask_userinfo(userinfo: str) -> str:
    """A URL's userinfo -- ``user`` or ``user:password`` -- with each part
    masked, for ``contrib.net.redact_url`` and the userinfo text rule alike. A
    token at its head is the user whole: split at its first colon, a masked
    user was read as ``ptok`` and masked again (`ptok:v1:ptok:v1:…`)."""
    head = _TOKEN_SHAPE.match(userinfo)
    if head is not None and userinfo[head.end() : head.end() + 1] in ("", ":"):
        user, rest = userinfo[: head.end()], userinfo[head.end() :]
        separator, password = rest[:1], rest[1:]
    else:
        user, separator, password = userinfo.partition(":")
    return f"{_mask_url_part(user)}{separator}{_mask_url_part(password)}"


# ---------------------------------------------------------------------------
# Value rules in text
# ---------------------------------------------------------------------------
# A JSON object written in text -- JSON, a Python repr, or JSON in a JSON
# string -- is asked of the service's value rules (value_rules): one a label
# rule matches is that rule's label, never a token (rule 2); one a keep rule
# matches is set aside before any rule reads the text, and put back as it was
# written after (stash_kept). ecsctx names no shape of its own: nothing
# configured, nothing runs.


def value_rules_in_force() -> tuple:
    """The value rules masking asks: the service's (config's
    ``ECSCTX_MASK_VALUE_RULES``). Imported here: config imports this module
    as it loads."""
    from ecsctx.masking.config import get_masking_value_rules

    return get_masking_value_rules()


def _json_object(string: str, space: str, character: str) -> str:
    """A JSON object as text: members whose value is a string, a scalar, or
    an object or list holding strings, anything but a bracket, and one more
    level of either -- as deep as an object a rule is asked about goes; a
    deeper one is read from inside. Every alternative starts on a character
    of its own and no loop takes a closing bracket, so a failed match never
    backtracks into another reading."""
    flat = rf"(?:{string}|{character})*"
    nested = rf"(?:{string}|{character}|\{{{flat}\}}|\[{flat}\])*"
    value = rf"(?:{string}|[-+.\w]+|\{{{nested}\}}|\[{nested}\])"
    member = rf"{string}{space}:{space}{value}"
    return rf"\{{{space}{member}(?:{space},{space}{member})*{space}\}}"


# As written: JSON, or a Python repr's quotes. Escaped: JSON in a JSON string
# (a field whose value is itself JSON), its quotes `\"`, a pretty-printed
# one's line breaks `\n`. Compiled once, as rule 2.
_OBJECT_TEXT = (
    "(?P<plain>"
    + _json_object(
        r"(?:\"(?:[^\"\\]|\\[\s\S])*\"|'(?:[^'\\]|\\[\s\S])*')",
        r"\s*",
        r"[^{}\[\]\"']",
    )
    + ")|(?P<escaped>"
    + _json_object(
        rf'\\"{_ESCAPED_QUOTED_UNIT}*\\"',
        r"(?:\s|\\[nrt])*",
        r'(?!\\")[^{}\[\]"]',
    )
    + ")"
)


def _object_value(m: re.Match) -> Any:
    """The object a match wrote, parsed: JSON, a Python repr, or JSON in a
    JSON string as it decodes. None where it does not parse."""
    written = m.group(0)
    if m.group("plain") is None:
        try:
            return json.loads(json.loads(f'"{written}"'))
        except (ValueError, RecursionError):
            return None
    try:
        return json.loads(written)
    except (ValueError, RecursionError):
        pass
    try:
        return ast.literal_eval(written)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None


def _mask_object(m: re.Match, rules: tuple) -> str:
    """The label where an object a label rule matches stood: a JSON string
    where it was a JSON value (after `:`, `,` or `[`), escaped where that JSON
    is itself in a string; bare anywhere else -- in prose, an element's text,
    a string of its own. An object no rule matches is read member by member,
    so one inside it is still found; one a keep rule matches first is left as
    written and not looked into. Only the rules whose hints the object's text
    holds are asked."""
    written = m.group(0)
    asked = applicable(written, rules)
    if not asked:
        return written  # nothing in it can match: every match holds a hint
    rule = rule_of(_object_value(m), asked)
    if rule is None:
        inner = mask_objects(written[1:-1], rules)
        return written if inner == written[1:-1] else f"{{{inner}}}"
    if is_keep_rule(rule):
        return written
    label = f"[{make_label(rule.field_type)}]"
    text, position = m.string, m.start() - 1
    while position >= 0 and text[position].isspace():
        position -= 1
    if position < 0 or text[position] not in ":,[":
        return label
    quote = '"' if m.group("plain") is not None else '\\"'
    return f"{quote}{label}{quote}"


def _value_object(m: re.Match) -> str:
    rules = value_rules_in_force()
    return _mask_object(m, rules) if label_rules(rules) else m.group(0)


def mask_objects(text: str, rules: tuple) -> str:
    """Each JSON object written in ``text`` that a label rule among ``rules``
    matches first, as its label: rule 2 alone, for ``contrib.net.redact_body``.
    Only the label rules' hints open the text: keep rules alone write no
    label."""
    labels = label_rules(rules)
    if not labels or "{" not in text or not hinted(text, labels):
        return text
    return _OBJECT_RULE.pattern.sub(lambda m: _mask_object(m, rules), text)


# Nothing is kept under these, as the key walk keeps nothing under such a key
# or in such a container (filters): a CVV and the rest of Sensitive
# Authentication Data.
_FLOOR_TYPES = frozenset({"cvv", "sad"})
# The key right before an object in text, as the floor reads it: a quoted key
# and its colon (JSON, a repr, JSON in a JSON string, its quotes escaped), a
# key and `=` or `:`, or an XML start tag -- then any space and the opening
# quote of a string the object is the JSON text of.
_KEY_BEFORE = re.compile(
    r"(?:(?P<quote>\\?[\"'])(?P<quoted>[^\"'\\]{1,128})(?P=quote)\s*:"
    r"|(?<![\w.-])(?P<bare>[\w.-]{1,128})\s*[:=]"
    r"|<(?:[A-Za-z_][\w.-]*:)?(?P<tag>[A-Za-z_][\w.-]*)(?:\s[^<>]*)?(?<!/)>)"
    r"\s*(?:\\?[\"'])?\s*\Z"
)
# How far back the key is looked for.
_KEY_REACH = 192


def _floored_before(text: str, start: int) -> bool:
    """Whether the object at ``start`` sits right after a CVV or SAD key --
    `"cvv": {…}`, `cvv={…}`, `<cvv>{…}</cvv>`, `"pin": "{…}"`: nothing under
    one is kept, however deep. Every pack on, as the key walk reads a key."""
    found = _KEY_BEFORE.search(text, max(0, start - _KEY_REACH), start)
    if found is None:
        return False
    name = found.group("quoted") or found.group("bare") or found.group("tag")
    return classify_key(name, ALL_PACKS) in _FLOOR_TYPES


def _written_as_parsed(m: re.Match) -> bool:
    """Whether the object a match wrote is all its parse says, as a keep
    decision needs: what ships is the text as written. JSON, or JSON in a
    JSON string as it decodes, that names no key twice; a Python repr whose
    parse renders back to it exactly -- a comment or a key written twice is
    dropped by the parse, and would ship unread."""
    written = m.group(0)
    try:
        if m.group("plain") is None:
            json_as_written(json.loads(f'"{written}"'))
            return True
        try:
            json_as_written(written)
        except DuplicateKey:
            return False
        except ValueError:
            return repr(ast.literal_eval(written)) == written
        return True
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return False


def _object_ruling(m: re.Match, rules: tuple) -> Any:
    """``ruling`` of the object a match wrote; a label rule's error reads as a
    label -- not kept, not looked into -- so finding kept spans never raises,
    and the text is masked as without a keep rule. A keep match written
    otherwise than it parses (``_written_as_parsed``) is read as one nothing
    matches."""
    try:
        found = ruling(_object_value(m), rules)
    except Exception:  # noqa: BLE001 -- a service's matcher; rule 2 reports it where it runs
        return ""
    return None if found is KEEP and not _written_as_parsed(m) else found


def kept_spans(text: str, rules: tuple) -> list[tuple[int, int]]:
    """Where ``text`` writes a value a keep rule among ``rules`` matches first
    and may keep: each JSON object (rule 2's reading), top down. An object a
    label rule matches first is no span and is not looked into, nor is one
    right after a CVV or SAD key; one nothing matches is read member by
    member; a keep match the guard refuses (``holds_card_data``) is read as
    one nothing matches. In order, none inside another."""
    spans: list[tuple[int, int]] = []
    _find_kept(text, 0, len(text), rules, spans)
    return spans


def _find_kept(text: str, start: int, end: int, rules: tuple, spans: list[tuple[int, int]]) -> None:
    for m in _OBJECT_RULE.pattern.finditer(text, start, end):
        asked = applicable(m.group(0), rules)
        if not asked or _floored_before(text, m.start()):
            continue
        found = _object_ruling(m, asked)
        if found is KEEP:
            spans.append(m.span())
        elif found is None:
            _find_kept(text, m.start() + 1, m.end() - 1, rules, spans)


# What a kept span stands as while the rules read the text: a label's shape,
# which every rule leaves as it is, with no digit in it for a rule to read.
_KEPT_HEAD = "[KEPT-"
_KEPT_PLACEHOLDER = re.compile(r"\[KEPT-[A-Z]+-MASKED\]")


def _letters(index: int) -> str:
    """0 is A, 25 is Z, 26 is AA: a placeholder's own, digit-free name."""
    letters = ""
    index += 1
    while index:
        index, rest = divmod(index - 1, 26)
        letters = chr(ord("A") + rest) + letters
    return letters


class KeptStash(NamedTuple):
    """Text with each kept span set aside (``text``), and what each
    placeholder stands for."""

    text: str
    originals: dict[str, str]

    def hold(self, value: str) -> str:
        """A new placeholder standing for ``value``, for the caller to put
        where it stood: ``contrib.net.redact_body`` sets aside an element's
        entity-encoded text that holds a kept value."""
        placeholder = f"{_KEPT_HEAD}{_letters(len(self.originals))}-MASKED]"
        self.originals[placeholder] = value
        return placeholder

    def restore(self, masked: str) -> str:
        """``masked`` with each placeholder that is still in it put back as
        the value was written. One a rule destroyed -- hashed or labelled with
        what was around it -- is not: the value goes with it."""
        if not self.originals:
            return masked
        return _KEPT_PLACEHOLDER.sub(lambda m: self.originals.get(m.group(), m.group()), masked)


def stash_kept(text: str, rules: tuple | None = None) -> KeptStash | None:
    """``text`` with each value a keep rule ships set aside as a placeholder
    (``[KEPT-A-MASKED]``), for the rules to read around it -- or None when
    there is none: no keep rule among ``rules`` (the rules in force when
    None), none whose hints the text holds, no span (``kept_spans``), or text
    that already holds a placeholder's head, which is masked as before.
    Never raises."""
    if "{" not in text:
        return None
    if rules is None:
        rules = value_rules_in_force()
    if not rules or not (keep := keep_rules(rules)) or not hinted(text, keep) or _KEPT_HEAD in text:
        return None
    spans = kept_spans(text, rules)
    if not spans:
        return None
    parts: list[str] = []
    originals: dict[str, str] = {}
    copied = 0
    for index, (start, end) in enumerate(spans):
        placeholder = f"{_KEPT_HEAD}{_letters(index)}-MASKED]"
        originals[placeholder] = text[start:end]
        parts += [text[copied:start], placeholder]
        copied = end
    parts.append(text[copied:])
    return KeptStash("".join(parts), originals)


def is_kept(value: Any, *, key: str | None = None) -> bool:
    """Whether masking ships ``value`` as sent: a mapping, or JSON text, that
    a keep rule in force matches first (``ECSCTX_MASK_VALUE_RULES``, asked in
    their order), that the guard lets through -- no card, CVV or SAD key and
    no card number in it, at any depth -- and, given the ``key`` it sits
    under, not under a CVV or SAD key. False with no keep rule configured,
    for a label rule's match, and for anything else. Never raises.

    For a service's own masking pass after ecsctx's, which must leave such a
    value as ecsctx did: ask before masking a field."""
    if not isinstance(value, (str, Mapping)):
        return False
    rules = value_rules_in_force()
    if not keep_rules(rules):
        return False
    if key is not None and classify_key(str(key), ALL_PACKS) in _FLOOR_TYPES:
        return False
    try:
        if isinstance(value, str):
            return text_ruling(value, rules) is KEEP
        return ruling(value if isinstance(value, dict) else dict(value), rules) is KEEP
    except Exception:  # noqa: BLE001 -- a label rule's error: not kept, and a log path never raises
        return False


def mask_outside_kept(text: str, mask: Callable[[str], str]) -> str:
    """``mask(text)`` with each value ecsctx keeps in ``text`` set aside: a
    placeholder in a label's shape, ``[KEPT-<letters>-MASKED]``, stands for
    it while ``mask`` reads the rest, and is put back as the value was
    written. One ``mask`` destroys is not put back: the value goes with it.

    For a service's own text masking after ecsctx's, which would otherwise
    read into what ecsctx ships as sent."""
    stash = stash_kept(text)
    if stash is None:
        return mask(text)
    return stash.restore(mask(stash.text))


def _mask_pem(match: re.Match) -> str:
    """Token computed over the base64 body only — strip the BEGIN/END lines
    and all whitespace first, so the same key re-wrapped at a different line
    width (or with CRLF instead of LF) still produces the same token.
    """
    body = match.group(0)
    stripped = re.sub(r"-----(BEGIN|END)[^-]*-----", "", body)
    stripped = re.sub(r"\s+", "", stripped)
    return mask_by_field_type(stripped, "pem_key")


# What a credential keyword names when the key rule reads it as a CVV or other
# SAD (`cvv_token`, `pin_password`): its value is that type's label, as under
# the key and in a URL, never a keyed hash of a CVV.
_NEVER_TOKENIZED = frozenset({"cvv", "sad"})


def _credential_type(keyword: str) -> str:
    field_type = classify_key(keyword, ALL_PACKS)
    return field_type if field_type in _NEVER_TOKENIZED else "secret"


def _mask_credential(value: str, keyword: str) -> str:
    return mask_by_field_type(value, _credential_type(keyword))


def _mask_quoted(value: str, quote: str, keyword: str) -> str:
    """A quoted credential value, masked as what it decodes to when it is a
    JSON string with an escape in it -- so `{"password": "a\\"b"}` carries
    the token `a"b` gets under the key. Written back as it was when masking
    leaves it as it is: an escaped quote in a label would end the string."""
    if quote == '"' and "\\" in value:
        with contextlib.suppress(ValueError):
            decoded = json.loads(f'"{value}"')
            masked = _mask_credential(decoded, keyword)
            return value if masked == decoded else masked
    return _mask_credential(value, keyword)


def _cred_quoted(m: re.Match) -> str:
    q, kw, sep, val = m.group("q"), m.group("key"), m.group("sep"), m.group("value")
    return f"{q}{kw}{q}{sep}{q}{_mask_quoted(val, q, kw)}{q}"


# Values a quoted key can hold that are literals, not text: JSON's and a
# Python repr's. None of them is a secret.
_LITERALS = frozenset({"null", "true", "false", "None", "True", "False"})
_SEPARATOR = re.compile(r"[:=]")
# The quote closing a key, JSON-escaped where the key sits in a JSON string.
_KEY_QUOTE = re.compile(r"\\?[\"']")


def _unquoted_value_quote(prefix: str) -> str:
    """The quote closing the key in ``prefix`` (key, separator, spacing) when
    the value after it is unquoted — JSON or a repr, whose text must stay
    parseable once masked; escaped as the key's is (`{\\"api_key\\": 1}` in a
    JSON string). Empty for ``key=value`` text, or when the value's own opening
    quote is in the prefix."""
    separator = _SEPARATOR.search(prefix)
    if separator is None:
        return ""
    before, after = prefix[: separator.start()], prefix[separator.end() :]
    if any(q in after for q in "\"'"):
        return ""
    quote = _KEY_QUOTE.search(before)
    return quote.group() if quote else ""


def _mask_escaped_quoted(value: str, keyword: str) -> str:
    """A value between escaped quotes -- JSON in a JSON string -- masked as it
    decodes from the outer string and then the inner one, so it carries the
    token it gets under its key. Written back as it was when masking leaves it
    as it is."""
    inner = value
    if "\\" in value:
        with contextlib.suppress(ValueError):
            outer = json.loads('"' + value + '"')
            inner = json.loads('"' + outer + '"')
    masked = _mask_credential(inner, keyword)
    return value if masked == inner else masked


def _cred_kv(m: re.Match) -> str:
    prefix, keyword, val = m.group("prefix"), m.group("key"), m.group("value")
    if quote := m.group("quote"):
        return f"{prefix}{_mask_quoted(val, quote, keyword)}"
    if m.group("escaped"):
        return f"{prefix}{_mask_escaped_quoted(val, keyword)}"
    if quote := _unquoted_value_quote(prefix):
        if val in _LITERALS:
            return m.group(0)
        return f"{prefix}{quote}{_mask_credential(val, keyword)}{quote}"
    return f"{prefix}{_mask_credential(val, keyword)}"


# A container after a credential word, as a %-style argument renders one
# (`password=['a', 'b']`, `{'password': ('a', 'b')}`): a list, dict, tuple or
# set, its strings read whole so a bracket in one ends nothing, nested three
# deep; or, opened and never closed (a line cut short), the rest of the line.
_CONTAINER_STRING = r"\"(?:[^\"\\]|\\[\s\S])*\"|'(?:[^'\\]|\\[\s\S])*'"


def _container(depth: int) -> str:
    inner = rf"(?:{_CONTAINER_STRING}|[^\[\]{{}}()\"']" + (f"|{_container(depth - 1)}" if depth else "") + ")*"
    return rf"(?:\[{inner}\]|\{{{inner}\}}|\({inner}\))"


_CONTAINER = rf"(?:{_container(2)}|[\[{{(][^\n]*)"


def _only_masks(value: Any) -> bool:
    """Whether every value in a parsed container is masking's own output --
    a token, a label, a truncation -- or no value at all (None, a flag)."""
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, str):
        return already_masked(value)
    if isinstance(value, (list, tuple, set, frozenset)):
        return all(_only_masks(item) for item in value)
    if isinstance(value, dict):
        return all(_only_masks(item) for item in value.values())
    return False


def _masked_already(text: str) -> bool:
    """Whether a container's text holds only masking's own output, as the key
    walk writes a credential's container, a record's field included."""
    for parse in (ast.literal_eval, json.loads):
        try:
            return _only_masks(parse(text))
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            continue
    return False


def _cred_container(m: re.Match) -> str:
    value = m.group("value")
    if _masked_already(value):
        return m.group(0)
    # A repr's key is quoted: its value stays a string.
    quote = m.group("quote")
    return f"{m.group('prefix')}{quote}{_mask_credential(value, m.group('key'))}{quote}"


# Masking's own output in a value: a whole token, a label, a truncation.
_MASKS_IN_A_VALUE = re.compile(rf"(?-i:{_CARDLESS_TOKEN}|\[[A-Z0-9-]+-MASKED\]|{_TRUNCATED_PAN})")
_DIGIT = re.compile(r"\d")
# A form field whose value masking wrote, as redact_body leaves one after a
# scheme word (`API-Key password=<token>`).
_MASKED_FIELD = re.compile(rf"[\w.\-\[\]%]+[=:](?-i:{_CARDLESS_TOKEN}|\[[A-Z0-9-]+-MASKED\])")


def _api_key_scheme(m: re.Match) -> str:
    """`API-Key <key>` without its `Authorization:` -- Ottu PG's header,
    written into text: the scheme and the key are one value, as after
    Authorization, and carry the token the header carries. A form field
    masking wrote there (`API-Key password=<token>`) is left, never hashed
    again with the scheme."""
    if _MASKED_FIELD.fullmatch(m.group("value")):
        return m.group(0)
    return mask_secret(m.group(0))


def _cred_space(m: re.Match) -> str:
    kw, val = m.group("keyword"), m.group("value")
    if _DIGIT.search(_MASKS_IN_A_VALUE.sub("", val)) is None:
        # Its only digits are masking's own: `password=<token>`, which
        # redact_body wrote after the scheme word. The digit is what makes
        # this rule read a credential, and hashing it again was a token of a
        # token. A credential glued to a key name keeps its own digits
        # (`Token abc123abc123api_key=<token>`), and is hashed as before.
        return m.group(0)
    return f"{kw} {_mask_credential(val, kw)}"


# An element's text given as a CDATA section, whose content is the value.
_CDATA = re.compile(r"\s*<!\[CDATA\[(?P<content>[\s\S]*?)\]\]>\s*")
# An Authorization element's text that masking already wrote, or another
# masker did: a scheme before a whole token, a label or a placeholder. As in
# rule 7, the scheme is not hashed again with it.
_SCHEME_BEFORE_A_MASK = re.compile(
    rf"\s*{_AUTH_SCHEME}[ \t]+(?:(?-i:{_CARDLESS_TOKEN})|\[[^\[\]]*\]|\*+)\s*", re.IGNORECASE
)
_AUTH_NAME = re.compile(_AUTH_KEYWORD, re.IGNORECASE)


def _element_text(raw: str) -> str:
    """An XML element's text as it decodes: a CDATA section's content, or the
    text with its entities resolved -- the value a key would carry, so it
    gets the token the same value gets under a key."""
    if (cdata := _CDATA.fullmatch(raw)) is not None:
        return cdata.group("content")
    return html.unescape(raw) if "&" in raw else raw


# A start tag's attributes: a `>` inside a quoted value is the value's, as
# XML allows it there (`<password hint="a>b">`); read to the first `>`, the
# rest of the value went into the element's text, and its token. Each piece
# starts with a character no other can (no backtracking to speak of), and a
# quoted value never crosses a `<`.
_ATTRIBUTES = r"(?:[^<>\"']|\"[^\"<]*\"|'[^'<]*')*"
# An XML element's start tag: its qualified name, the local name after any
# namespace prefix, and its attributes. Not an empty-element tag
# (`<password/>`), which holds no text. A quote nothing closes before the
# next tag leaves the first `>` to end it, as before: never no start tag,
# which would leave the element's text in clear.
_XML_START = re.compile(
    rf"<(?P<tag>(?:[A-Za-z_][\w.-]*:)?(?P<local>[A-Za-z_][\w.-]*))"
    rf"(?:(?:\s{_ATTRIBUTES})?(?<!/)>|(?:\s[^<>]*)?(?<!/)>)"
)
# ...and an end tag, with its qualified name.
_XML_END = re.compile(r"</(?P<tag>(?:[A-Za-z_][\w.-]*:)?[A-Za-z_][\w.-]*)\s*>")
_match_start = methodcaller("start")


def _tag_key(tag: str) -> str:
    """A tag's name as an end tag is paired with a start tag: ignoring case,
    as the rules read a name."""
    return tag.translate(_ASCII_FOLDS).casefold()


def _end_tags(text: str) -> dict[str, list[re.Match]]:
    """The end tags in ``text``, in order, by name (`_tag_key`)."""
    found: dict[str, list[re.Match]] = {}
    for end in _XML_END.finditer(text):
        found.setdefault(_tag_key(end.group("tag")), []).append(end)
    return found


def _closing(ends: dict[str, list[re.Match]], start: re.Match) -> re.Match | None:
    """The end tag that closes the element ``start`` opens -- the first of its
    name after it -- in ``ends`` (`_end_tags`), or None."""
    found = ends.get(_tag_key(start.group("tag")))
    if not found:
        return None
    at = bisect_left(found, start.end(), key=_match_start)
    return found[at] if at < len(found) else None


def _mask_elements(text: str, kind: Callable[[str], str | None], mask: Callable[[str, str], str]) -> str:
    """``text`` with each element's text masked as ``mask(text, kind)`` masks
    it, where ``kind`` gives the element's local name a kind (None: not one
    to mask). An element runs to the first end tag of its name after its
    start tag, children and all, and is read whole: none inside it is looked
    for. No end tag, no element: a route in a message
    (`DELETE /v1/cards/<str:token>/`) is a start tag's shape.

    The text's end tags are found once, when the first element of a kind
    needs one: looked for again from each start tag, a text holding many
    that nothing closes took quadratic time -- 160 KB of `<password>`,
    twelve seconds.
    """
    parts, copied, after, ends = [], 0, 0, None
    for start in _XML_START.finditer(text):
        if start.start() < after:
            continue
        if (found := kind(start.group("local"))) is None:
            continue
        if ends is None:
            ends = _end_tags(text)
        if (closing := _closing(ends, start)) is None:
            continue
        after = closing.end()
        raw = text[start.end() : closing.start()]
        masked = mask(raw, found)
        if masked != raw:
            parts += [text[copied : start.end()], masked]
            copied = closing.start()
    if not parts:
        return text
    parts.append(text[copied:])
    return "".join(parts)


_CRED_NAME = re.compile(_CRED_KEYWORD, re.IGNORECASE)


def _credential_name(local: str) -> str | None:
    return local if _CRED_NAME.fullmatch(local) else None


def _mask_credential_element(raw: str, keyword: str) -> str:
    value = _element_text(raw)
    if _AUTH_NAME.fullmatch(keyword) and _SCHEME_BEFORE_A_MASK.fullmatch(value):
        return raw
    masked = _mask_credential(value, keyword)
    return raw if masked == value else masked


def _cred_elements(m: re.Match) -> str:
    return _mask_elements(m.group(0), _credential_name, _mask_credential_element)


# What a key names that is masked by its type, whatever the value looks like:
# a CVV and the rest of Sensitive Authentication Data as their labels, never a
# token, and a card number truncated. Classified as the key walk classifies a
# key, every pack on: MIGS's `vpc_CardSecurityCode`, a form's `card_number`,
# `pin`. A query param, a form field and an XML element are read so
# (contrib.net, rule 3).
_CARD_TYPES = frozenset({"cvv", "sad", "card"})
# ...and those whose element is its label whole, children and all.
_LABEL_TYPES = frozenset({"cvv", "sad"})


def _card_field_type(key: str) -> str | None:
    field_type = classify_key(key, ALL_PACKS)
    return field_type if field_type in _CARD_TYPES else None


def _label_field_type(key: str) -> str | None:
    field_type = classify_key(key, ALL_PACKS)
    return field_type if field_type in _LABEL_TYPES else None


def _mask_card_field(value: str, field_type: str) -> str:
    return mask_card_value(value) if field_type == "card" else mask_by_field_type(value, field_type)


def mask_card_elements(text: str) -> str:
    """``text`` with each XML element whose local name the key rules call a
    card, a CVV or other SAD masked as that key's value is, in every pack --
    rule 3, and redact_body's first pass over a body's elements:

    - a CVV's or SAD's text, children and all, is its label;
    - a card's text is a card value (`mask_card_value`): a card number
      truncated, what a card key refuses `[CARD-MASKED]`, anything else
      shown. A card element holding elements -- a card object, CyberSource's
      `<card>` -- is read as the key walk reads one: a CVV or SAD element in
      it is its label, and every other element's text a card value, so a
      card number under `<accountNumber>` is truncated as under
      `<cardNumber>`, and an expiry reads through.

    A text is masked as it decodes (a CDATA section's content, entities
    resolved), and masking's own output passes through.
    """
    return _mask_elements(text, _card_field_type, _mask_card_element)


def _mask_card_element(raw: str, field_type: str) -> str:
    if field_type != "card":
        value = _element_text(raw)
        masked = mask_by_field_type(value, field_type)
        return raw if masked == value else masked
    if "<" not in raw:
        return _card_run(raw)
    raw = _mask_elements(raw, _label_field_type, _mask_card_element)
    # Each CDATA section's content, and each run of text between the markup,
    # a card value. A section is found by `find`, not a lazy regex, which
    # read on to the end of the text from each opening nothing closes.
    parts, at = [], 0
    while (opening := raw.find("<![CDATA[", at)) != -1:
        if (closing := raw.find("]]>", opening + 9)) == -1:
            break
        parts.append(_TEXT_RUN.sub(_card_text, raw[at:opening]))
        content = raw[opening + 9 : closing]
        masked = mask_card_value(content)
        parts.append(raw[opening : closing + 3] if masked == content else masked)
        at = closing + 3
    parts.append(_TEXT_RUN.sub(_card_text, raw[at:]))
    return "".join(parts)


# Markup -- a quoted attribute's `>` its own -- or a run of text between it.
_TEXT_RUN = re.compile(rf"<{_ATTRIBUTES}>|<[^<>]*>|(?P<text>[^<]+)")


def _card_text(m: re.Match) -> str:
    return m.group(0) if m.group("text") is None else _card_run(m.group(0))


def _card_run(text: str) -> str:
    """A run of a card element's text, masked as a card value as it
    decodes."""
    value = html.unescape(text) if "&" in text else text
    masked = mask_card_value(value)
    return text if masked == value else masked


def _card_elements(m: re.Match) -> str:
    return mask_card_elements(m.group(0))


def _cvv_quoted(m: re.Match) -> str:
    q, kw, sep = m.group("q"), m.group("key"), m.group("sep")
    return f"{q}{kw}{q}{sep}{q}{_CVV_LABEL}{q}"


def _cvv_kv(m: re.Match) -> str:
    quote = _unquoted_value_quote(m.group(1))
    return f"{m.group(1)}{quote}{_CVV_LABEL}{quote}"


def _cvv_space(m: re.Match) -> str:
    return f"{m.group(1)} {_CVV_LABEL}"


def _cvv_beside_card(m: re.Match) -> str:
    """Each field of the card's that is three or four digits alone, as the
    label: which of `1227` and `123` after a card is its CVV no rule can
    tell, so neither ships. A date (`12/27`), a field its word names as the
    expiry (`exp 1227`) and a month or year of one or two digits stay."""
    return m.group("card") + _CARD_FIELD.sub(_cvv_field, m.group("fields"))


def _cvv_field(field: re.Match) -> str:
    value = field.group("field")
    return field.group("separator") + (_CVV_LABEL if _BARE_CVV.fullmatch(value) else value)


def _cvv_after_word(m: re.Match) -> str:
    return f"{m.group('lead')}{_CVV_LABEL}"


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


def _userinfo(m: re.Match) -> str:
    scheme, userinfo = m.group("scheme"), m.group("userinfo")
    if m.group("user") is not None:
        # A user alone is an account (`ssh://git@host`) -- unless it is shaped
        # like a card number or holds a card-number run: a saved card's
        # gateway token, as redact_url reads it, and never its hash.
        user = unquote(userinfo)
        if not (pan_shaped(user) or holds_pan_run(user)):
            return m.group(0)
        return f"{scheme}{_SECRET_LABEL}@"
    return f"{scheme}{_mask_userinfo(userinfo)}@"


# How far before an email's local part a URL's scheme can end when what is
# between them is a userinfo masking wrote: two tokens and their colon.
_MASKED_USERINFO_REACH = 2 * _TOKEN_LENGTH + 8
_USERINFO_TEXT = re.compile(rf"{_USERINFO_PART}*")


def _email(m: re.Match) -> str:
    """An email -- never one that starts inside masking's own output: a
    token's body, or a label percent-encoded in a URL's userinfo
    (redact_url's `%5BSECRET-MASKED%5D`), before an `@` is the user or password
    of a URL masking wrote, and the host after it is no email. Only what
    follows a token can be one."""
    text, start = m.string, m.start()
    at = text.index("@", start)
    head = text.rfind(_TOKEN_START, max(0, start - _TOKEN_LENGTH + 1), start)
    if head != -1:
        token = text[head : head + _TOKEN_LENGTH]
        if _TOKEN_SHAPE.fullmatch(token) and not holds_pan_run(token):
            token_end = head + _TOKEN_LENGTH
            if token_end >= at:
                return m.group(0)
            return text[start:token_end] + mask_by_field_type(text[token_end : m.end()], "email")
    scheme = text.rfind("://", max(0, start - _MASKED_USERINFO_REACH), start)
    if scheme != -1:
        userinfo = text[scheme + 3 : at]
        if _USERINFO_TEXT.fullmatch(userinfo) and _mask_userinfo(userinfo) == userinfo:
            return m.group(0)
    return mask_by_field_type(m.group(0), "email")


def _jwt(m: re.Match) -> str:
    return mask_by_field_type(m.group(0), "jwt")


def _ssn(m: re.Match) -> str:
    return mask_by_field_type(_digits_only(m.group(0)), "ssn")


# ---------------------------------------------------------------------------
# Rules, packs and pre-checks
# ---------------------------------------------------------------------------
# Each rule belongs to one pack. `default` is always on, the keyed CVV rules
# among its own; `pci` (card numbers, and a bare 3-4 digit CVV beside card
# context) and `financial_ids` (IBAN, SSN, payment ids) are opt-in: only a PCI
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
# In every CVV keyword: "cv" (cvv, cvc, cvn, cvd, cv number, cardCvv), the rest
# spelled out, or "card code" -- not "card" alone, which most payment lines
# hold.
_CVV_LITERALS = ("cv", "csc", "cav2", "security", "verification")
_CARD_CODE = re.compile(r"card[-_.\s]?code")
_PHONE_SHAPE = re.compile(r"\+\d|\d{3}\D{0,2}\d{3}\D?\d{4}")
_CARD_SHAPE = re.compile(rf"\d(?:{_CARD_SEP}?\d){{11}}")
_SSN_SHAPE = re.compile(r"\d{3}[-\s]?\d{2}[-\s]?\d{4}")
_IBAN_SHAPE = re.compile(r"[A-Za-z]{2}\d{2}")
_THREE_DIGITS = re.compile(r"\d{3}")


def _has_pem(_text: str, lowered: str) -> bool:
    return "-----begin" in lowered


def _has_credential(_text: str, lowered: str) -> bool:
    return any(word in lowered for word in _CRED_LITERALS)


def _has_value_object(text: str, _lowered: str) -> bool:
    # The label rules only: a keep rule writes no label, and what it keeps is
    # set aside before this rule reads the text (stash_kept).
    return "{" in text and bool(rules := label_rules(value_rules_in_force())) and hinted(text, rules)


def _has_credential_container(text: str, lowered: str) -> bool:
    return ("[" in text or "{" in text or "(" in text) and _has_credential(text, lowered)


def _has_credential_element(text: str, lowered: str) -> bool:
    return "<" in text and _has_credential(text, lowered)


def _has_end_tag(text: str, _lowered: str) -> bool:
    return "</" in text


def _has_cvv_keyword(_text: str, lowered: str) -> bool:
    return any(word in lowered for word in _CVV_LITERALS) or _CARD_CODE.search(lowered) is not None


def _has_id(_text: str, lowered: str) -> bool:
    return "id" in lowered


def _has_iban_shape(text: str, _lowered: str) -> bool:
    return _IBAN_SHAPE.search(text) is not None


def _has_phone_shape(text: str, _lowered: str) -> bool:
    return _PHONE_SHAPE.search(text) is not None


def _has_at(text: str, _lowered: str) -> bool:
    return "@" in text


def _has_userinfo(text: str, _lowered: str) -> bool:
    return "://" in text and "@" in text


def _has_jwt_prefix(_text: str, lowered: str) -> bool:
    # The rules compile with IGNORECASE, so the JWT rule matches "EYJ…" too.
    return "eyj" in lowered


def _has_card_shape(text: str, _lowered: str) -> bool:
    return _CARD_SHAPE.search(text) is not None


def _has_ssn_shape(text: str, _lowered: str) -> bool:
    return _SSN_SHAPE.search(text) is not None


def _has_card_and_digits(text: str, _lowered: str) -> bool:
    # A truncation's stars, or a card number's digits, and three digits.
    return _THREE_DIGITS.search(text) is not None and ("*" in text or _CARD_SHAPE.search(text) is not None)


# A bare CVV's card: a card number the card rule truncated -- its first six,
# stars and last four, or stars and the last four -- or a run of 12-19 digits
# it left as it is (one glued to a word). The card rule runs first, so a PAN
# in the text is its truncation by the time the bare CVV rules look.
_CVV_CARD = r"(?:(?<![\d*])(?:\d{6})?\*{4,}\d{4}|(?<!\d)\d{12,19})(?!\d)"
# What joins the fields of a card written out: whitespace, or `|`, `,`, `;`
# or `:` with any whitespace around it.
_CVV_SEPARATOR = r"(?:\s*[|,;:]\s*|\s+)"
# A field of a card written out, after the card number: the CVV, the expiry
# -- a month, a year, or both joined by `/` or `-`, perhaps after its word
# (`exp 12/27`) -- or the label masking wrote for one. Never the start of a
# longer number, a date, a time or an amount (`2026-09-30`, `10:30`,
# `100.000`): what follows those ends the card's fields before them. A comma
# does not: it separates the fields of a CSV row (`4111…,12,27,123`).
_CVV_FIELD = (
    r"(?:(?:(?:exp(?:iry|ires|iration)?(?:\s*date)?|valid(?:\s*thru)?)\s*[:=]?\s*)?\d{1,4}(?:[/-]\d{1,4})?"
    r"|\[CVV-MASKED\])(?![\w*/-]|[.:]\d)"
)
_CARD_FIELD = re.compile(rf"(?P<separator>{_CVV_SEPARATOR})(?P<field>{_CVV_FIELD})", re.IGNORECASE)
# A field that may be the CVV: three or four digits, nothing else.
_BARE_CVV = re.compile(r"\d{3,4}")
# The CVV after its word: three or four digits, as a field is.
_CVV_DIGITS = r"\d{3,4}(?![\w*/-]|[.:]\d)"
# Between a CVV word and its digits: a sign, or a word or two a sentence puts
# there (`the cvv is 123`, `security code was 1234`, `cvv number 123`).
_CVV_LINK = r"(?=[\s:=#-])(?:\s+(?:is|was|of|number|value|code)){0,2}\s*[:=#-]?\s*"


# Every credential match contains one of these words, and starts inside the
# run of [\w-] characters holding it, or on the quote right before that run
# (rule 5's quoted key). So the credential rules only need trying at those
# positions, not at every position of a long body — re.sub tries every one,
# and at ~16 µs per rule per gateway body that was most of the masking cost.
# The words are found with str.find on the lowercased text: a case-insensitive
# regex alternation gets no literal-prefix speedup and costs as much as the
# rule it would be saving. The keyed CVV rules are read the same way, near
# their own words (_cvv_word_starts).
_CRED_WORDS = (
    "bearer", "basic", "digest", "credential", "authorization", "authorisation",
    "token", "secret", "password", "passwd", "key",
)
_KEY_CHAR = re.compile(r"[\w-]")
_KEY_RUN = re.compile(r"[\w-]*")


def _word_starts(lowered: str, words: tuple[str, ...]) -> set[int]:
    starts = set()
    for word in words:
        index = lowered.find(word)
        while index != -1:
            starts.add(index)
            index = lowered.find(word, index + 1)
    return starts


def _credential_word_starts(lowered: str) -> list[int]:
    return sorted(_word_starts(lowered, _CRED_WORDS))


def _cvv_word_starts(lowered: str) -> list[int]:
    """Where a keyed CVV rule's keyword can hold one of its words: every CVV
    keyword holds a gate literal, or is `card code`."""
    starts = _word_starts(lowered, _CVV_LITERALS)
    starts.update(match.start() for match in _CARD_CODE.finditer(lowered))
    return sorted(starts)


# A credential match starts at most this far before its credential word: the
# bounded key prefix (128), its separator, and rule 5's opening quote.
_CRED_REACH = 130
# ...and a CVV match before its CVV word: the bounded key prefix (64) and its
# separator, or a camelCase word (64), `card_`, and rule 9's opening quote.
_CVV_REACH = 72


def _near_words(
    word_starts: Callable[[str], list[int]], reach: int
) -> Callable[[re.Pattern, Callable, str], str]:
    """A Rule.scan for rules whose every match holds one of the words
    ``word_starts`` finds, starting inside the run of word characters and
    hyphens holding it -- at most ``reach`` characters before it -- or on the
    quote right before that run."""

    def scan(pattern: re.Pattern, repl, text: str) -> str:
        """pattern.sub(repl, text), trying only positions a match can start at."""
        lowered = _folded_lower(text)
        if lowered is None:
            return pattern.sub(repl, text)
        parts = []
        copied = 0  # text[:copied] is already in parts
        tried = 0  # every position below this has been tried or lies inside a match
        run_start = run_end = -1  # the [\w-] run found for the previous word
        for word_start in word_starts(lowered):
            if word_start < tried:
                continue
            if not run_start <= word_start <= run_end:
                # Once per run, not once per word: a run holding many words
                # ("keykeykey…") would otherwise be quadratic. Its start only
                # as far back as a match can reach, which is all `first` needs;
                # its end, to know whether the next word shares it.
                bound = max(0, word_start - reach - 1)
                run_start = word_start
                while run_start > bound and _KEY_CHAR.match(text, run_start - 1):
                    run_start -= 1
                run_end = _KEY_RUN.match(text, word_start).end()
            first = max(tried, run_start - 1, word_start - reach)
            for position in range(first, word_start + 1):
                match = pattern.match(text, position)
                if match:
                    parts.append(text[copied : match.start()])
                    parts.append(repl(match))
                    copied = tried = match.end()
                    break
            else:
                tried = word_start + 1
        if not parts:
            return text
        parts.append(text[copied:])
        return "".join(parts)

    return scan


_sub_near_credential_words = _near_words(_credential_word_starts, _CRED_REACH)
# Tried at every word boundary instead, a long `a-a-a-…` cost 0.7 s per rule.
_sub_near_cvv_words = _near_words(_cvv_word_starts, _CVV_REACH)


def _rule(pack, regex, repl, gate, scan=None, prose_only=False):
    return (pack, regex, repl, gate, scan, prose_only)


# ---------------------------------------------------------------------------
# The 24 content rules, in execution order. DO NOT REORDER — several rules
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
#   6. SSN before the bare CVV rules — a space-separated SSN's outer groups
#      are each CVV-shaped.
#   7. The bare CVV rules last — the card a CVV sits beside is the
#      truncation the card rule wrote.
#   8. URL userinfo before phone and email — a password is a credential,
#      not a phone number, and `user:pw@host.tld` keeps its host rather than
#      masking as an email.
#   9. The XML credential element before the other credential rules — they
#      would mask a `password=`, `"token": …` or `Bearer x` inside its text
#      first, and the element's value, holding their token, was hashed again.
#  10. The value rule before every credential rule, the XML one included —
#      a value a rule matches under `"token": …` or in `<password>` was
#      hashed whole.
#  11. The `API-Key` scheme before the `key=value` credential rule — that
#      would mask a `password=` inside its value first, which it never does
#      after `Authorization:`, and the two forms would carry different tokens.
#  12. The XML card, CVV and SAD element before the XML credential element —
#      a `<cvv>` inside `<password>` was part of the text the credential's
#      token hashed, where the key walk gives a CVV under a credential key
#      its label.
#  13. Kept spans are stashed before every rule (mask_by_patterns →
#      stash_kept): what a keep rule ships is a placeholder while the rules
#      read the text, so none of them reads into it -- a credential rule
#      would hash it, the payment-id rule mask its `"transactionId"` -- and
#      one that splits text around it never misreads a quote. A placeholder a
#      rule destroys takes the value with it.
# ---------------------------------------------------------------------------

_RULE_TABLE = (
    # 1. PEM key block.
    _rule(
        "default",
        r"-----BEGIN [A-Z ]*KEY-----[\s\S]*?-----END [A-Z ]*KEY-----",
        _mask_pem,
        _has_pem,
    ),
    # 2. Value rules — a JSON object in text, or in a JSON string, that a
    # label rule in force matches first (`value_rules`,
    # ECSCTX_MASK_VALUE_RULES): the rule's label, never a token, in every
    # pack. Nothing configured, or keep rules alone, nothing runs; text
    # holding none of the label rules' hints is never parsed. Before the
    # credential rules, which would hash one under `"token": …` first.
    _rule(
        "default",
        _OBJECT_TEXT,
        _value_object,
        _has_value_object,
    ),
    # 3. Card, CVV and SAD — an XML element named as the key walk names one
    # (<cvv>123</cvv>, <ns2:CardSecurityCode>…</ns2:CardSecurityCode>,
    # <pin>, <cardNumber>), whatever namespace prefix and attributes it has,
    # its text masked as that key's value is (`mask_card_elements`): a CVV's
    # or SAD's its label, children and all; a card's a card value, and a card
    # object's field by field. In every pack, as the key walk reads a key: a
    # test card that fails Luhn under <cardNumber> is truncated without
    # `pci`. No end tag, no element, as for rule 4, and the same walk.
    _rule(
        "default",
        r"<[\s\S]*",
        _card_elements,
        _has_end_tag,
    ),
    # 4. Credential — an XML element (<password>s3cret</password>,
    # <wsse:Password Type="PasswordText">…</wsse:Password>), for a body that
    # never went through redact_body: its local name a credential keyword, as
    # rules 5 and 7 read a key, whatever namespace prefix and attributes it
    # has. The value runs to the end tag, children and all, and is masked as
    # it decodes (`_element_text`). No end tag, no element: a route in a
    # message (`DELETE /v1/cards/<str:token>/`) is a start tag's shape. The
    # walk is the rule (`_mask_elements`): the pattern hands it the text from
    # the first `<`, since a regex pairing each start tag with its end tag
    # looked for one from every start tag, in quadratic time.
    _rule(
        "default",
        r"<[\s\S]*",
        _cred_elements,
        _has_credential_element,
    ),
    # 5. Credential — quoted key ("token": "abc123"), the value to its
    # unescaped closing quote.
    _rule(
        "default",
        rf"(?P<q>[\"'])(?P<key>{_CRED_KEYWORD})(?P=q)(?P<sep>\s*:\s*)(?P=q)"
        rf"(?P<value>{_quoted_body('q')}*)(?P=q)",
        _cred_quoted,
        _has_credential,
        _sub_near_credential_words,
    ),
    # 6. Credential — Ottu's `API-Key` scheme word standing alone (not the end
    # of a header name, `X-API-Key`), without its `Authorization:`: the
    # scheme and the value are one value, as after Authorization (rule 7), and
    # carry the header's token. Any value to its delimiter -- the word is the
    # evidence, and a key may have no digit (1 in 1,550 of Ottu PG's Fernet
    # keys). Before rule 7, which would mask a `password=` inside the value
    # first, as it never does after `Authorization:`.
    _rule(
        "default",
        rf"(?<![\w-])api-key[ \t]+(?!{_WHOLE_TOKEN})(?P<value>{_UNQUOTED_VALUE})",
        _api_key_scheme,
        _has_credential,
        _sub_near_credential_words,
    ),
    # 7. Credential — ":" / "=" (secret_key=abc123). A value that opens with a
    # quote a closing one matches runs to it (`quote`); any other, to its
    # delimiter. An empty quoted value is none: quotes doubled as CSV and SQL
    # escape one (`password=""s3cret`) are structure before the value. The
    # quotes around a JSON-escaped key are the key's, and a value between
    # escaped quotes (`escaped`: JSON in a JSON string) runs to its matching
    # one. After Authorization (`auth`) the scheme is part of the value, as it
    # is of the header under its key -- `Authorization: Bearer x` masks
    # `Bearer x`, the token `mask_secret` gives it -- and is never the whole
    # value while more follows it: then pass 2 would read `Bearer` off
    # `Bearer [REDACTED]`. Nor is a token after the scheme (what masking the
    # credential alone left) hashed again with it.
    _rule(
        "default",
        rf"\b(?P<prefix>(?P<key>(?P<auth>{_AUTH_KEYWORD})|{_OTHER_CRED_KEYWORD})(?:\\?[\"']|\s)*[:=]\s*"
        rf"(?:(?P<quote>(?<!\\)[\"'])(?={_quoted_value_body('quote')}+(?P=quote))"
        rf"|(?P<escaped>\\\")(?={_ESCAPED_QUOTED_UNIT}+\\\")|(?:\\?[\"'])+)?)"
        rf"(?P<value>(?(quote){_quoted_value_body('quote')}+|(?(escaped){_ESCAPED_QUOTED_UNIT}+|(?!{_WHOLE_TOKEN})"
        rf"(?(auth)(?:{_AUTH_SCHEME}[ \t]+(?={_VALUE_START})(?!{_WHOLE_TOKEN}))?(?!{_AUTH_SCHEME}[ \t]+\S))"
        rf"{_UNQUOTED_VALUE})))",
        _cred_kv,
        _has_credential,
        _sub_near_credential_words,
    ),
    # 8. Credential — a container after the key (`password=['a', 'b']`), as a
    # %-style argument renders one: rule 7 never starts a value at an opening
    # bracket, so `password=%(pw)s` with a list shipped it whole (#160054).
    # The whole container is the value, and a repr's quoted key keeps it a
    # string. Not a JSON key's: the key walk masked that container by its keys
    # before writing it (the saved card under `token` shows its own number,
    # brand and expiry); nor a container holding only masking's own output,
    # which a record's field renders.
    _rule(
        "default",
        rf"\b(?P<prefix>(?P<key>{_CRED_KEYWORD})(?P<quote>'?)\s*[:=]\s*){_NOT_A_LABEL}(?P<value>{_CONTAINER})",
        _cred_container,
        _has_credential_container,
        _sub_near_credential_words,
    ),
    # 9. CVV — quoted key ("cvv": "123"). The keyed CVV rules (9, 10, 14) are
    # `default`: a CVV must not ship from any service, and a default-pack one
    # (Connect) receives the CVV a saved-card payment sends. A value that
    # starts as a CVV runs to its end, as a credential's does: none of it is
    # left after the first four digits.
    _rule(
        "default",
        rf"(?P<q>[\"'])(?P<key>{_CVV_KEYWORD})(?P=q)(?P<sep>\s*:\s*)(?P=q)\d{{3}}{_quoted_body('q')}*(?P=q)",
        _cvv_quoted,
        _has_cvv_keyword,
        _sub_near_cvv_words,
    ),
    # 10. CVV — ":" / "=" (cvv=123).
    _rule(
        "default",
        rf"\b({_CVV_KEYWORD}(?:\\?[\"']|\s)*[:=](?:\\?[\"']|\s)*)\d{{3}}{_VALUE_UNIT}*",
        _cvv_kv,
        _has_cvv_keyword,
        _sub_near_cvv_words,
    ),
    # 11. Payment/transaction/auth id — quoted key ("payment_id": "abc12345").
    _rule(
        "financial_ids",
        rf"([\"'])({_PAYMENT_ID_KEYWORD})\1(\s*:\s*)\1([A-Za-z0-9_\-]+)\1",
        _payid_quoted,
        _has_id,
    ),
    # 12. Payment/transaction/auth id (payment_id: abc12345).
    _rule(
        "financial_ids",
        rf"\b({_PAYMENT_ID_KEYWORD}\s*[:=]\s*)([A-Za-z0-9_\-]{{8,}})\b",
        _payid_kv,
        _has_id,
    ),
    # 13. Credential — bare space (Bearer abc12345). A value of eight or more
    # characters with a digit among them, "ptok:" counted too (Bearer
    # ptok:hunter2), to its delimiter: prose says "Bearer of bad news".
    _rule(
        "default",
        rf"\b(?P<keyword>{_CRED_KEYWORD})\s+(?!{_WHOLE_TOKEN})(?=(?:(?!\d){_VALUE_UNIT})*\d)"
        rf"(?P<value>{_VALUE_START}{_VALUE_UNIT}{{7,}})",
        _cred_space,
        _has_credential,
        _sub_near_credential_words,
    ),
    # 14. CVV — bare space (CVV 123).
    _rule(
        "default",
        rf"\b({_CVV_KEYWORD})\s+\d{{3}}{_VALUE_UNIT}*",
        _cvv_space,
        _has_cvv_keyword,
        _sub_near_cvv_words,
    ),
    # 15. Payment/transaction/auth id — bare space (payment_id abc12345).
    _rule(
        "financial_ids",
        
        rf"\b({_PAYMENT_ID_KEYWORD})\s+(?=[A-Za-z0-9_\-]*\d)([A-Za-z0-9_\-]{{8,}})\b",
        _payid_space,
        _has_id,
    ),
    # 16. IBAN (GB33BUKB20201555555555).
    _rule(
        "financial_ids",
        rf"(?-i:\b(?:{_IBAN_PREFIX})\d{{2}}[A-Z0-9]{{11,30}}\b)",
        _iban,
        _has_iban_shape,
    ),
    # 17. URL userinfo (postgresql://user:password@host), each part masked as
    # redact_url masks it, the scheme, host and port kept: a DSN in exception
    # text. With a password, empty or not (`https://key:@host`), or a token
    # alone, as masking left a user. A user alone (`user`) names an account
    # (`ssh://git@host`) and is left to the other rules -- unless it is shaped
    # like a card number or holds a card-number run, which is the label, as
    # redact_url gives it (#160054). Bounded: a scheme is at most 32
    # characters and starts no longer run of scheme characters, so a long run
    # is read once.
    _rule(
        "default",
        rf"(?<![A-Za-z0-9+.\-])(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]{{0,31}}://)"
        rf"(?P<userinfo>(?-i:{_TOKEN})(?::{_USERINFO_PART}*)?|[^\s/?#:\"'<>]*:{_USERINFO_PART}*"
        rf"|(?P<user>[^\s/?#:\"'<>@]+))@",
        _userinfo,
        _has_userinfo,
    ),
    # 18. Phone — international E.164-style or a bare local number. Union of
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
    # 19. Email (user@example.com).
    _rule(
        "default",
        # Bounded by RFC 5321's limits (64-char local part, 255-char domain):
        # unbounded, a long run of "a-a-a-" before an "@" backtracks
        # quadratically — seconds for one 20 KB string.
        r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}\b",
        _email,
        _has_at,
    ),
    # 20. JWT (eyJhbGciOi....).
    _rule(
        "default",
        r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{3,}\.[A-Za-z0-9_\-]{3,}",
        _jwt,
        _has_jwt_prefix,
    ),
    # 21. Card number — truncated, bare (411111******1111; last 4
    # only below 15 digits, see _truncate_pan); the middle never survives,
    # starred or not. A whole run of digit groups is read at once, and Luhn
    # decides between its readings: _CardRun.
    # The output stays inside the [LABEL…] convention so already_masked()
    # idempotency holds, and the stars break the digit run so a second
    # pass cannot re-match it.
    _rule(
        "pci",
        _CARD_RUN,
        _mask_card_run,
        _has_card_shape,
    ),
    # 22. SSN (123-45-6789).
    _rule(
        "financial_ids",
        r"(?=\d)" + _CARD_LEAD_GUARD + r"\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
        _ssn,
        _has_ssn_shape,
    ),
    # 23. CVV beside a card — a bare 3-4 digit group among the fields written
    # after a card number or its truncation, up to three of them:
    # `4111111111111111 123`, `411111******1111|12/27|123`. A CVV is worth
    # nothing without its card and is written beside it; any other 3-4 digit
    # group in a line that mentions a card is a status, a duration, a count,
    # an amount or a decline code (#160054: `card list returned 200 in 350
    # ms`). It never sees a whole scalar field value (prose_only): there,
    # "000" is a PSP response code, and the key says what it is.
    _rule(
        "pci",
        rf"(?P<card>{_CVV_CARD})(?P<fields>(?:{_CVV_SEPARATOR}{_CVV_FIELD}){{1,3}})",
        _cvv_beside_card,
        _has_card_and_digits,
        prose_only=True,
    ),
    # 24. CVV after its word — a bare 3-4 digit group after a CVV word, a
    # sign or a word or two between them (`the cvv is 123`), which the keyed
    # rules 9, 10 and 14 do not read. Tried near the CVV words, as they are.
    _rule(
        "pci",
        rf"\b(?P<lead>{_CVV_KEYWORD}{_CVV_LINK}){_CVV_DIGITS}",
        _cvv_after_word,
        _has_cvv_keyword,
        _sub_near_cvv_words,
        prose_only=True,
    ),
)


RULES: tuple[Rule, ...] = tuple(
    Rule(f"{index}:{repl.__name__}", pack, re.compile(regex, re.IGNORECASE), repl, gate, scan, prose)
    for index, (pack, regex, repl, gate, scan, prose) in enumerate(_RULE_TABLE, start=1)
)


# The value rule, for mask_objects.
_OBJECT_RULE = next(rule for rule in RULES if rule.repl is _value_object)


# Just the card rule, for mask_card_value: the value already has a card key
# saying what it is, so the other rules have nothing to add and applying them
# would mask by shape inside a field that is not about them.
_CARD_RULE_ONLY: tuple[Rule, ...] = tuple(
    rule for rule in RULES if rule.repl is _mask_card_run
)


def _by_identity(cache: dict, rules: tuple, build: Callable[[tuple], Any]) -> Any:
    """What ``build`` makes of ``rules``, cached on the tuple's identity.

    Never on its hash: a tuple of rules hashes every rule, and a compiled
    pattern hashes its whole program, on every call -- 30 µs a string for
    the default pack once a large rule was in it, which lru_cache paid on
    each lookup. Keeping ``rules`` in the entry keeps its id from being
    reused; a cache past its bound is emptied, not evicted, as _clean is.
    """
    entry = cache.get(id(rules))
    if entry is None or entry[0] is not rules:
        if len(cache) >= _BY_IDENTITY_LIMIT:
            cache.clear()
        entry = cache[id(rules)] = (rules, build(rules))
    return entry[1]


# More distinct rule sets than a process makes: rules_for() holds one per
# combination of packs, and scalar_rules() one per set.
_BY_IDENTITY_LIMIT = 64
_scalar: dict[int, tuple[tuple, tuple]] = {}


def scalar_rules(rules: tuple[Rule, ...]) -> tuple[Rule, ...]:
    """``rules`` minus the ones that may only run over prose.

    Cached on the rule tuple's identity so the result is a stable object:
    mask_by_patterns keys its known-clean set on tuple identity.
    """
    return _by_identity(_scalar, rules, lambda rules: tuple(rule for rule in rules if not rule.prose_only))


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
        # No case-folded text to gate by, so every rule runs: masking more
        # than necessary is the safe direction to fail in.
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
    if (stash := stash_kept(text)) is not None:
        # Not recorded as clean: it is no fixed point of the rules, which
        # would read into what it ships.
        return stash.restore(mask_by_patterns(stash.text, rules))
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


_gates: dict[int, tuple[tuple, tuple]] = {}


def _distinct_gates(rules: tuple[Rule, ...]) -> tuple:
    return _by_identity(_gates, rules, lambda rules: tuple(dict.fromkeys(rule.gate for rule in rules)))


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
    # `cardnum` ends the key: MIGS's `vpc_CardNum`, `card_num`. `card_id` is an
    # id, not a number, and stays unclassified.
    return (
        lowered == "card"
        or "pan" in words
        or "cardnumber" in joined
        or joined.endswith(("cardno", "cardnum"))
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

# A tokenized card's payment cryptogram and a 3DS authentication value: one-time values
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


# A card summary -- brand, holder's name, masked number and expiry in one
# string -- carries the holder's name. The whole key only: `card_details_url`
# is not one.
_CARD_SUMMARY_KEY = "carddetails"


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
    r"access|master|root|session|api|hmac|aes|merchant|shared|client)keys?"
    # ...also when written out in an encoding (`privateKeyPem`).
    r"(?:pem|der|hex|base64|b64)?$"
    r"|keymaterial$"
    # MIGS's `vpc_AccessCode`: the merchant access code, a gateway credential.
    r"|accesscode$"
)


def _is_cred_key(joined: str) -> bool:
    return _CRED_KEY_JOINED.search(joined) is not None


# Key material named for what it is: an algorithm, size or mode before `key`
# (`aes256Key`, `hmacSha256Key`, `3desKey`), or a payment-HSM key as the last
# word. Matched on words, so `codes_key` is not a DES key, and an id, alias or
# check value (`sessionKeyId`, `tmkCheckValue`) stays readable.
_KEY_ALGORITHM_WORD = re.compile(
    r"(?:aes|des|3des|tripledes|hmac|rsa|ecdsa|mac|gcm|cbc|sha|"
    r"symmetric|cipher|crypto|wrapped|encrypted|raw)\d*"
)
_KEY_ENCODING_WORDS = frozenset({"pem", "der", "hex", "base64", "b64"})
_HSM_KEY_WORDS = frozenset({"zpk", "zmk", "tmk", "tpk", "bdk", "ipek", "kek", "dek"})


def _is_key_material(words: list[str]) -> bool:
    if len(words) > 1 and words[-1] in _KEY_ENCODING_WORDS:
        words = words[:-1]
    if not words:
        return False
    if words[-1] in _HSM_KEY_WORDS:
        return True
    if words[-1] not in ("key", "keys") or len(words) < 2:
        return False
    # `aes_256_key`: a bare size sits between the algorithm and `key`.
    before = words[-3] if words[-2].isdigit() and len(words) > 2 else words[-2]
    return _KEY_ALGORITHM_WORD.fullmatch(before) is not None


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
            if _is_cred_key(joined) or _is_key_material(words):
                return "secret"
            # Before the pack gate and before `generic`: a person's identity
            # number is PII in every service (`customer_civil_id` too).
            if _is_national_id_key(joined, words):
                return "ssn"
            if "financial_ids" not in packs:
                continue
        if field_type == "phone" and _is_tel_key(words):
            return "phone"
        if field_type == "generic" and (
            _is_name_key(joined) or _is_holder_key(words) or joined == _CARD_SUMMARY_KEY
        ):
            # Also between address and generic, as before.
            return "name"
        if pattern.search(lowered):
            return field_type
    return None


def check_if_sensitive_keyword(dict_key: str) -> str | None:
    """classify_key with every pack on."""
    return classify_key(dict_key, ALL_PACKS)
