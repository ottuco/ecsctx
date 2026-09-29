"""Tokenization + label formatting shared by every masking rule.

safe_tokenize wraps ecsctx.pii.tokenize with a fail-closed fallback: if PII is
not configured, or tokenization fails for any reason, it returns
[PII_REDACTED] rather than letting raw PII through or raising.
"""

from __future__ import annotations

import re
from urllib.parse import unquote_plus

from ecsctx.masking.fields_rules import get_field_rule
from ecsctx.pii import tokenize as _pii_tokenize
from ecsctx.pii.crypto import TOKEN_PREFIX, TOKEN_VERSION
from ecsctx.pii.normalize import normalize_value

# The one shape ecsctx.pii.tokenize emits (hmac_tokenize): prefix, version, and
# an HMAC-SHA-256 digest in unpadded base64url, 43 characters. Anything else
# that starts "ptok:" was typed that way: it is no token, and is masked like
# any other value of its type.
_TOKEN_START = f"{TOKEN_PREFIX}:v{TOKEN_VERSION}:"
_TOKEN_HEAD = re.escape(_TOKEN_START)
_TOKEN = rf"{_TOKEN_HEAD}[A-Za-z0-9_-]{{43}}"
_TOKEN_SHAPE = re.compile(_TOKEN)
_TOKEN_LENGTH = len(_TOKEN_START) + 43
# ...and in that shape with a card-number run in its body -- twelve digits,
# joined by single hyphens at most, as patterns.holds_pan_run reads one -- it
# is `ptok:v1:` typed before a card number: nothing takes it for a token. A
# real token's body holds such a run about once in 10^8.
_CARDLESS_TOKEN = rf"(?!{_TOKEN_HEAD}[A-Za-z0-9_-]{{0,31}}[0-9](?:-?[0-9]){{11}}){_TOKEN}"
_REDACTED = "[PII_REDACTED]"

# What _truncate_pan produces: the BIN, stars, and the last four (15 digits and
# up), or stars and the last four below that. With the [CARD-MASKED:…] wrapper
# gone, THIS SHAPE IS THE MARKER -- it is the only thing saying "a PAN already
# passed through here", so it has to be recognisable on its own. Five stars is
# the fewest _truncate_pan ever emits (a 15-digit PAN); {4,} leaves a margin.
# The stars match from the first one only: a search tried from every star of a
# long run reads to the end of it each time, which is quadratic.
_TRUNCATED_PAN = r"(?:\d{6})?(?<!\*)\*{4,}\d{4}"

# A whole value that masking itself produced: a bare label, a bare token, a
# truncated PAN, or the pre-0.11 bracketed card form, which still arrives from
# documents masked by an older release. A token only in the exact shape.
_MASKED_VALUE = re.compile(
    rf"\[[A-Z0-9-]+-MASKED(?::{_TOKEN})?\]|{_TOKEN}"
    rf"|{_TRUNCATED_PAN}|\[CARD-MASKED:{_TRUNCATED_PAN}\]"
)

# A credential some other masker already replaced: `[REDACTED]`
# (ecsctx.contrib.net until 0.15.4), `[PII_REDACTED]` (safe_tokenize without a
# keyset), stars, or stars after an auth scheme (`Bearer ****`). Hashed, each
# is one token shared by every record that carries it: a credential that was
# never there.
_PLACEHOLDER = re.compile(r"\[(?:PII_)?REDACTED\]|(?:[A-Za-z][\w-]*\s+)?\*+")


def already_tokenized(text: str) -> bool:
    return _TOKEN_SHAPE.fullmatch(text) is not None


def safe_tokenize(value: str, field_type: str = "generic") -> str:
    if not value:
        return value

    # Idempotency: already tokenized.
    if already_tokenized(value):
        return value

    # Quote-stripping (single or double) happens inside tokenize(), via
    # normalize_value() — a general case for every field type, not just this
    # call site. See ecsctx.pii.normalize.strip_wrapping_quotes.
    try:
        token = _pii_tokenize(value, field_type)
    except Exception:
        return _REDACTED
    return token


def make_label(field_type: str) -> str:
    return F"{field_type.upper().replace('_', '-')}-MASKED"


def already_masked(text: str) -> bool:
    """Whether ``text`` is, in its entirety, something masking already produced.

    Anchored on purpose. It used to be a substring test for "-MASKED:" /
    "-MASKED]", which was safe only while every masked value wore brackets: a
    bare truncated PAN has no punctuation to search for, and a substring test
    would let a marker-shaped fragment vouch for the rest of a longer value.
    """
    return _MASKED_VALUE.fullmatch(text) is not None


# The types judged here for a card number inside the value, with the `pci`
# pack: every path a credential or a payment id takes into a log ends in
# mask_by_field_type, as the key walk's own `pci` branch judges a PII leaf
# (filters._mask_pii_leaf).
_PAN_CHECKED_TYPES = frozenset({"secret", "payment_id"})
# A truncation the card rule writes, its first six and last four showing. As a
# credential it is ten digits of a saved card's sixteen-digit gateway token.
_SHOWN_TRUNCATION = re.compile(r"\d{6}\*{4,}\d{4}")


def mask_by_field_type(value: str, field_type: str) -> str:
    """The token for ``value``, bare (``ptok:v1:…``), as a reader searches for
    it; ``[LABEL]`` where no token can stand: a type that is never tokenized,
    or PII tokenization not configured or failing.

    Brackets mean nothing survived. Where something real is carried -- a token,
    or a PAN's BIN and last four -- it is carried bare.

    Masking's own output passes through as it is, unless a card-number run is
    in it: ``ptok:v1:`` typed before a card number is in a token's exact shape,
    and is the label, in every pack. A credential is the label, never a token,
    when it is shaped like a card number (a saved card's sixteen-digit gateway
    token), since a keyed hash of what may be a PAN is what PCI DSS FAQ 1117
    forbids, and when it is a placeholder another masker left -- judged as it
    is written and as a URL or form encoding decodes it (``%22…%22``, ``+``).
    With `pci` among the call's packs, and the process's -- a filter's own
    ``packs=`` for the call, with the process's (``config.packs_in_force``)
    -- a credential or payment id that holds a card-number run anywhere
    (``holds_pan_run``) is the label too. Applied here, where every caller
    passes -- the key walk, the credential and payment-id text rules, a
    route parameter, ``ecsctx.contrib.net`` -- rather than by each of them.
    """
    field_rule = get_field_rule(field_type)
    label = make_label(field_rule.field_type)
    if not value:
        # Nothing was there. A label would read as a value that had been
        # hidden -- the same reason a null stays null.
        return value
    if not field_rule.tokenizable:
        return f"[{label}]"
    if field_type in _PAN_CHECKED_TYPES:
        # Judged as it would be hashed: tokenize() drops the surrounding
        # whitespace and one layer of matching quotes first, so '"4111…"'
        # was a keyed hash of the bare card number. And as a URL or a form
        # encoding decodes it, as redact_url and redact_body read it before
        # they mask: `%224111…%22` in text was a keyed hash of a card number
        # in quotes, `4111+1111+…` of one with its spaces encoded.
        forms = [normalize_value(value, field_type)]
        if "%" in value or "+" in value:
            forms.append(normalize_value(unquote_plus(value), field_type))
        if field_type == "secret" and any(_SHOWN_TRUNCATION.fullmatch(bare) for bare in forms):
            # Never passed through as masking's own output: rendered from its
            # argument, a gateway token the card rule truncated showed ten
            # of its digits where the key walk gives the label.
            return f"[{label}]"
    if already_masked(value):
        return f"[{label}]" if _holds_a_card_number(value) else value
    if field_type in _PAN_CHECKED_TYPES:
        # Imported here: patterns imports this module as it loads.
        from ecsctx.masking.patterns import holds_pan_run, pan_shaped

        if field_type == "secret":
            for bare in forms:
                if already_masked(bare):
                    # Masking's own output in quotes (the credential text
                    # rule keeps a value's quotes around its label) or
                    # encoded (redact_url's userinfo): hashed, every such
                    # label would be one token shared by every record.
                    return f"[{label}]" if holds_pan_run(bare) else value
                if pan_shaped(bare) or _PLACEHOLDER.fullmatch(bare):
                    return f"[{label}]"
        if _pci_in_force() and any(holds_pan_run(bare) for bare in forms):
            # Without `pci` among the call's packs and the process's it is
            # hashed: a default-pack service receives no card numbers, and
            # the label would stand in for 7% of the 64-hex signatures
            # Connect logs, where a token can stand.
            return f"[{label}]"
    token = safe_tokenize(value, field_rule.field_type)
    if token == _REDACTED:
        return f"[{label}]"
    return token


def _holds_a_card_number(text: str) -> bool:
    # Imported here: patterns imports this module as it loads.
    from ecsctx.masking.patterns import holds_pan_run

    return holds_pan_run(text)


def _pci_in_force() -> bool:
    """Whether `pci` is among the call's packs, and the process's: those of
    the masking call in progress -- a MaskPIIFilter's own -- with the
    process's. Imported here: config imports patterns, which imports this
    module as it loads."""
    from ecsctx.masking.config import packs_in_force

    return "pci" in packs_in_force()
