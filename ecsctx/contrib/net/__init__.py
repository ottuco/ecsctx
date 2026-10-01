"""Credential redaction for the network boundary (shared by all services).

The net boundary logs ``url.full`` and (when textual) the request and response
bodies of every outbound call. Legacy providers send
``username``/``password``/``apikey`` in the GET query string, a DSN or proxy URL
carries a password in its userinfo, and OAuth-style secrets come back as body
values, so all of them are masked before logging. ``mask_sensitive_data``
masks what its credential rules name wherever it appears -- ``password=`` in a
query, ``"access_token": …`` in body text, a URL's userinfo, ``cvv=123`` --
but these helpers know their input: a param whose name only hints at a
credential (``user``, ``P``, ``sign``), a card number under its key in a query
or form body, a literal secret in a URL's path, a body masked by its keys
before it is serialised and capped. Each value found is masked as
``mask_secret`` masks a credential, so it carries the token the same value gets
under a key.

Ported from ottu_backend's ``contrib/net/redact.py`` so every service imports
one copy. Best-effort by design: matches common credential key names
(substring + a few exact short keys, case-insensitive). Exotic single-letter
keys may slip — those providers should move credentials out of the query.
"""

from __future__ import annotations

import contextlib
import html
import json
import os
import re
from collections.abc import Collection
from http import HTTPStatus
from typing import Any
from urllib.parse import unquote_plus, urlparse, urlsplit, urlunsplit
from xml.sax.saxutils import escape as xml_escape

from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import (
    _XML_START,
    _card_field_type,
    _closing,
    _element_text,
    _end_tags,
    _mask_card_field,
    _mask_userinfo,
    holds_pan_run,
    mask_card_elements,
    mask_objects,
    mask_secret,
    value_rules_in_force,
)
from ecsctx.masking.tokens import _MASKED_VALUE, _PLACEHOLDER, make_label

_SECRET_LABEL = f"[{make_label('secret')}]"

# Masks a body by its keys before it is serialised (see _masked_json). The
# filter's defaults describe a log record: service/project/log and the
# correlation ids are ecsctx's own fields, and user.name is a login. In a
# gateway body those keys hold whatever the gateway put there — a card, a
# person's name — so nothing is skipped or exempted.
_structure_masker = MaskPIIFilter(skip_keys=(), name_rule_exempt=())

# Query-param key hints: a param whose name contains one of these is treated
# as credential-bearing (case-insensitive).
_CREDENTIAL_HINTS = (
    "user",
    "pass",
    "pwd",
    "key",
    "auth",
    "secret",
    "token",
    "uid",
    "login",
    "sign",
    "access",  # access_code / accessCode / vpc_accesscode (smart_pay/sohar/MIGS)
)
# Short keys that hint matching can't catch (e.g. fcc uses "P" for the password).
_CREDENTIAL_EXACT = frozenset({"p", "u", "pw"})

# Only log a response body when it's textual, and cap its size so a
# binary/large download never bloats a log line.
# Bodies that are a download or a rendered page, never a reply worth reading.
# A deny-list, not an allow-list: gateways mislabel JSON as text/plain or send
# no Content-Type at all often enough that requiring a known-textual type drops
# exactly the replies worth reading.
UNREADABLE_CONTENT_TYPES = (
    "text/html",
    "text/csv",
    "image/",
    "audio/",
    "video/",
    "application/pdf",
    "application/zip",
    "application/octet-stream",
)
_DEFAULT_BODY_LOG_CAP = 4096

# Credential keys whose VALUE must never reach the log, whatever the body shape.
# A bare "token" among them, as the key walk classifies it: left alone, a saved
# card's sixteen-digit gateway token went out whole. With a keyset its value is
# still its token, so a gateway's payment or session id correlates.
_DEFAULT_SECRET_BODY_KEYS = (
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "password",
    "api_key",
    "apikey",
    # Telr's merchant credential, sent in the request body.
    "authkey",
    "secret",
)

# --- Configurable redaction (explicit call wins over env) ----------------------
# Mirrors the configure_masking()/configure_masking_from_env() pattern:
# services commit sane defaults and override per deploy without code changes.
_extra_secret_keys: tuple[str, ...] | None = None
_body_log_cap: int | None = None
_redact_auto_configure_attempted: bool = False
_compiled_cache: tuple | None = None


def configure_redaction(
    *,
    extra_secret_keys: list[str] | None = None,
    body_log_cap: int | None = None,
) -> None:
    """Extend the secret-body key list and/or the logged-body cap."""
    global _extra_secret_keys, _body_log_cap, _redact_auto_configure_attempted
    global _compiled_cache
    _extra_secret_keys = tuple(k for k in (extra_secret_keys or []) if k)
    if body_log_cap is not None:
        _body_log_cap = body_log_cap
    _redact_auto_configure_attempted = True
    _compiled_cache = None


def _from_django(setting: str) -> Any:
    """Read a Django setting, or None if Django is absent or not configured.

    Mirrors ecsctx.identity._from_django: the import lives inside the
    function, so pure-Python/FastAPI consumers (no Django installed) fall
    through to env vars with no hard dependency and no import-time cost.
    """
    try:
        from django.conf import settings
    except ImportError:
        return None
    if not getattr(settings, "configured", False):
        return None
    return getattr(settings, setting, None)


def _django_pending() -> bool:
    """True if Django is installed but its settings aren't ready yet."""
    try:
        from django.conf import settings
    except ImportError:
        return False
    return not getattr(settings, "configured", False)


def _load_env() -> None:
    """Resolve the env-var layer into the module globals."""
    global _extra_secret_keys, _body_log_cap
    if _extra_secret_keys is None:
        raw_keys = os.environ.get("ECSCTX_REDACT_EXTRA_SECRET_KEYS", "")
        _extra_secret_keys = tuple(k.strip() for k in raw_keys.split(",") if k.strip())
    if _body_log_cap is None:
        raw_cap = os.environ.get("ECSCTX_REDACT_BODY_LOG_CAP", "").strip()
        if raw_cap:
            with contextlib.suppress(ValueError):
                if (cap := int(raw_cap)) > 0:
                    _body_log_cap = cap


def configure_redaction_from_env() -> None:
    """Load redaction overrides from env (idempotent)."""
    global _redact_auto_configure_attempted
    if _redact_auto_configure_attempted or (
        _extra_secret_keys is not None or _body_log_cap is not None
    ):
        return
    _redact_auto_configure_attempted = True
    _load_env()


def _ensure_configured() -> None:
    """Resolve redaction config once: explicit call > Django settings > env.

    Retries until Django settings are importable, so a first call during
    settings.py import doesn't pin env values permanently (same lazy pattern
    as the masking exemptions). An explicit configure_redaction() call
    wins wholesale — even a partial one — matching masking_is_configured().
    """
    global _redact_auto_configure_attempted, _extra_secret_keys, _body_log_cap
    global _compiled_cache
    if _redact_auto_configure_attempted:
        return
    django_keys = _from_django("ECSCTX_REDACT_EXTRA_SECRET_KEYS")
    django_cap = _from_django("ECSCTX_REDACT_BODY_LOG_CAP")
    if django_keys is None and django_cap is None and _django_pending():
        return  # settings mid-import: retry at the next log call
    _redact_auto_configure_attempted = True
    if django_keys is not None:
        if isinstance(django_keys, str):
            django_keys = [k.strip() for k in django_keys.split(",") if k.strip()]
        _extra_secret_keys = tuple(k for k in django_keys if k)
    if django_cap is not None:
        with contextlib.suppress(ValueError, TypeError):
            if (parsed := int(django_cap)) > 0:
                _body_log_cap = parsed
    _load_env()
    _compiled_cache = None


def _reset_redaction() -> None:
    """Reset redaction config. For testing only."""
    global _extra_secret_keys, _body_log_cap, _redact_auto_configure_attempted
    global _compiled_cache
    _extra_secret_keys = None
    _body_log_cap = None
    _redact_auto_configure_attempted = False
    _compiled_cache = None


def _get_secret_keys() -> tuple[str, ...]:
    _ensure_configured()
    return _DEFAULT_SECRET_BODY_KEYS + (_extra_secret_keys or ())


def _get_body_log_cap() -> int:
    _ensure_configured()
    return _body_log_cap or _DEFAULT_BODY_LOG_CAP


def _get_compiled() -> tuple:
    """Cached (hint_re, json_re, form_re, element names) for the current key set."""
    global _compiled_cache
    keys = _get_secret_keys()
    cache_key = keys
    if _compiled_cache is not None and _compiled_cache[0] == cache_key:
        return _compiled_cache[1]
    # Cheap pre-check: scans without lowercasing (and so without copying) the body.
    hint_re = re.compile("|".join(keys), re.IGNORECASE)
    # "access_token": "..."  ->  "access_token": "<masked>"
    # The value is read past an escaped quote: `"[^"]*"` stopped at the one in
    # "a\"b" and left the rest of the value in clear. Past any escaped
    # character, too, and to the end of the text when no quote closes it: a
    # body json.loads rejects -- a backslash before a line break, a body cut
    # mid-value -- is exactly the one that reaches this rule as text. The
    # closing quote is looked for, not taken: in `""password": "…"` it also
    # opens the next key, whose value it hid.
    json_re = re.compile(
        r'("(?:' + "|".join(keys) + r')"\s*:\s*)"([^"\\]*(?:\\[\s\S][^"\\]*)*\\?)(?="|\Z)',
        re.IGNORECASE,
    )
    # access_token=...  ->  access_token=<masked>  (form-encoded bodies)
    # `\b` cannot fire between "_" and "secret", so "client_secret=" is never half-matched.
    # A value runs to the next `&` or whitespace, as it always did: every
    # reading that ended it at a quote left the rest of some secret in clear.
    # Only the structure at its two ends stays outside the mask
    # (_split_form_value).
    form_re = re.compile(
        r"\b(" + "|".join(keys) + r")=(" + _FORM_VALUE + ")",
        re.IGNORECASE,
    )
    # An XML element named by one of them, lowercased: element names are
    # matched case-insensitively, as the keys are.
    names = frozenset(key.lower() for key in keys)
    _compiled_cache = (cache_key, (hint_re, json_re, form_re, names))
    return _compiled_cache[1]


def _is_credential_key(key: str) -> bool:
    k = key.lower()
    return k in _CREDENTIAL_EXACT or any(hint in k for hint in _CREDENTIAL_HINTS)


# A form value: to the next `&` or whitespace, and never into an end tag. In
# `<note>password=abc</note>` the element's text ends there, as the
# credential text rules read it: read on, the value took the tag with it.
# Unrolled: a lookahead at every character of every value made a 64 KB form
# body's field pass twice as slow as 0.15.5's.
_FORM_VALUE = r"[^&\s<]*(?:<(?!/)[^&\s<]*)*"


def redact_url(url: str, *, secrets: Collection[str] | None = None) -> str:
    """Return ``url`` with its userinfo and credential-looking query and
    fragment params masked, each as ``mask_secret`` masks a credential: its
    token, or ``[SECRET-MASKED]``. A param whose key the key rules call a
    card, CVV or other SAD is masked by that type instead: a card number
    truncated, a CVV ``[CVV-MASKED]``, never a token.

    The userinfo's user and password are masked each as it decodes
    (``https://<user>:<password>@host``), the host and port kept; an empty
    part stays empty, and a label's brackets there are percent-encoded
    (``%5BSECRET-MASKED%5D``), as a netloc must be to parse. The fragment's
    ``key=value`` params are read as the query's are (an OAuth implicit grant
    returns ``#access_token=…``).
    ``secrets`` holds literal values (e.g. a saved-card token carried in the
    URL path) to mask wherever they occur in the URL, longest first, so one
    that contains another is masked whole. The path is otherwise left alone,
    so deliberately logged identifiers such as ``session_id`` stay visible.
    Empty secrets are ignored. A credential param's value is replaced in place
    and every other param is left as written; an empty value stays empty. The
    URL is rebuilt only when something in it was masked, and a URL that cannot
    be parsed is masked whole. Masking a URL twice masks it once.
    """
    if not isinstance(url, str) or not url:
        return url  # None/empty/non-str: nothing to redact, never raise on a log path
    if isinstance(secrets, str):
        secrets = (secrets,)  # a bare string is one secret, not a char collection
    # One pass, longest first: a shorter secret inside a longer one, masked
    # first, left the rest of the longer one in clear; and masked one after
    # another, a short secret was found again inside the token or label a
    # longer one had just become.
    literals = sorted({str(s) for s in secrets or () if s}, key=len, reverse=True)
    if literals:
        literal_re = re.compile("|".join(map(re.escape, literals)))
        url = literal_re.sub(lambda match: mask_secret(match.group()), url)
    try:
        parts = urlsplit(url)
    except ValueError:
        return mask_secret(url)  # unparseable -> don't risk logging it raw
    userinfo, at, host = parts.netloc.rpartition("@")
    # A label's brackets percent-encoded: urlsplit refuses brackets in a
    # netloc whose host is no IPv6 address, so the masked URL would not parse
    # again -- not in redact_url, nor in ecs_url's urlparse. The userinfo is
    # read as it decodes, so a second pass leaves it as it is.
    masked = _mask_userinfo(userinfo).replace("[", "%5B").replace("]", "%5D")
    netloc = f"{masked}@{host}" if at else parts.netloc
    query, fragment = _mask_params(parts.query), _mask_params(parts.fragment)
    if (netloc, query, fragment) != (parts.netloc, parts.query, parts.fragment):
        url = urlunsplit(parts._replace(netloc=netloc, query=query, fragment=fragment))
    return url


def _mask_params(params: str) -> str:
    """A query or fragment, ``&``-separated ``key=value`` params, each masked
    by its key."""
    if not params:
        return params
    return "&".join(_mask_query_field(field) for field in params.split("&"))


def _mask_query_field(field: str) -> str:
    """One ``key=value`` of a query or fragment: a card, CVV or SAD key's value
    masked as its type is, a credential's as ``mask_secret`` masks one, each
    written unencoded so it reads as the truncation, label or token it is;
    anything else byte for byte, since re-encoding it changed what a reader
    searches for."""
    key, equals, value = field.partition("=")
    if not equals:
        return field
    name, decoded = unquote_plus(key), unquote_plus(value)
    if field_type := _card_field_type(name):
        masked = _mask_card_field(decoded, field_type)
        return field if masked == decoded else f"{key}={masked}"
    if _is_credential_key(name):
        return f"{key}={mask_secret(decoded)}"
    return field


def url_host(url: str) -> str:
    """The host to name in a log message. The full URL stays in ``url.full``.

    A message is a grouping key, so it must not carry the URL itself: a
    per-merchant endpoint makes every line unique and defeats aggregation. The
    host says where the call went at a glance and stays bounded.
    """
    with contextlib.suppress(ValueError):
        if host := urlsplit(url or "").hostname:
            return host
    return "unknown host"


def redact_body(text: str) -> str:
    """Mask credential values inside a response body before it is logged, each
    as ``mask_secret`` masks a credential: its token, or ``[SECRET-MASKED]``.

    Only unambiguous credential keys are masked, a bare ``token`` among them
    as the key walk classifies it: a card-shaped one (a saved card's gateway
    token) is ``[SECRET-MASKED]``, any other its token or label. A value is
    masked as what it decodes to -- a JSON string unescaped, a form value
    unquoted -- so it carries the token the same value gets under a key; one
    already masked passes through.

    A form value runs to the next ``&``, whitespace or end tag. Only the
    structure at its two ends -- a quote or an escaped one, and ``}``,
    ``]``, ``,``, a JSON key's ``":``, ``>`` or ``/>`` -- stays as written;
    the rest is the value, unescaped first only when it sits between escaped
    quotes in a JSON string. A value, JSON or form, that holds a card-number
    run is the label. A form field whose key the key rules call a card, CVV
    or other SAD is masked by that type, whatever the credential keys: a
    card number truncated, a CVV ``[CVV-MASKED]``.

    An XML element is read as a key: its local name, whatever its namespace
    prefix and attributes, classified as a query or form key is. A card, CVV
    or SAD name masks its text by that type, as the text rule does
    (``mask_card_elements``: a card object field by field); then a
    credential name (as ``redact_url`` reads a param's, or one of the secret
    keys) masks its text as a credential, the label when it holds a
    card-number run, a CVV inside it already its label. The text runs to
    the end tag, children and all, and is masked as it decodes (a CDATA
    section's content, entities resolved). Any other element's text that is
    JSON or XML written with entities goes through these rules as it
    decodes, and is written back escaped.

    A value a value rule in force matches (``ECSCTX_MASK_VALUE_RULES``), as
    JSON anywhere in the body or as JSON in a JSON string, is the rule's
    label first, before a credential's rule could hash it.
    """
    if "{" in text and (rules := value_rules_in_force()):
        text = mask_objects(text, rules)
    if "<" in text:
        text = _mask_xml_elements(text)
    if "=" in text:
        text = _FORM_FIELD.sub(_mask_card_form_field, text)
    hint_re, json_re, form_re, _names = _get_compiled()
    if not hint_re.search(text):
        return text
    masked = form_re.sub(_mask_form_value, json_re.sub(_mask_json_value, text))
    if masked != text and "=" in masked:
        # A credential masked there can uncover a card, CVV or SAD field the
        # form field pass read as part of the field holding it
        # (`"password": "password="paymentCvv=…`): one more pass masks it,
        # so one call leaves nothing a second would mask.
        masked = _FORM_FIELD.sub(_mask_card_form_field, masked)
    return masked


# Any form field: its key as a form writes one (`card[number]` too), not
# glued to more of one, and its value up to the next `&`, whitespace or end
# tag.
_FORM_FIELD = re.compile(r"(?<![\w.\-\[\]%])([\w.\-\[\]%]+)=(" + _FORM_VALUE + ")")

def _is_credential_element(name: str, names: frozenset[str]) -> bool:
    """A credential's element name: one a query param's name would be read
    as (`_is_credential_key`), or one of the secret body keys."""
    return _is_credential_key(name) or name.lower() in names


def _mask_xml_elements(text: str) -> str:
    """Each element named as a card, CVV or SAD key is, its text masked by
    that type, as the text rule masks one (`mask_card_elements`) -- first, so
    a CVV inside a credential's element is its label, not part of the text
    the credential's token hashes. Then each element named as a credential
    key is, its text masked as a credential; and entity-encoded text in any
    other leaf, through the body rules as it decodes."""
    text = mask_card_elements(text)
    names = _get_compiled()[3]
    parts, copied, ends = [], 0, None
    for start in _XML_START.finditer(text):
        if start.start() < copied:
            continue  # inside an element already masked whole
        if ends is None:
            ends = _end_tags(text)
        # No end tag, no element: a route (`/v1/cards/<str:token>/`) is a
        # start tag's shape. Each end tag is found once (`_end_tags`).
        if (closing := _closing(ends, start)) is None:
            continue
        end = closing.start()
        if not _is_credential_element(start.group("local"), names):
            if (masked := _encoded_leaf(text, start.end(), end)) is not None:
                parts += [text[copied : start.end()], masked]
                copied = end
            continue
        value = _element_text(text[start.end() : end])
        masked = _SECRET_LABEL if holds_pan_run(value) else mask_secret(value)
        if masked != value:
            parts += [text[copied : start.end()], masked]
            copied = end
    if not parts:
        return text
    parts.append(text[copied:])
    return "".join(parts)


def _encoded_leaf(text: str, start: int, end: int) -> str | None:
    """The text of a leaf, ``text[start:end]``, masked by the body rules as
    it decodes and escaped again -- when it is JSON or XML written with
    entities, and masking changed it. A leaf's raw text needs nothing here,
    nor a form body's: the body rules read them where they stand, `&amp;` a
    form's separator either way. Decoded, a form value ran on past `&quot;`,
    and a leaf the first pass left as a form body read differently on the
    next."""
    if text.find("<", start, end) != -1 or text.find("&", start, end) == -1:
        return None
    decoded = html.unescape(text[start:end])
    if decoded.lstrip()[:1] not in ("{", "[", "<"):
        return None
    masked = redact_body(decoded)
    if masked == decoded:
        return None
    return xml_escape(masked)


def _mask_card_form_field(match: re.Match) -> str:
    """A form field whose key names a card, a CVV or other SAD, masked by that
    type (a JSON string's structure at its ends kept, as ``_mask_form_value``
    keeps it); any other field as it is."""
    field_type = _card_field_type(unquote_plus(match.group(1)))
    if field_type is None:
        return match.group(0)
    head, inner, tail = _split_form_value(match.group(2))
    value = unquote_plus(inner)
    masked = _mask_card_field(value, field_type)
    if masked == value:
        return match.group(0)
    return f"{match.group(1)}={head}{masked}{tail}"


def _mask_json_value(match: re.Match) -> str:
    raw = match.group(2)
    try:
        value = json.loads(f'"{raw}"')
    except ValueError:
        value = raw  # an escape JSON does not know: masked as it is written
    closed = match.end() < len(match.string)
    if holds_pan_run(value):
        # Closed or run on to the end of the text, judged as a form value is:
        # hashed, it was a keyed hash of a card number, and a value shaped
        # like a token passed through with one in it.
        masked = _SECRET_LABEL
    else:
        masked = mask_secret(value)
    dumped = json.dumps(masked)
    # A closed value's quote is still in the text: write only the rest.
    return match.group(1) + (dumped[:-1] if closed else dumped)


# The structure a form value may end in -- a quote or an escaped one, a JSON
# key's `":`, `}`, `]`, `,`, `>`, and `/>` after a quote -- written backwards,
# so one match from the start of the reversed value finds the longest such
# end. After an unquoted value only the `>` is structure: a `/` right after a
# token reads to the credential text rule as more of the credential, so the
# next pass hashed the token again.
_TAIL_REVERSED = re.compile(r'(?:"\\?|:"\\?|[}\],]|>/(?=")|>)*')


def _tail(text: str) -> str:
    """The longest end of ``text`` that is structure only."""
    return text[len(text) - _TAIL_REVERSED.match(text[::-1]).end() :]


# The structure a form value may open with: a quote or an escaped one, or a
# run of them -- quotes doubled as CSV and SQL escape one (`password=""x`,
# `password=''x`), as the credential text rule reads them. A lone `'` is the
# value's own: closed by another, it is a quoted value, normalized as one.
_HEAD = re.compile(r'(?:\\?["\'])(?:\\?["\'])+|(?:\\?")*')


def _split_form_value(value: str) -> tuple[str, str, str]:
    """``value`` as the structure it opens with, the value itself, and the
    structure it ends in.

    A label, token, truncation or placeholder with only structure after it
    is taken whole: `[SECRET-MASKED],` is the label and a comma, where the
    longest structural end alone would read `[SECRET-MASKED` and `],`.
    """
    head = _HEAD.match(value).group()
    body = value[len(head) :]
    for shape in (_MASKED_VALUE, _PLACEHOLDER):
        whole = shape.match(body)
        if whole and _tail(rest := body[whole.end() :]) == rest:
            return head, whole.group(), rest
    tail = _tail(body)
    return head, body[: len(body) - len(tail)], tail


def _mask_form_value(match: re.Match) -> str:
    head, inner, tail = _split_form_value(match.group(2))
    value = inner
    if head == '\\"' and tail.startswith('\\"'):
        # Between escaped quotes it sits in a JSON string, so it is JSON text:
        # unescaped, it carries the token the same value gets under a key. A
        # raw form body is never unescaped -- its backslashes are its own.
        with contextlib.suppress(ValueError):
            value = json.loads(f'"{inner}"')
    value = unquote_plus(value)
    if holds_pan_run(value):
        # Asked before the pass-through below: a value shaped like a token can
        # carry a card number too.
        masked = _SECRET_LABEL
    else:
        masked = mask_secret(value)
        if masked == value:
            # Empty, or masked already once its quotes are dropped: left
            # exactly as written.
            return match.group(0)
    return f"{match.group(1)}={head}{masked}{tail}"


def _masked_json(body: Any) -> str:
    """Mask a structure by its keys, then serialise it.

    Masking must happen before the body becomes a string: once it is one, a
    key such as ``securityCode`` no longer sits next to its value for the
    key-name rules, and three digits match no content rule worth having.
    Serialised rather than logged as a dict so ``http.*.body.content`` keeps
    one Elasticsearch mapping instead of one field per gateway key.
    """
    return json.dumps(_structure_masker._mask_value(body), default=str)


def loggable_request_body(data: Any, json_body: Any) -> str | None:
    """The request body to log: masked, redacted, capped text — or None.

    ``json_body`` wins over form ``data``, as in ``requests``. Never raises:
    logging must not be the thing that breaks a payment, so a body that
    cannot be serialised is simply not logged. A cyclic body no longer lands
    there: masking cuts it at its depth cap, so it is logged bounded and
    marked like any other.
    """
    body = json_body if json_body is not None else data
    if body is None:
        return None
    if isinstance(body, str):
        # A caller that serialised the body itself (`data=json.dumps(payload)`)
        # gets the same key masking as one that passed a dict. Only a string that
        # is not a JSON object or list stays text, left to `redact_body`.
        with contextlib.suppress(ValueError):
            parsed = json.loads(body)
            if isinstance(parsed, (dict, list)):
                body = parsed
    try:
        text = body if isinstance(body, str) else _masked_json(body)
    except (TypeError, ValueError, RecursionError):  # RecursionError: a cyclic structure
        return None
    # Redact before capping: a cap landing mid-value would leave the head of a
    # token exposed, since the JSON pattern needs the closing quote to match.
    return redact_body(text)[: _get_body_log_cap()]


def _is_error(response: Any) -> bool:
    status = getattr(response, "status_code", None)
    return isinstance(status, int) and status >= HTTPStatus.BAD_REQUEST


def loggable_body(response: Any) -> str | None:
    """The response body to log: masked, redacted, capped text, or None.

    ``response`` is duck-typed (``headers`` mapping, ``text``, optional
    ``status_code``) so any ``requests``-like response works. Never raises: a
    body that can't be read is omitted, not logged raw.
    """
    try:
        content_type = response.headers.get("Content-Type", "").lower()
        text = response.text
        if any(t in content_type for t in UNREADABLE_CONTENT_TYPES):
            # A document is noise on a success and the whole story on a
            # failure: when a gateway answers with an edge proxy's block page,
            # that page is the explanation. A receipt PDF still costs nothing,
            # because it comes back 200.
            if _is_error(response) and isinstance(text, str):
                return redact_body(text)[: _get_body_log_cap()]
            return None
        if not isinstance(text, str):
            return None
        # Parse first so the key-name rules see keys; a reply that is not a
        # JSON object or list falls through to the text path.
        with contextlib.suppress(ValueError):
            parsed = json.loads(text or "")
            if isinstance(parsed, (dict, list)):
                return redact_body(_masked_json(parsed))[: _get_body_log_cap()]
        return redact_body(text)[: _get_body_log_cap()]
    except Exception:  # noqa: BLE001 - log path must never raise; omit the body instead
        return None


def parse_json_or_raw(raw: bytes | str | None) -> Any:
    """Parse a raw HTTP body as JSON for logging under ``payload=``.

    Returns it unchanged when it isn't valid JSON (an HTML error page, a
    non-JSON callback body, binary/non-UTF-8 bytes). Logging raw bytes
    directly renders as their Python repr (b'...'), a garbled,
    unsearchable string — this keeps the body as real structured JSON when
    it is one, and never crashes the log call when it isn't.
    """
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return raw


def ecs_url(url: str, *, redact: bool = True) -> dict:
    """Build an ECS-compliant ``url`` object from a raw URL string.

    Redacted by default (``redact=True``, ``redact_url``): ``url.full`` — the
    field every dashboard shows — carries no userinfo password and no value of
    a credential-named query or fragment param, only their tokens or labels.
    A credential in the path is masked only when it is named: pass the URL
    through ``redact_url(url, secrets=[...])`` first. Pass ``redact=False``
    only when the URL is already redacted. ``urlparse`` never raises on
    malformed input: hostname is simply None if the URL can't be parsed.
    """
    if redact:
        url = redact_url(url)
    parsed = urlparse(url)
    return {"full": url, "domain": parsed.hostname, "path": parsed.path}


def _ecs_body(bytes_: int | None, content: str | None) -> dict | None:
    if bytes_ is None and content is None:
        return None
    body: dict = {}
    if bytes_ is not None:
        body["bytes"] = bytes_
    if content is not None:
        body["content"] = content
    return body


def ecs_http(
    *,
    request_method: str | None = None,
    request_mime_type: str | None = None,
    request_referrer: str | None = None,
    request_bytes: int | None = None,
    request_id: str | None = None,
    request_body_bytes: int | None = None,
    request_body_content: str | None = None,
    response_status_code: int | None = None,
    response_mime_type: str | None = None,
    response_bytes: int | None = None,
    response_body_bytes: int | None = None,
    response_body_content: str | None = None,
    version: str | None = None,
) -> dict:
    """Build the ECS ``http`` field from named arguments only — never from an
    object whose attributes get read blindly. Every parameter name is a real
    ECS sub-field; a typo in a caller's kwarg is a Python TypeError, not a
    silently wrong JSON key. Only the arguments actually passed end up in the
    result. Body CONTENT params exist for completeness but should rarely be
    used — the body belongs in the ``payload=`` kwarg (masked by
    ``mask_sensitive_data``) or behind ``loggable_body()``.
    """
    request: dict = {}
    if request_method is not None:
        request["method"] = request_method
    if request_mime_type is not None:
        request["mime_type"] = request_mime_type
    if request_referrer is not None:
        request["referrer"] = request_referrer
    if request_bytes is not None:
        request["bytes"] = request_bytes
    if request_id is not None:
        request["id"] = request_id
    request_body = _ecs_body(request_body_bytes, request_body_content)
    if request_body is not None:
        request["body"] = request_body

    response: dict = {}
    if response_status_code is not None:
        response["status_code"] = response_status_code
    if response_mime_type is not None:
        response["mime_type"] = response_mime_type
    if response_bytes is not None:
        response["bytes"] = response_bytes
    response_body = _ecs_body(response_body_bytes, response_body_content)
    if response_body is not None:
        response["body"] = response_body

    http: dict = {}
    if request:
        http["request"] = request
    if response:
        http["response"] = response
    if version is not None:
        http["version"] = version
    return http


__all__ = [
    "UNREADABLE_CONTENT_TYPES",
    "configure_redaction",
    "configure_redaction_from_env",
    "ecs_http",
    "ecs_url",
    "loggable_body",
    "loggable_request_body",
    "parse_json_or_raw",
    "redact_body",
    "redact_url",
    "url_host",
]
