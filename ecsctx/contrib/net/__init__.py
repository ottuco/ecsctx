"""Credential redaction for the network boundary (shared by all services).

The net boundary logs ``url.full`` and (when textual) the response body for
every outbound call. Legacy providers send ``username``/``password``/``apikey``
in the GET query string and OAuth-style secrets as body values, so both must
be masked before logging. ``mask_sensitive_data`` does not cover these shapes:
it masks PII (email/phone) and ``Authorization`` *headers*, but not a secret
carried as a query param or a body value — an OAuth token response would reach
the index intact.

Ported from ottu_backend's ``contrib/net/redact.py`` so every service imports
one copy. Best-effort by design: matches common credential key names
(substring + a few exact short keys, case-insensitive). Exotic single-letter
keys may slip — those providers should move credentials out of the query.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
from collections.abc import Collection
from http import HTTPStatus
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunsplit

from ecsctx.masking.filters import MaskPIIFilter

_REDACTED = "[REDACTED]"

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
# Deliberately excludes a bare "token": gateways use it for non-secret payment
# and session identifiers that log readers rely on.
_DEFAULT_SECRET_BODY_KEYS = (
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "password",
    "api_key",
    "apikey",
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
    as the masking settings bridge). An explicit configure_redaction() call
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
    """Cached (hint_re, json_re, form_re) for the current key set."""
    global _compiled_cache
    keys = _get_secret_keys()
    cache_key = keys
    if _compiled_cache is not None and _compiled_cache[0] == cache_key:
        return _compiled_cache[1]
    # Cheap pre-check: scans without lowercasing (and so without copying) the body.
    hint_re = re.compile("|".join(keys), re.IGNORECASE)
    # "access_token": "..."  ->  "access_token": "[REDACTED]"
    json_re = re.compile(
        r'("(?:' + "|".join(keys) + r')"\s*:\s*)"[^"]*"',
        re.IGNORECASE,
    )
    # access_token=...  ->  access_token=[REDACTED]  (form-encoded bodies)
    # `\b` cannot fire between "_" and "secret", so "client_secret=" is never half-matched.
    form_re = re.compile(
        r"\b(" + "|".join(keys) + r")=[^&\s]*",
        re.IGNORECASE,
    )
    _compiled_cache = (cache_key, (hint_re, json_re, form_re))
    return _compiled_cache[1]


def _is_credential_key(key: str) -> bool:
    k = key.lower()
    return k in _CREDENTIAL_EXACT or any(hint in k for hint in _CREDENTIAL_HINTS)


def redact_url(url: str, *, secrets: Collection[str] | None = None) -> str:
    """Return ``url`` with credential-looking query-param values masked.

    ``secrets`` holds literal values (e.g. a saved-card token carried in the
    URL path) to mask wherever they occur in the URL. The path is otherwise
    left alone, so deliberately logged identifiers such as ``session_id`` stay
    visible. Empty values are ignored; with no secrets the result is exactly
    what the query-param masking alone produces.
    """
    if not isinstance(url, str) or not url:
        return url  # None/empty/non-str: nothing to redact, never raise on a log path
    try:
        parts = urlsplit(url)
    except ValueError:
        return _REDACTED  # unparseable -> don't risk logging it raw
    if parts.query:
        redacted = [
            (k, _REDACTED if _is_credential_key(k) else v)
            for k, v in parse_qsl(parts.query, keep_blank_values=True)
        ]
        url = urlunsplit(parts._replace(query=urlencode(redacted)))
    if isinstance(secrets, str):
        secrets = (secrets,)  # a bare string is one secret, not a char collection
    for secret in secrets or ():
        if secret:
            url = url.replace(str(secret), _REDACTED)
    return url


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
    """Mask credential values inside a response body before it is logged.

    Only unambiguous credential keys are masked. A bare ``token`` is
    deliberately left alone: gateways use it for non-secret payment/session
    identifiers that are the main thing a log reader needs.
    """
    hint_re, json_re, form_re = _get_compiled()
    if not hint_re.search(text):
        return text
    text = json_re.sub(rf'\1"{_REDACTED}"', text)
    return form_re.sub(rf"\1={_REDACTED}", text)


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
    cannot be serialised is simply not logged.
    """
    body = json_body if json_body is not None else data
    if body is None:
        return None
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

    Credential query params are redacted by default (``redact=True``), so
    ``url.full`` — the field every dashboard shows — can never carry a
    password or API key. Pass ``redact=False`` only when the URL is already
    redacted. ``urlparse`` never raises on malformed input: hostname is
    simply None if the URL can't be parsed.
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
