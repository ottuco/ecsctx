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
import os
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_REDACTED = "[REDACTED]"

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
_TEXTUAL_CONTENT_TYPES = ("application/json", "application/xml", "text/", "+xml", "+json")
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


def redact_url(url: str) -> str:
    """Return ``url`` with credential-looking query-param values masked."""
    if not isinstance(url, str) or not url:
        return url  # None/empty/non-str: nothing to redact, never raise on a log path
    try:
        parts = urlsplit(url)
    except ValueError:
        return _REDACTED  # unparseable -> don't risk logging it raw
    if not parts.query:
        return url
    redacted = [
        (k, _REDACTED if _is_credential_key(k) else v)
        for k, v in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return urlunsplit(parts._replace(query=urlencode(redacted)))


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


def loggable_body(response: Any) -> str | None:
    """The response body to log: capped text for textual responses, else None.

    ``response`` is duck-typed (``headers`` mapping + ``text``) so this module
    stays dependency-free — any ``requests``-like response works. Redacts
    before capping: a cap that lands mid-value would leave the head of a
    token exposed, since the JSON pattern needs the closing quote to match.
    Never raises: a body that can't be read is omitted, not logged raw.
    """
    try:
        content_type = response.headers.get("Content-Type", "").lower()
        if not any(t in content_type for t in _TEXTUAL_CONTENT_TYPES):
            return None
        return redact_body(response.text or "")[: _get_body_log_cap()]
    except Exception:  # noqa: BLE001 - log path must never raise; omit the body instead
        return None


__all__ = [
    "configure_redaction",
    "configure_redaction_from_env",
    "loggable_body",
    "redact_body",
    "redact_url",
]
