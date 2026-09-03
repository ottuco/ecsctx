"""Where a service's own name comes from.

Three fields identify the emitter, and all three were resolving to defaults in
production: `service.name` reported the process class rather than the service,
`project.name` fell back to the literal string "connect" for every consumer,
and `service.version` read "0.0.0" because APP_VERSION was set nowhere. An audit
could not tell two services apart in a shared index (#159489).

Resolution order is settings, then environment, then a default:

* **Django settings** — versioned code, per service, reviewed like anything
  else. `ECSCTX_PROJECT_NAME`, `ECSCTX_SERVICE_TYPE`, `ECSCTX_APP_VERSION`.
* **Environment** — how it worked before, kept so nothing breaks and so
  non-Django consumers still have a way in.
* **A default**, with a warning emitted once, because a service that cannot say
  what it is should say so rather than quietly claim to be Connect.

Settings are read lazily and the result is cached. ecsctx must import cleanly
without Django (it is an optional extra) and long before the app registry is
ready, so nothing here runs at import time and every lookup is guarded — see
the note in CLAUDE.md about why the Django injector avoids `settings` during
bootstrap. Reading a setting is safe once something is actually logging; it is
the *model* imports that are not.
"""

import os
import sys
import warnings

# "connect" was the old hardcoded default. Keeping it as a literal would mean
# every unconfigured service keeps claiming to be Connect, which is the bug.
UNRESOLVED_PROJECT = "unknown"
UNRESOLVED_VERSION = "0.0.0"

_cache: dict[str, str | None] = {}
_warned: set[str] = set()


def _from_django(setting: str) -> str | None:
    """Read a Django setting, or None if Django is absent or not configured.

    Guarded rather than optimistic: ecsctx ships Django as an optional extra, so
    a non-Django consumer must not pay an ImportError, and `settings` raises
    ImproperlyConfigured until DJANGO_SETTINGS_MODULE is set.
    """
    try:
        from django.conf import settings
    except ImportError:
        return None
    try:
        value = getattr(settings, setting, None)
    except Exception:  # noqa: BLE001 - ImproperlyConfigured and friends
        return None
    return value or None


def _warn_once(field: str, fallback: str) -> None:
    if field in _warned:
        return
    _warned.add(field)
    warnings.warn(
        f"ecsctx could not resolve {field}; logging as {fallback!r}. "
        f"Set ECSCTX_{field.upper()} in Django settings (preferred) or "
        f"{field.upper()} in the environment, so this service is "
        f"distinguishable from every other one in a shared index.",
        RuntimeWarning,
        stacklevel=2,
    )


def _resolve(field: str, fallback: str) -> str:
    if field in _cache:
        return _cache[field] or fallback
    value = _from_django(f"ECSCTX_{field.upper()}") or os.environ.get(field.upper())
    if not value:
        _warn_once(field, fallback)
    _cache[field] = value
    return value or fallback


def reset_cache() -> None:
    """Forget resolved values. For tests, and for a settings change at runtime."""
    _cache.clear()
    _warned.clear()


def get_project_name() -> str:
    return _resolve("project_name", UNRESOLVED_PROJECT)


def get_app_version() -> str:
    return _resolve("app_version", UNRESOLVED_VERSION)


def get_service_type() -> str | None:
    """The declared service class, or None to fall back to argv detection."""
    if "service_type" in _cache:
        return _cache["service_type"]
    value = _from_django("ECSCTX_SERVICE_TYPE") or os.environ.get("SERVICE_TYPE")
    # No warning here: argv detection below is a legitimate answer, not a
    # fallback that loses information the way an unnamed project does.
    _cache["service_type"] = value
    return value


def detect_service() -> tuple[str, str]:
    """(service.name, service.version) for whatever process this is.

    A declared SERVICE_TYPE always wins over argv sniffing. The sniffing exists
    because RQ workers are started by a management command rather than by a
    distinct entrypoint, but it guesses, and a deployment that knows what it is
    should be able to say so — every service reported "rq" for its workers
    before, whichever service they belonged to.
    """
    declared = get_service_type()
    if declared:
        return declared, _version_for(declared)
    for arg in sys.argv:
        if "rqworker" in arg:
            return "rq", _version_for("rq")
        if "rqscheduler" in arg:
            return "rqscheduler", _version_for("rqscheduler")
    return "app", get_app_version()


def _version_for(service_type: str) -> str:
    if service_type == "rq":
        try:
            import rq
        except ImportError:
            return get_app_version()
        return rq.VERSION
    if service_type == "rqscheduler":
        try:
            import rq_scheduler
        except ImportError:
            return get_app_version()
        return ".".join(map(str, rq_scheduler.VERSION))
    return get_app_version()
