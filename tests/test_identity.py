"""Service identity resolution (#159489).

All three identity fields were resolving to defaults in production:
`service.name` reported the process class, `project.name` was the literal
"connect" for every consumer, and `service.version` read "0.0.0". Two services
were indistinguishable in a shared index.
"""

import builtins
import os
import sys
import warnings

import pytest
from django.test import override_settings

from ecsctx import identity


@pytest.fixture(autouse=True)
def _clean_identity(monkeypatch):
    """Resolution is cached and the cache is global."""
    for var in ("PROJECT_NAME", "SERVICE_TYPE", "APP_VERSION"):
        monkeypatch.delenv(var, raising=False)
    identity.reset_cache()
    yield
    identity.reset_cache()


class TestResolutionOrder:
    @override_settings(ECSCTX_PROJECT_NAME="ottu_pg")
    def test_django_settings_win(self, monkeypatch):
        monkeypatch.setenv("PROJECT_NAME", "from_env")
        assert identity.get_project_name() == "ottu_pg"

    def test_environment_is_the_fallback(self, monkeypatch):
        # Kept working so nothing breaks on the way to settings, and so
        # non-Django consumers still have a way in.
        monkeypatch.setenv("PROJECT_NAME", "from_env")
        assert identity.get_project_name() == "from_env"

    def test_unresolved_is_named_unknown_not_connect(self):
        # The old default was the literal "connect", so every unconfigured
        # service claimed to be Connect. That is the bug, not the fallback.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            assert identity.get_project_name() == "unknown"

    def test_unresolved_warns_once(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            identity.get_project_name()
            identity.get_project_name()
            identity.get_project_name()
        relevant = [w for w in caught if "project_name" in str(w.message)]
        assert len(relevant) == 1
        assert "ECSCTX_PROJECT_NAME" in str(relevant[0].message)

    def test_a_resolved_value_does_not_warn(self, monkeypatch):
        monkeypatch.setenv("PROJECT_NAME", "ottu_pg")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            identity.get_project_name()
        assert not [w for w in caught if "project_name" in str(w.message)]

    def test_the_result_is_cached(self, monkeypatch):
        monkeypatch.setenv("PROJECT_NAME", "first")
        assert identity.get_project_name() == "first"
        monkeypatch.setenv("PROJECT_NAME", "second")
        assert identity.get_project_name() == "first"
        identity.reset_cache()
        assert identity.get_project_name() == "second"


class TestServiceDetection:
    @override_settings(ECSCTX_SERVICE_TYPE="pg")
    def test_a_declared_type_beats_argv_sniffing(self, monkeypatch):
        # Every service reported "rq" for its workers before, whichever service
        # they belonged to, because argv was the only signal.
        monkeypatch.setattr(sys, "argv", ["manage.py", "rqworker", "default"])
        name, _version = identity.detect_service()
        assert name == "pg"

    def test_argv_still_detects_a_worker_when_nothing_is_declared(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["manage.py", "rqworker", "default"])
        name, _version = identity.detect_service()
        assert name == "rq"

    def test_plain_process_is_app(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["manage.py", "runserver"])
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            name, version = identity.detect_service()
        assert name == "app"
        assert version == "0.0.0"

    def test_version_comes_from_settings_when_declared(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["manage.py", "runserver"])
        monkeypatch.setenv("APP_VERSION", "6.2.1")
        assert identity.detect_service() == ("app", "6.2.1")

    def test_service_type_does_not_warn(self, monkeypatch):
        """argv detection is a real answer, not a lossy fallback — unlike an
        unnamed project, which cannot be told apart from another service."""
        monkeypatch.setattr(sys, "argv", ["manage.py", "runserver"])
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            identity.get_service_type()
        assert not [w for w in caught if "service_type" in str(w.message)]


class TestWithoutDjango:
    def test_resolution_works_when_django_is_absent(self, monkeypatch):
        """ecsctx ships Django as an optional extra and is imported long before
        the app registry is ready, so every settings lookup is guarded.

        Simulates the import failing the way it would without Django installed,
        and asserts the *caller* still resolves — rather than asserting that a
        mock raises, which would only test the mock.
        """
        real_import = builtins.__import__

        def no_django(name, *args, **kwargs):
            if name == "django.conf" or name.startswith("django."):
                raise ImportError(f"No module named {name!r}")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", no_django)
        monkeypatch.setenv("PROJECT_NAME", "standalone")
        assert identity.get_project_name() == "standalone"

    def test_no_django_and_no_env_still_yields_a_usable_default(self, monkeypatch):
        real_import = builtins.__import__

        def no_django(name, *args, **kwargs):
            if name.startswith("django"):
                raise ImportError(f"No module named {name!r}")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", no_django)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            assert identity.get_project_name() == "unknown"

    def test_improperly_configured_settings_fall_through_to_env(self, monkeypatch):
        import django.conf

        class Unconfigured:
            def __getattr__(self, _name):
                raise django.core.exceptions.ImproperlyConfigured("no settings")

        monkeypatch.setattr(django.conf, "settings", Unconfigured())
        monkeypatch.setenv("PROJECT_NAME", "standalone")
        assert identity.get_project_name() == "standalone"


class TestProcessorsStillWork:
    def test_processors_delegate_to_identity(self, monkeypatch):
        from ecsctx import processors

        monkeypatch.setenv("PROJECT_NAME", "ottu_pg")
        monkeypatch.setenv("APP_VERSION", "6.2.1")
        monkeypatch.setattr(sys, "argv", ["manage.py", "runserver"])
        assert processors._detect_service() == ("app", "6.2.1")
        assert processors._get_app_version() == "6.2.1"

    def test_service_metadata_carries_the_resolved_project(self, monkeypatch):
        monkeypatch.setenv("PROJECT_NAME", "ottu_pg")
        assert identity.get_project_name() == "ottu_pg"
        assert os.environ.get("PROJECT_NAME") == "ottu_pg"


class TestWarningScope:
    """Which fields warn is a decision, not an accident of sharing _resolve."""

    def test_app_version_warns_because_a_release_cannot_be_identified(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            identity.get_app_version()
        assert [w for w in caught if "app_version" in str(w.message)]

    def test_exactly_two_fields_warn_on_a_cold_start(self, monkeypatch):
        """project_name and app_version, not service_type. A worker detected
        from argv is correctly identified; an unnamed project is not."""
        monkeypatch.setattr(sys, "argv", ["manage.py", "runserver"])
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            identity.get_project_name()
            identity.get_app_version()
            identity.get_service_type()
        fields = {
            f
            for f in ("project_name", "app_version", "service_type")
            if any(f in str(w.message) for w in caught)
        }
        assert fields == {"project_name", "app_version"}
