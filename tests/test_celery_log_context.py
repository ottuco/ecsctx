"""Tests for ecsctx.contrib.celery.log_context.

Focus: structlog contextvars isolation around task execution. Celery prefork
children are long-lived and run many tasks, so anything a task binds onto
structlog contextvars (e.g. via LogContextBinder) would leak into every later
task's logs unless the prerun/postrun hooks isolate it.
"""

from types import SimpleNamespace

import pytest
import structlog

from ecsctx.context import LoggingContext, _logging_context, get_logging_context
from ecsctx.contrib.celery.log_context import (
    LOG_CONTEXT_KEY,
    _cleanup_context_on_postrun,
    _restore_context_on_prerun,
)


@pytest.fixture()
def clean_logging_state():
    """Start and leave with both context stores empty, whatever ran before."""
    structlog.contextvars.clear_contextvars()
    _logging_context.set(None)
    yield
    structlog.contextvars.clear_contextvars()
    _logging_context.set(None)


def _make_task(log_context_data=None):
    request = SimpleNamespace(id="celery-task-1")
    if log_context_data is not None:
        setattr(request, LOG_CONTEXT_KEY, log_context_data)
    return SimpleNamespace(request=request, name="tests.sample_task")


class TestPrerunClearsStaleStructlogContext:
    def test_task_without_propagated_context_starts_clean(
        self, clean_logging_state
    ):
        structlog.contextvars.bind_contextvars(session_id="previous-task-session")
        task = _make_task()

        _restore_context_on_prerun(task=task)

        assert structlog.contextvars.get_contextvars() == {}
        _cleanup_context_on_postrun(task=task)

    def test_task_with_propagated_context_starts_clean(
        self, clean_logging_state
    ):
        structlog.contextvars.bind_contextvars(session_id="previous-task-session")
        task = _make_task({"ctx": {"session_id": "my-session"}, "trace_id": None})

        _restore_context_on_prerun(task=task)

        assert structlog.contextvars.get_contextvars() == {}
        assert get_logging_context().session_id == "my-session"
        _cleanup_context_on_postrun(task=task)


class TestPostrunRestoresCallerContext:
    def test_task_structlog_binds_wiped_and_caller_context_restored(
        self, clean_logging_state
    ):
        # Eager execution fires prerun/postrun in the caller's context; the
        # caller must get its own structlog bindings back.
        structlog.contextvars.bind_contextvars(session_id="caller-session")
        task = _make_task()

        _restore_context_on_prerun(task=task)
        structlog.contextvars.bind_contextvars(session_id="task-bound-session")
        _cleanup_context_on_postrun(task=task)

        assert structlog.contextvars.get_contextvars() == {
            "session_id": "caller-session"
        }

    def test_ecsctx_context_reset_after_task(self, clean_logging_state):
        task = _make_task({"ctx": {"session_id": "my-session"}, "trace_id": None})

        _restore_context_on_prerun(task=task)
        _cleanup_context_on_postrun(task=task)

        assert get_logging_context() == LoggingContext()
