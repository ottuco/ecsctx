"""Tests for ecsctx.contrib.rq.log_context.

Focus: structlog contextvars isolation around job execution. Long-lived
(non-forking) workers reuse one execution context for many jobs, so anything a
job binds onto structlog contextvars (e.g. via LogContextBinder) would leak
into every later job's logs unless the wrapper isolates it.
"""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
import structlog

from ecsctx.context import LoggingContext, _logging_context, get_logging_context
from ecsctx.contrib.rq.log_context import LOG_CONTEXT_KEY, with_log_context


@pytest.fixture()
def clean_logging_state():
    """Start and leave with both context stores empty, whatever ran before."""
    structlog.contextvars.clear_contextvars()
    _logging_context.set(None)
    yield
    structlog.contextvars.clear_contextvars()
    _logging_context.set(None)


def _propagated_context(**ctx):
    return {LOG_CONTEXT_KEY: {"ctx": ctx, "trace_id": None}}


class TestJobWithPropagatedContext:
    def test_job_starts_with_clean_logging_state(
        self, clean_logging_state
    ):
        structlog.contextvars.bind_contextvars(session_id="previous-job-session")
        seen = {"sentinel": True}

        @with_log_context
        def job():
            seen.clear()
            seen.update(structlog.contextvars.get_contextvars())

        job(**_propagated_context(session_id="my-session"))

        assert seen == {}

    def test_job_structlog_binds_do_not_leak_to_caller(
        self, clean_logging_state
    ):
        @with_log_context
        def job():
            structlog.contextvars.bind_contextvars(session_id="job-bound-session")

        job(**_propagated_context())

        assert structlog.contextvars.get_contextvars() == {}

    def test_inline_call_restores_caller_structlog_context(
        self, clean_logging_state
    ):
        # Eager/inline execution (tests, is_async=False queues) must hand the
        # caller's structlog context back untouched.
        structlog.contextvars.bind_contextvars(session_id="caller-session")

        @with_log_context
        def job():
            structlog.contextvars.bind_contextvars(session_id="job-session")

        job(**_propagated_context())

        assert structlog.contextvars.get_contextvars() == {
            "session_id": "caller-session"
        }

    def test_propagated_ecsctx_context_restored_inside_job(
        self, clean_logging_state
    ):
        captured = {}

        @with_log_context
        def job():
            captured["ctx"] = get_logging_context()

        fake_job = SimpleNamespace(id="rq-job-1")
        with patch(
            "ecsctx.contrib.rq.log_context.get_current_job", return_value=fake_job
        ):
            job(**_propagated_context(session_id="my-session"))

        assert captured["ctx"].session_id == "my-session"
        assert captured["ctx"].extra["rq_job"] == {"id": "rq-job-1"}
        assert get_logging_context() == LoggingContext()


class TestJobInsideWorker:
    def test_worker_job_without_propagated_context_starts_clean(
        self, clean_logging_state
    ):
        structlog.contextvars.bind_contextvars(session_id="previous-job-session")
        seen = {"sentinel": True}

        @with_log_context
        def job():
            seen.clear()
            seen.update(structlog.contextvars.get_contextvars())

        fake_job = SimpleNamespace(id="rq-job-1")
        with patch(
            "ecsctx.contrib.rq.log_context.get_current_job", return_value=fake_job
        ):
            job()

        assert seen == {}

    def test_worker_job_gets_rq_job_extra(self, clean_logging_state):
        captured = {}

        @with_log_context
        def job():
            captured["ctx"] = get_logging_context()

        fake_job = SimpleNamespace(id="rq-job-1")
        with patch(
            "ecsctx.contrib.rq.log_context.get_current_job", return_value=fake_job
        ):
            job()

        assert captured["ctx"].extra == {"rq_job": {"id": "rq-job-1"}}
        assert get_logging_context() == LoggingContext()


class TestDirectCall:
    def test_plain_call_is_passthrough(self, clean_logging_state):
        # No job, no propagated context: plain function-call semantics, the
        # caller's structlog context stays visible and intact.
        structlog.contextvars.bind_contextvars(session_id="caller-session")

        @with_log_context
        def fn():
            return structlog.contextvars.get_contextvars()

        assert fn() == {"session_id": "caller-session"}
        assert structlog.contextvars.get_contextvars() == {
            "session_id": "caller-session"
        }
