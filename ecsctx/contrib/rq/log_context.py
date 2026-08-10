"""
RQ context propagation utilities.

This module provides decorators and helpers to propagate logging context
from web requests to RQ background jobs.
"""

from contextlib import contextmanager
from dataclasses import asdict
from functools import wraps
import uuid

import structlog
from rq import get_current_job

from ecsctx.context import (
    LoggingContext,
    get_logging_context,
    get_trace_id,
    reset_logging_context,
    set_logging_context,
)


# Reserved kwarg for passing full log context to RQ jobs
LOG_CONTEXT_KEY = "_rq_log_context"


@contextmanager
def _isolated_structlog_contextvars():
    """Run the job on a clean structlog slate, restoring the caller's bindings.

    Non-forking workers (SimpleWorker, gevent) reuse one execution context for
    many jobs, and integrations like LogContextBinder bind structlog
    contextvars with no reset — job N's bindings would leak into job N+1's
    logs. Snapshot-and-restore (rather than a bare clear) keeps inline/eager
    execution safe too: the enclosing request gets its own context back.
    """
    saved = structlog.contextvars.get_contextvars()
    structlog.contextvars.clear_contextvars()
    try:
        yield
    finally:
        structlog.contextvars.clear_contextvars()
        if saved:
            structlog.contextvars.bind_contextvars(**saved)


def capture_log_context() -> dict | None:
    """Capture current logging context + trace_id for RQ job propagation."""
    ctx = get_logging_context()
    trace_id = get_trace_id()

    if not trace_id and ctx == LoggingContext():
        return None

    return {
        "ctx": asdict(ctx),
        "trace_id": trace_id,
    }


def with_log_context(func):
    """
    Decorator for RQ jobs to restore logging context from enqueue time.

    Propagates the full LoggingContext (span_id, user_id, ip, session_id, etc.)
    plus trace_id and rq_job.id so all logs within the job can be correlated
    with the original request.

    Usage:
        @with_log_context
        def my_task(session_id, amount):
            logger.info("Processing payment")  # Has full context
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        log_context_data = kwargs.pop(LOG_CONTEXT_KEY, None)

        current_job = get_current_job()
        job_id = current_job.id if current_job else None

        if not log_context_data and not job_id:
            return func(*args, **kwargs)

        if log_context_data:
            ctx_dict = log_context_data.get("ctx", {})
            trace_id = log_context_data.get("trace_id")

            # new span id for job as it will be in different container/service/space.
            ctx_dict["span_id"] = str(uuid.uuid4())

            extra = ctx_dict.get("extra", {})
            if trace_id:
                extra["trace"] = {"id": trace_id}
            if job_id:
                extra["rq_job"] = {"id": job_id}
            ctx_dict["extra"] = extra

            ctx = LoggingContext(**ctx_dict)
        else:
            ctx = LoggingContext(extra={"rq_job": {"id": job_id}})

        with _isolated_structlog_contextvars():
            token = set_logging_context(ctx)
            try:
                return func(*args, **kwargs)
            finally:
                reset_logging_context(token)

    return wrapper


__all__ = ["capture_log_context", "with_log_context", "LOG_CONTEXT_KEY"]