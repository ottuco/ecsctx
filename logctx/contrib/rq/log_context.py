"""
RQ context propagation utilities.

This module provides decorators and helpers to propagate logging context
from web requests to RQ background jobs.
"""

from dataclasses import asdict
from functools import wraps

from rq import get_current_job

from logctx.context import (
    LoggingContext,
    get_logging_context,
    get_trace_id,
    reset_logging_context,
    set_logging_context,
)


# Reserved kwarg for passing full log context to RQ jobs
LOG_CONTEXT_KEY = "_rq_log_context"


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

        if log_context_data:
            ctx_dict = log_context_data.get("ctx", {})
            trace_id = log_context_data.get("trace_id")

            extra = ctx_dict.get("extra", {})
            if trace_id:
                extra["trace"] = {"id": trace_id}
            if job_id:
                extra["rq_job"] = {"id": job_id}
            ctx_dict["extra"] = extra

            ctx = LoggingContext(**ctx_dict)
            token = set_logging_context(ctx)
            try:
                return func(*args, **kwargs)
            finally:
                reset_logging_context(token)

        if job_id:
            ctx = LoggingContext(extra={"rq_job": {"id": job_id}})
            token = set_logging_context(ctx)
            try:
                return func(*args, **kwargs)
            finally:
                reset_logging_context(token)

        return func(*args, **kwargs)
    return wrapper


__all__ = ["capture_log_context", "with_log_context", "_LOG_CONTEXT_KEY"]