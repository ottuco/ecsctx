"""
Celery context propagation utilities.

Propagates ecsctx's LoggingContext across Celery task boundaries using signals.
When a task is published, the current logging context is captured into the task
headers. When a worker executes the task, the context is restored so all logs
within the task include the original request's trace_id, session_id, etc.

Signal-based: no decorators needed on task functions. Just call
``install_celery_hooks()`` once during Celery app setup.

Usage:
    # In your celery app config (e.g., config/celery.py):
    from ecsctx.contrib.celery import install_celery_hooks
    install_celery_hooks()
"""

import uuid
from dataclasses import asdict

from celery import signals

from ecsctx.context import (
    LoggingContext,
    get_logging_context,
    get_trace_id,
    reset_logging_context,
    set_logging_context,
)

LOG_CONTEXT_KEY = "_celery_log_context"


def capture_log_context() -> dict | None:
    """Capture current logging context + trace_id for Celery task propagation.

    Returns a serializable dict containing the full LoggingContext and trace_id,
    or None if no meaningful context exists.

    This is called automatically by the ``before_task_publish`` signal handler,
    but can also be used manually for custom propagation scenarios.
    """
    ctx = get_logging_context()
    trace_id = get_trace_id()

    if not trace_id and ctx == LoggingContext():
        return None

    return {
        "ctx": asdict(ctx),
        "trace_id": trace_id,
    }


def _capture_context_on_publish(headers=None, **kwargs):
    """Capture logging context into task headers before publishing."""
    if headers is None:
        return
    log_context = capture_log_context()
    if log_context:
        headers[LOG_CONTEXT_KEY] = log_context


def _restore_context_on_prerun(task=None, **kwargs):
    """Restore logging context from task headers when worker starts task."""
    if task is None:
        return

    log_context_data = getattr(task.request, LOG_CONTEXT_KEY, None)
    if not log_context_data:
        return

    ctx_dict = log_context_data.get("ctx", {})
    trace_id = log_context_data.get("trace_id")

    # Generate new span_id for the task (runs in a different process/container).
    ctx_dict["span_id"] = str(uuid.uuid4())

    extra = ctx_dict.get("extra", {})
    if trace_id:
        extra["trace"] = {"id": trace_id}
    extra["celery_task"] = {"id": task.request.id, "name": task.name}
    ctx_dict["extra"] = extra

    ctx = LoggingContext(**ctx_dict)
    token = set_logging_context(ctx)
    task._log_context_token = token


def _cleanup_context_on_postrun(task=None, **kwargs):
    """Reset logging context after task completes to prevent context leakage."""
    if task is None:
        return
    token = getattr(task, "_log_context_token", None)
    if token is not None:
        reset_logging_context(token)


def install_celery_hooks():
    """Connect Celery signal handlers for logging context propagation.

    Call this once during Celery app setup (e.g., in ``config/celery.py`` after
    ``app.autodiscover_tasks()``). Connecting the same handler multiple times
    is safe — Celery deduplicates signal receivers.

    Three signals are connected:

    - ``before_task_publish``: Captures the current ``LoggingContext`` and
      ``trace_id`` into the task message headers (publisher side).
    - ``task_prerun``: Restores the ``LoggingContext`` from headers, generates
      a new ``span_id``, and injects ``celery_task.id`` and ``celery_task.name``
      into ``extra`` (worker side).
    - ``task_postrun``: Resets the logging context to prevent leakage between
      tasks (worker side).

    Usage::

        from ecsctx.contrib.celery import install_celery_hooks
        install_celery_hooks()
    """
    signals.before_task_publish.connect(_capture_context_on_publish)
    signals.task_prerun.connect(_restore_context_on_prerun)
    signals.task_postrun.connect(_cleanup_context_on_postrun)


__all__ = ["capture_log_context", "install_celery_hooks", "LOG_CONTEXT_KEY"]
