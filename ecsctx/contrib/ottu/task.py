"""Shared ``task.*`` domain: async job lifecycle (RQ/Celery/scheduler).

Transcribed from ticket #159487 (Event catalogue, ``task`` table).
"""

from ecsctx.events.spec import EventSpec

TASK_ENQUEUED = EventSpec(
    action="task.enqueued",
    required=("labels.job", "labels.queue", "labels.job_id"),
)

TASK_STARTED = EventSpec(
    action="task.started",
    required=("labels.job", "labels.job_id", "trace.id"),
)

TASK_COMPLETED = EventSpec(
    action="task.completed",
    terminal=True,
    required=("event.outcome", "event.duration", "labels.job", "labels.job_id"),
)

TASK_CANCELLED = EventSpec(
    action="task.cancelled",
    terminal=True,
    required=("event.outcome", "labels.job_id", "labels.action"),
)

SPECS: tuple[EventSpec, ...] = (
    TASK_ENQUEUED,
    TASK_STARTED,
    TASK_COMPLETED,
    TASK_CANCELLED,
)
