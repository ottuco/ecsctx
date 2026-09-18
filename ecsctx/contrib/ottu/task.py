"""Shared ``task.*`` domain: async job lifecycle (RQ/Celery/scheduler).

Transcribed from ticket #159487 (Event catalogue, ``task`` table).
"""

from ecsctx.events.spec import EventSpec

TASK_ENQUEUED = EventSpec(
    action="task.enqueued",
    category=("process",),
    type=("info",),
    required=("labels.job", "labels.queue"),
)

TASK_STARTED = EventSpec(
    action="task.started",
    category=("process",),
    type=("info",),
    required=("labels.job", "labels.queue", "trace.id"),
)

TASK_COMPLETED = EventSpec(
    action="task.completed",
    terminal=True,
    category=("process",),
    type=("info",),
    required=("event.outcome", "event.duration", "labels.job", "labels.queue"),
)

TASK_CANCELLED = EventSpec(
    action="task.cancelled",
    terminal=True,
    category=("process",),
    type=("info",),
    reasons=("not_scheduled",),
    required=("event.outcome", "labels.queue"),
)

SPECS: tuple[EventSpec, ...] = (
    TASK_ENQUEUED,
    TASK_STARTED,
    TASK_COMPLETED,
    TASK_CANCELLED,
)
