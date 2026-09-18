"""Shared ``task.*`` domain: async job lifecycle (RQ/Celery/scheduler).

Transcribed from ticket #159487 (Event catalogue, ``task`` table).
"""

from ecsctx.events.spec import EventSpec, Reason

TASK_ENQUEUED = EventSpec(
    action="task.enqueued",
    description="A background job (labels.job) was put on labels.queue.",
    category=("process",),
    type=("info",),
    required=("labels.job", "labels.queue"),
)

TASK_STARTED = EventSpec(
    action="task.started",
    description="A worker started a background job.",
    category=("process",),
    type=("info",),
    required=("labels.job", "labels.queue", "trace.id"),
)

TASK_COMPLETED = EventSpec(
    action="task.completed",
    description="A background job finished; carries the outcome and duration.",
    terminal=True,
    category=("process",),
    type=("info",),
    required=("event.outcome", "event.duration", "labels.job", "labels.queue"),
)


class TaskCancellation(Reason):
    """Why a queued task was cancelled."""

    NOT_SCHEDULED = "not_scheduled"


TASK_CANCELLED = EventSpec(
    action="task.cancelled",
    description="A queued job was cancelled before it ran.",
    terminal=True,
    category=("process",),
    type=("info",),
    reasons=TaskCancellation,
    required=("event.outcome", "labels.queue"),
)

SPECS: tuple[EventSpec, ...] = (
    TASK_ENQUEUED,
    TASK_STARTED,
    TASK_COMPLETED,
    TASK_CANCELLED,
)
