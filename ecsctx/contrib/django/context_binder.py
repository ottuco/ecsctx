from typing import Any

import structlog
from django.core.exceptions import ObjectDoesNotExist


class LogContextBinder:
    """Generic auditlog ``LogEntry`` -> structlog contextvars bridge.

    Resolves the audited model instance from a ``LogEntry`` and binds the result
    of :meth:`extract_context` onto structlog's contextvars. The base extracts
    **nothing** and is intentionally domain-free:

    - No hardcoded fields — override :meth:`extract_context` in your integration
      to map your own model onto log fields (session id, order no, customer, …).
    - No ``auditlog`` import — operates on the duck-typed ``log_entry`` passed in,
      so importing ecsctx never forces the ``auditlog`` dependency on consumers.

    Example::

        class MyBinder(LogContextBinder):
            def extract_context(self, source):
                ctx = {}
                if sid := getattr(source, "session_id", None):
                    ctx["session_id"] = sid
                return ctx
    """

    def __init__(self, log_entry: Any):
        self.log_entry = log_entry

    def get_model_instance(self):
        model_class = self.log_entry.content_type.model_class()
        if not model_class:
            raise ValueError("Model class could not be resolved.")
        return model_class.objects.get(pk=self.log_entry.object_pk)

    def resolve_source_instance(self, instance):
        """Return the instance to extract fields from.

        Override to redirect to a related object (e.g. ``attempt.transaction``).
        The base returns the instance unchanged.
        """
        return instance

    def extract_context(self, source) -> dict[str, Any]:
        """Return a dict of context values to bind onto structlog.

        Override per integration to map your domain model onto log fields. The
        base binds nothing.
        """
        return {}

    def bind_context(self):
        try:
            instance = self.get_model_instance()
            source = self.resolve_source_instance(instance)
            context = self.extract_context(source)
            if context:
                structlog.contextvars.bind_contextvars(**context)
        except (ValueError, AttributeError, ObjectDoesNotExist) as e:
            # LogEntry.DoesNotExist is an ObjectDoesNotExist subclass, so this
            # covers a missing audited row without importing auditlog.
            structlog.contextvars.bind_contextvars(log_bind_error=str(e))
