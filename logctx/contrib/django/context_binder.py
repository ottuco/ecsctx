from typing import Any

from auditlog.models import LogEntry
from cid.locals import get_cid
from django.core.exceptions import ObjectDoesNotExist
import structlog

from logctx.processors import _tokenize


class LogContextBinder:
    def __init__(self, log_entry: LogEntry):
        self.log_entry = log_entry

    def get_model_instance(self):
        model_class = self.log_entry.content_type.model_class()
        if not model_class:
            raise ValueError("Model class could not be resolved.")
        return model_class.objects.get(pk=self.log_entry.object_pk)

    def resolve_source_instance(self, instance):
        """
        Determine if the fields should be extracted from the instance itself,
        or a nested related object (e.g., attempt.transaction).
        """
        if instance.__class__.__name__ == "PaymentAttempt":
            return getattr(instance, "transaction", instance)
        return instance

    def extract_context(self, source) -> dict[str, Any]:
        """Extract and structure context data for logging with proper ECS namespaces."""
        context: dict[str, Any] = {"trace_id": get_cid()}

        # Payment namespace: order_no
        payment: dict[str, Any] = {}
        if order_no := getattr(source, "order_no", None):
            payment["order_no"] = order_no
        if payment:
            context["payment"] = payment

        # Customer namespace: email, phone, id, image
        customer: dict[str, Any] = {}

        # ID: Never masked
        if customer_id := getattr(source, "customer_id", None):
            customer["id"] = customer_id

        # PII: Pre-mask to avoid triple-processing cost

        if email := getattr(source, "customer_email", None):
            customer["email"] = _tokenize(email)

        if phone := getattr(source, "customer_phone", None):
            customer["phone"] = _tokenize(phone)

        if image := getattr(source, "customer_image", None):
            customer["image"] = image

        if customer:
            context["customer"] = customer

        # Actor at root level
        if actor := getattr(source, "actor", None):
            context["actor"] = actor

        return context

    def bind_context(self):
        try:
            instance = self.get_model_instance()
            source = self.resolve_source_instance(instance)
            context = self.extract_context(source)
            structlog.contextvars.bind_contextvars(**context)
        except (
            ValueError,
            AttributeError,
            LogEntry.DoesNotExist,
            ObjectDoesNotExist,
        ) as e:
            structlog.contextvars.bind_contextvars(log_bind_error=str(e))