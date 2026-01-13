from enum import Enum


class Event(Enum):
    """Event types for logging context."""

    # HTTP method events
    POST = "post"
    GET = "get"
    UPDATE = "update"
    PATCH = "patch"
    DELETE = "delete"

    # PG callback events
    WEBHOOK = "webhook"
    CALLBACK = "callback"
    NOTIFICATION = "notification"

    # Outbound PG events
    PAYMENT_REQUEST = "payment_request"
    INQUIRY = "inquiry"

    # Merchant notification events
    WEBHOOK_OUTBOUND = "webhook_outbound"

    # Service provider events
    SMS_SEND = "sms_send"
    EMAIL_SEND = "email_send"
    PDF_GENERATE = "pdf_generate"

    # Background job events
    SCHEDULED_TASK = "scheduled_task"
    BACKGROUND_JOB = "background_job"


class Entity(Enum):
    """Entity types representing source/target of requests."""

    OTTU_CORE = "ottu_core"
    MERCHANT = "merchant"
    PG = "payment_gateway"
    SERVICE_PROVIDER = "service_provider"
    INTERNAL_SERVICE = "internal_service"
    SCHEDULER = "scheduler"
    ADMIN = "admin"


class RequestDirection(Enum):
    """Direction of the request flow."""

    INBOUND = "inbound"
    OUTBOUND = "outbound"


class APIType(Enum):
    """API endpoint classification."""

    PUBLIC = "public"
    PRIVATE = "private"
    INTERNAL = "internal"
    CALLBACK = "callback"
