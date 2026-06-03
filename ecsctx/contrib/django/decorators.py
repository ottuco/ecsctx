import structlog
from ipware import get_client_ip
from rest_framework.response import Response

logger = structlog.get_logger(__name__)


def _log_user(user):
    """ECS ``user.*`` fields for an authenticated user, or ``None``.

    Emits ``user.id`` (stable identifier — int pk or SSO uuid) and ``user.name``
    (the username — ``user.name`` is the ECS field for it, see
    https://www.elastic.co/docs/reference/ecs/ecs-user). The root ``user`` block is
    not touched by ``mask_sensitive_data`` (which only scrubs headers/body/payload
    containers), so these values are logged as-is.
    """
    if not (user and getattr(user, "is_authenticated", False)):
        return None

    fields = {"id": str(user.pk)}
    name = user.get_username()
    if name:
        fields["name"] = name
    return fields


def api_logging(view_cls):
    """
    Log INBOUND request and OUTBOUND response for DRF views.

    - INBOUND: Logged in initial() with request headers, body, client IP, user agent
    - OUTBOUND: Logged in dispatch() with response status, headers, body
    - Masking/tokenization handled by mask_sensitive_data processor
    - Field explosion prevented by ES flattened type mapping
    """

    exception_status_map = {
        "ValidationError": 400,
        "ParseError": 400,
        "AuthenticationFailed": 401,
        "NotAuthenticated": 401,
        "PermissionDenied": 403,
        "DoesNotExist": 404,
        "ObjectDoesNotExist": 404,
        "MethodNotAllowed": 405,
        "Conflict": 409,
    }

    def _resolve_status_code(response, exception):
        """
        Determine the most accurate HTTP status code.
        """
        if response is not None:
            return response.status_code

        if exception is not None:
            if hasattr(exception, "status_code"):
                return exception.status_code

            exc_name = exception.__class__.__name__
            if exc_name in exception_status_map:
                return exception_status_map[exc_name]
        return 500

    class LoggedView(view_cls):
        def initial(self, request, *args, **kwargs):
            if request.method == "OPTIONS":
                return super().initial(request, *args, **kwargs)

            client_ip, _ = get_client_ip(request)
            user_agent = request.META.get("HTTP_USER_AGENT", "")

            # Log INBOUND
            log_kwargs = {
                "view": view_cls.__name__,
                "ecs_event": {
                    "kind": "event",
                    "category": ["web"],
                    "type": ["access"],
                },
                "http": {
                    "request": {
                        "method": request.method,
                        "headers": dict(request.headers),
                        "body": request.data if request.data else None,
                    }
                },
                "url": {"path": request.path},
            }
            if client_ip:
                log_kwargs["client"] = {"ip": str(client_ip)}
            if user_agent:
                log_kwargs["user_agent"] = {"original": user_agent}

            # `request.user` triggers DRF's lazy authentication, which can raise
            # (AuthenticationFailed) before super().initial() handles it — guard so
            # logging never alters request handling.
            try:
                user = request.user
            except Exception:
                user = None
            if fields := _log_user(user):
                log_kwargs["user"] = fields

            logger.info("INBOUND %s %s", request.method, request.path, **log_kwargs)
            return super().initial(request, *args, **kwargs)

        def dispatch(self, request, *args, **kwargs):
            if request.method == "OPTIONS":
                return super().dispatch(request, *args, **kwargs)

            response = None
            exc = None

            try:
                response = super().dispatch(request, *args, **kwargs)
            except Exception as e:
                exc = e
                raise
            finally:
                # This block runs regardless of whether the view succeeded or crashed
                exception_type = exc.__class__.__name__ if exc else None
                status_code = _resolve_status_code(response, exc)
                self._log_outbound(request, response, status_code, exception_type)

            return response

        def _log_outbound(self, request, response, status_code, exception_type=None):
            # Extract response details safely
            response_headers = (
                dict(response.items())
                if response and hasattr(response, "items")
                else {}
            )

            response_body = None
            if response and isinstance(response, Response) and hasattr(response, "data"):
                response_body = response.data
                # Exclude specific keys to protect PII or avoid huge blobs
                ignore_keys = getattr(self, "logging_ignore_response_keys", None)
                if ignore_keys and isinstance(response_body, dict):
                    response_body = {
                        k: v
                        for k, v in response_body.items()
                        if k not in ignore_keys
                    }

            log_payload = {
                "view": view_cls.__name__,
                "ecs_event": {
                    "kind": "event",
                    "category": ["web"],
                    "type": ["access"],
                    "outcome": "success" if status_code < 400 else "failure",
                },
                "http": {
                    "request": {"method": request.method},
                    "response": {
                        "status_code": status_code,
                        "headers": response_headers,
                        "body": response_body,
                    },
                },
                "url": {"path": request.path},
            }

            if exception_type:
                log_payload["error"] = {"type": exception_type}

            # Use the DRF request (self.request), whose `.user` is set by
            # authentication during dispatch — the raw Django `request.user` is not
            # updated for token/JWT auth.
            user = getattr(getattr(self, "request", None), "user", None)
            if fields := _log_user(user):
                log_payload["user"] = fields

            log_level = logger.info if status_code < 400 else logger.warning
            if status_code >= 500:
                log_level = logger.error

            log_level(
                "OUTBOUND %s %s (%s)",
                request.method,
                request.path,
                status_code,
                **log_payload,
            )

    LoggedView.__name__ = view_cls.__name__
    LoggedView.__module__ = view_cls.__module__
    LoggedView.__doc__ = view_cls.__doc__
    return LoggedView
