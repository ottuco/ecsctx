"""
Django-specific processor wrappers that read configuration from Django settings.

These are pre-configured versions of the framework-agnostic processors
from logctx.processors, using Django settings for configuration.
"""

from django.conf import settings

from logctx.processors import make_contextvars_injector

# Pre-configured processor using Django settings
contextvars_injector = make_contextvars_injector(
    merchant_id=getattr(settings, "MERCHANT_ID", None),
)