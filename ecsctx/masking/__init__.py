"""Unified PII/PCI masking engine.

MaskPIIFilter is the single engine every masking path calls into:
- get_logging_config() puts it in LOGGING["filters"] for every handler it
  builds — the default path, no consumer code needed.
- install_maskers() sweeps any handler ecsctx did not build.
- ecsctx.processors.mask_sensitive_data (a structlog processor) delegates to
  it, so structlog-only pipelines that don't use get_logging_config() are
  still covered.

See ecsctx.masking.patterns for the masking rules themselves and
ecsctx.masking.exemptions for the configure_masking() path-exemption API.
"""

from ecsctx.masking.exemptions import (
    configure_masking,
    configure_masking_from_env,
    masking_is_configured,
)
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.install import install_maskers, uninstall_maskers
from ecsctx.masking.tokens import mask_by_field_type, safe_tokenize

__all__ = [
    "MaskPIIFilter",
    "install_maskers",
    "uninstall_maskers",
    "configure_masking",
    "configure_masking_from_env",
    "masking_is_configured",
    "safe_tokenize",
    "mask_by_field_type",
]
