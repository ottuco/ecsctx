"""Unified PII/PCI masking engine.

MaskPIIFilter is the single engine every masking path calls into:
- ecsctx.processors.mask_sensitive_data (a structlog processor) delegates to
  it — the formatter get_logging_config() builds runs it on every record.
- get_logging_config() defines it in LOGGING["filters"] and attaches it to
  handlers whose formatter does not mask, so each record is masked once.
- install_maskers() sweeps any live handler ecsctx did not build.

See ecsctx.masking.patterns for the rules and packs, ecsctx.masking.config
for choosing packs (configure_masking_packs, ECSCTX_MASKING_PACKS) and skip
paths, and ecsctx.masking.exemptions for the configure_masking()
path-exemption API.
"""

from ecsctx.masking.config import configure_masking_packs, get_masking_packs
from ecsctx.masking.exemptions import (
    configure_masking,
    configure_masking_from_env,
    masking_is_configured,
)
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.install import install_maskers, uninstall_maskers
from ecsctx.masking.patterns import ALL_PACKS, PACK_NAMES
from ecsctx.masking.tokens import mask_by_field_type, safe_tokenize

__all__ = [
    "ALL_PACKS",
    "PACK_NAMES",
    "configure_masking_packs",
    "get_masking_packs",
    "MaskPIIFilter",
    "install_maskers",
    "uninstall_maskers",
    "configure_masking",
    "configure_masking_from_env",
    "masking_is_configured",
    "safe_tokenize",
    "mask_by_field_type",
]
