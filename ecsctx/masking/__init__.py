"""Unified PII/PCI masking engine.

MaskPIIFilter is the single engine every masking path calls into:
- get_logging_config() puts it on every handler it builds: it masks the
  record in place, before anything else reads it.
- ecsctx.processors.mask_sensitive_data (a structlog processor) delegates to
  it in the formatter chain; that second pass skips strings already known
  clean, so it costs little.
- install_maskers() sweeps any live handler ecsctx did not build.

See ecsctx.masking.patterns for the rules and packs, ecsctx.masking.config
for choosing packs (configure_masking_packs, ECSCTX_MASKING_PACKS), a
service's own safe key names (configure_masking_safe_keys,
ECSCTX_MASK_SAFE_KEYS), its value rules (configure_masking_value_rules,
ECSCTX_MASK_VALUE_RULES; ecsctx.masking.value_rules: ValueRule labels a
shape, KeepRule ships it as sent) and skip paths, and
ecsctx.masking.exemptions for the configure_masking() path-exemption API.
"""

from ecsctx.masking.config import (
    configure_masking_packs,
    configure_masking_safe_keys,
    configure_masking_value_rules,
    get_masking_packs,
    get_masking_safe_keys,
    get_masking_value_rules,
    key_field_type,
)
from ecsctx.masking.exemptions import (
    configure_masking,
    configure_masking_from_env,
    masking_is_configured,
)
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.install import install_maskers, uninstall_maskers
from ecsctx.masking.patterns import ALL_PACKS, PACK_NAMES, mask_card_value, mask_secret
from ecsctx.masking.tokens import mask_by_field_type, safe_tokenize
from ecsctx.masking.value_rules import KeepRule, ValueRule

__all__ = [
    "ALL_PACKS",
    "PACK_NAMES",
    "configure_masking_packs",
    "get_masking_packs",
    "configure_masking_safe_keys",
    "get_masking_safe_keys",
    "configure_masking_value_rules",
    "get_masking_value_rules",
    "ValueRule",
    "KeepRule",
    "MaskPIIFilter",
    "install_maskers",
    "uninstall_maskers",
    "configure_masking",
    "configure_masking_from_env",
    "masking_is_configured",
    "safe_tokenize",
    "mask_by_field_type",
    "mask_card_value",
    "mask_secret",
    "key_field_type",
]
