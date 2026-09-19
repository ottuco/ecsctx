"""Key names Ottu services log that are not PII, for ``ECSCTX_MASK_SAFE_KEYS``.

ecsctx's own safe keys hold only names that mean the same in every service. These
are Ottu's vocabulary, where a generic key rule would mask a value that is not
personal or card data — "name" in ``pg_name``, "cvv" in ``cvv_required``,
"token" in ``tokenization_status``. A service opts in from its settings::

    from ecsctx.contrib.ottu.masking import SAFE_KEYS as OTTU_SAFE_KEYS

    ECSCTX_MASK_SAFE_KEYS = [*OTTU_SAFE_KEYS, "x-script-name"]

Nothing installs them implicitly: ``register_ottu()`` registers events, and what a
service masks stays in its own settings.
"""

SAFE_KEYS = frozenset({
    # Ottu PG API fields: a gateway's short name ("mpgs") and flags saying
    # whether a card payment needs its CVV.
    "pg_name",
    "cvv_required",
    "cvv_required_for_card_payment",
    # Payment-configuration names and statuses, in ecsctx's built-in list until
    # 0.9.0.
    "gateway_name",
    "vendor_name",
    "bank_name",
    "install_name",
    "installation_name",
    "tokenization_status",
})
