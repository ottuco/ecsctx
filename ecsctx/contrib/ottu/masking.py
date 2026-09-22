"""Key names Ottu services log that are not PII, for ``ECSCTX_MASK_SAFE_KEYS``.

ecsctx's own safe keys hold only names that mean the same in every service. These
are Ottu's vocabulary, where a generic key rule would mask a value that is not
personal or card data — "cvv" in ``cvv_required``.

Most of this list is redundant as of 0.13.0: the key rules stopped claiming
every ``*_name`` as a person and every name containing "token" as a credential,
so ``pg_name``, ``gateway_name``, ``vendor_name``, ``bank_name``,
``install_name``, ``installation_name``, ``tokenization_status`` and
``authorizationresponse`` all read through without being listed. They are kept
so a service pinned to an older ecsctx keeps working, and because listing a key
that is already safe costs nothing.

A service opts in from its settings::

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
    # MPGS: the acquirer's processing and response codes ("authorization" is a
    # credential word to the key rules).
    "authorizationresponse",
    # Payment-configuration names and statuses, in ecsctx's built-in list until
    # 0.9.0.
    "gateway_name",
    "vendor_name",
    "bank_name",
    "install_name",
    "installation_name",
    "tokenization_status",
})
