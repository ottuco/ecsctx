"""Ottu's masking vocabulary: key names Ottu services log that are not PII
(``SAFE_KEYS``, for ``ECSCTX_MASK_SAFE_KEYS``), and the wallet tokens they
carry, masked by shape (``WALLET_RULES``, for ``ECSCTX_MASK_VALUE_RULES``).

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

An Apple Pay or Google Pay token carries the device card number and the
payment cryptogram, encrypted: Sensitive Authentication Data, the SAD label
under any key and in any text, never hashed. Which shapes those are is Ottu's
knowledge, not ecsctx's: core names none, and masks one only as a service's
value rule (``ecsctx.masking.value_rules``). ``WALLET_RULES`` are Ottu's.

A service opts in to both from its settings::

    from ecsctx.contrib.ottu.masking import SAFE_KEYS as OTTU_SAFE_KEYS, WALLET_RULES

    ECSCTX_MASK_SAFE_KEYS = [*OTTU_SAFE_KEYS, "x-script-name"]
    ECSCTX_MASK_VALUE_RULES = [*WALLET_RULES]

or from the environment:
``ECSCTX_MASK_VALUE_RULES=ecsctx.contrib.ottu.masking.WALLET_RULES``.

Nothing installs them implicitly: ``register_ottu()`` registers events, and what a
service masks stays in its own settings.
"""

from typing import Any

from ecsctx.masking.value_rules import ValueRule

SAFE_KEYS = frozenset({
    # Ottu PG API fields: a gateway's short name ("mpgs") and flags saying
    # whether a card payment needs its CVV.
    "pg_name",
    "cvv_required",
    "cvv_required_for_card_payment",
    # The saved card's gateway code, read through when the card is walked under
    # its `token` key in ottu_pg's webhook.
    "pg_code",
    # The saved card's auto-debit agreement ids, read through when the card is
    # walked under its `token` key in ottu_pg's webhook. Not card data.
    "agreements",
    # Ottu's `billing` is the fee breakdown shown on the checkout page, not an
    # address, but `billing` stays a PII container (elsewhere it holds a city
    # and a postcode). Its own keys are listed instead, so the amounts escape
    # the container: they went out tokenized on both services.
    "amount",
    "sub_total",
    "fee",
    "wallet_amount",
    "pg_amount",
    # MPGS: the acquirer's processing and response codes ("authorization" is a
    # credential word to the key rules).
    "authorizationresponse",
    # MPGS's CVV-check verdict, `response.cardSecurityCode = {"acquirerCode":
    # "M", "gatewayCode": "MATCH"}`. Under a CVV key only a listed name reads
    # through, and these name the result of the check, not the CVV.
    "acquirercode",
    "gatewaycode",
    # MPGS's acquirer references -- what a reconciliation or a chargeback is
    # fought with. A listed key keeps a reference number of up to 14 digits
    # readable: the RRN (`receipt`, 12), `posData` (13), the acquirer's
    # `merchantId` (9, which the SSN rule took for a social security number).
    "receipt",
    "rrn",
    "posdata",
    "merchantid",
    "stan",
    "trackid",
    # Payment-configuration names and statuses, in ecsctx's built-in list until
    # 0.9.0.
    "gateway_name",
    "vendor_name",
    "bank_name",
    "install_name",
    "installation_name",
    "tokenization_status",
})


# Apple Pay's PKPaymentToken `paymentData`: its `version`, and the encrypted
# `data`. Its `signature` and `header` are useless without `data`, so the whole
# object is the label, and an unrelated `paymentData` reads through.
_APPLE_PAY_VERSIONS = frozenset({"EC_v1", "RSA_v1"})
# Google Pay's payment method token: its `protocolVersion` and the
# `signedMessage` holding the encrypted payload.
_GOOGLE_PAY_VERSIONS = frozenset({"ECv1", "ECv2", "ECv2SigningOnly"})


def _is_apple_pay_token(value: Any) -> bool:
    version = value.get("version")
    return isinstance(version, str) and version in _APPLE_PAY_VERSIONS and "data" in value


def _is_google_pay_token(value: Any) -> bool:
    protocol = value.get("protocolVersion")
    return isinstance(protocol, str) and protocol in _GOOGLE_PAY_VERSIONS and "signedMessage" in value


APPLE_PAY_RULE = ValueRule("sad", _is_apple_pay_token, hints=("EC_v1", "RSA_v1"))
GOOGLE_PAY_RULE = ValueRule("sad", _is_google_pay_token, hints=("ECv1", "ECv2"))
# Found by shape, never by a key name: under `paymentData`, TAP's `token_data`,
# MPGS's `paymentToken` (a JSON string), Google Pay's `tokenizationData.token`,
# KPay's `<udf9>`, or in a message.
WALLET_RULES = (APPLE_PAY_RULE, GOOGLE_PAY_RULE)
