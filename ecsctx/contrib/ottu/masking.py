"""Ottu's masking vocabulary: key names Ottu services log that are not PII
(``SAFE_KEYS``, for ``ECSCTX_MASK_SAFE_KEYS``), and the wallet tokens they
carry, found by shape (``WALLET_RULES``, for ``ECSCTX_MASK_VALUE_RULES``).

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

Wallet tokens ship in logs exactly as sent (#159487, decided 2026-10-01). An
Apple Pay or Google Pay token is single-use: it pays once, and what it carries
-- the device card number and the payment cryptogram -- is encrypted for the
payment processor. When a wallet payment fails, the token as it was sent is
what tells a wrong merchant certificate, an expired signing key or a token
altered on the way apart. So ``WALLET_RULES`` are keep rules
(``ecsctx.masking.value_rules``): a token they match is left as sent under any
key -- ``paymentData``, TAP's ``token_data``, MPGS's ``paymentToken`` (a JSON
string), Google Pay's ``tokenizationData.token``, KPay's ``<udf9>`` -- and in
a message or a body, and no rule reads into it: not a credential rule, not the
payment-id rule (its ``transactionId``), not a service's extra secret keys
(``signature``).

What stays masked:

- Saved-card tokens. A card on file is charged again with its token, so it is
  a credential: no wallet shape matches it, under ``token`` or anywhere.
- What is not exactly a wallet's shape. The matchers are strict -- an Apple
  Pay ``paymentData`` or ``PKPaymentToken``, a Google Pay payment method
  token, and no key besides the ones they write -- so anything else is walked
  as before: a ``PKPaymentToken`` with a key of its own keeps only its
  ``paymentData``.
- Card data. ecsctx keeps nothing under a CVV or SAD key, and nothing that
  holds a card, CVV or SAD key or a card number (the floor and the guard).

Samsung Pay is not here: its token is a JWE, and no captured token pins its
shape yet. A rule for any JWE would keep every JWE.

``WALLET_SAD_RULES`` are 0.16.0's: label rules that make the same tokens'
payment data ``[SAD-MASKED]``, for a service that must not log them.

A service opts in to both lists from its settings::

    from ecsctx.contrib.ottu.masking import SAFE_KEYS as OTTU_SAFE_KEYS, WALLET_RULES

    ECSCTX_MASK_SAFE_KEYS = [*OTTU_SAFE_KEYS, "x-script-name"]
    ECSCTX_MASK_VALUE_RULES = [*WALLET_RULES]

or from the environment:
``ECSCTX_MASK_VALUE_RULES=ecsctx.contrib.ottu.masking.WALLET_RULES``.

Nothing installs them implicitly: ``register_ottu()`` registers events, and what a
service masks stays in its own settings.
"""

from typing import Any

from ecsctx.masking.value_rules import KeepRule, ValueRule

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


# The versions of Apple Pay's PKPaymentToken `paymentData`.
_APPLE_PAY_VERSIONS = frozenset({"EC_v1", "RSA_v1"})
# ...and of Google Pay's payment method token.
_GOOGLE_PAY_VERSIONS = frozenset({"ECv1", "ECv2", "ECv2SigningOnly"})


# 0.16.0's label rules. `paymentData`'s `version` and the encrypted `data`:
# its `signature` and `header` are useless without `data`, so the whole object
# is the label, and an unrelated `paymentData` reads through. Google Pay's
# `protocolVersion` and the `signedMessage` holding the encrypted payload.
def _is_apple_pay_token(value: Any) -> bool:
    version = value.get("version")
    return isinstance(version, str) and version in _APPLE_PAY_VERSIONS and "data" in value


def _is_google_pay_token(value: Any) -> bool:
    protocol = value.get("protocolVersion")
    return isinstance(protocol, str) and protocol in _GOOGLE_PAY_VERSIONS and "signedMessage" in value


APPLE_PAY_RULE = ValueRule("sad", _is_apple_pay_token, hints=("EC_v1", "RSA_v1"))
GOOGLE_PAY_RULE = ValueRule("sad", _is_google_pay_token, hints=("ECv1", "ECv2"))


# The keep rules' shapes, key for key: what Apple's PKPaymentToken and Google
# Pay's payment method token are documented to hold, and nothing else. A key
# besides these is no wallet's, and the object is walked as before.
_PAYMENT_DATA_KEYS = frozenset({"version", "data", "signature", "header"})
_PAYMENT_DATA_HEADER_KEYS = frozenset(
    {"ephemeralPublicKey", "wrappedKey", "publicKeyHash", "transactionId", "applicationData"}
)
_PK_PAYMENT_TOKEN_KEYS = frozenset({"paymentData", "paymentMethod", "transactionIdentifier"})
_PAYMENT_METHOD_KEYS = frozenset({"displayName", "network", "type"})
_GOOGLE_PAY_KEYS = frozenset({"signature", "intermediateSigningKey", "protocolVersion", "signedMessage"})
_SIGNING_KEY_KEYS = frozenset({"signedKey", "signatures"})


def _text_or_absent(value: Any, key: str) -> bool:
    """A wallet's field is text where it is written: every leaf a wallet
    writes is a string, so a container or a number in a slot is no wallet's,
    and nothing can ride in it -- a `{name, value}` pair among them."""
    return key not in value or isinstance(value[key], str)


def _is_apple_pay_payment_data(value: Any) -> bool:
    """Apple Pay's `paymentData`: an EC_v1 or RSA_v1 `version`, the
    encrypted `data` and its `signature` as text, and a `header` of text
    fields."""
    version = value.get("version")
    if not (isinstance(version, str) and version in _APPLE_PAY_VERSIONS and isinstance(value.get("data"), str)):
        return False
    if not (value.keys() <= _PAYMENT_DATA_KEYS and _text_or_absent(value, "signature")):
        return False
    header = value.get("header", {})
    return (
        isinstance(header, dict)
        and header.keys() <= _PAYMENT_DATA_HEADER_KEYS
        and all(isinstance(field, str) for field in header.values())
    )


def _is_pk_payment_token(value: Any) -> bool:
    """Apple Pay's PKPaymentToken: its `paymentData`, and what the device says
    about the card -- its display name, network and type -- and the
    transaction's id, each as text."""
    payment_data = value.get("paymentData")
    if not (isinstance(payment_data, dict) and _is_apple_pay_payment_data(payment_data)):
        return False
    if not (value.keys() <= _PK_PAYMENT_TOKEN_KEYS and _text_or_absent(value, "transactionIdentifier")):
        return False
    method = value.get("paymentMethod", {})
    return (
        isinstance(method, dict)
        and method.keys() <= _PAYMENT_METHOD_KEYS
        and all(isinstance(field, str) for field in method.values())
    )


def _is_google_pay_payment_token(value: Any) -> bool:
    """Google Pay's payment method token: its `protocolVersion`, the
    `signedMessage` and its `signature` as text, and the intermediate signing
    key ECv2 signs with: a `signedKey` as text and its `signatures`, a list
    of text."""
    protocol = value.get("protocolVersion")
    if not (isinstance(protocol, str) and protocol in _GOOGLE_PAY_VERSIONS):
        return False
    if not isinstance(value.get("signedMessage"), str):
        return False
    if not (value.keys() <= _GOOGLE_PAY_KEYS and _text_or_absent(value, "signature")):
        return False
    signing_key = value.get("intermediateSigningKey", {})
    if not (isinstance(signing_key, dict) and signing_key.keys() <= _SIGNING_KEY_KEYS):
        return False
    signatures = signing_key.get("signatures", [])
    return (
        _text_or_absent(signing_key, "signedKey")
        and isinstance(signatures, list)
        and all(isinstance(signature, str) for signature in signatures)
    )


APPLE_PAY_TOKEN_KEEP_RULE = KeepRule(_is_pk_payment_token, hints=("EC_v1", "RSA_v1"))
APPLE_PAY_KEEP_RULE = KeepRule(_is_apple_pay_payment_data, hints=("EC_v1", "RSA_v1"))
GOOGLE_PAY_KEEP_RULE = KeepRule(_is_google_pay_payment_token, hints=("ECv1", "ECv2"))
# Found by shape, never by a key name: under `paymentData`, TAP's `token_data`,
# MPGS's `paymentToken` (a JSON string), Google Pay's `tokenizationData.token`,
# KPay's `<udf9>`, or in a message. The whole PKPaymentToken first, so it is
# kept whole where it is one.
WALLET_RULES = (APPLE_PAY_TOKEN_KEEP_RULE, APPLE_PAY_KEEP_RULE, GOOGLE_PAY_KEEP_RULE)
WALLET_SAD_RULES = (APPLE_PAY_RULE, GOOGLE_PAY_RULE)
