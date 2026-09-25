"""Credential key names the classifier did not know.

Each of these reached a log in clear with every pack on (verified against
0.13.0): the WSGI spelling of the Authorization header, a proxy's, cookies (a
session id is a credential), the plural `api_keys`, key compounds beyond the
original stems, `passphrase`/`passcode`/`pwd`, and MIGS's `vpc_AccessCode` --
the merchant access code, a live gateway credential.

The existing rule stands: the credential word must END the key, so
`authorizationCode` (the acquirer's approval code) and `cookie_consent` stay
readable.
"""

import pytest

from ecsctx.masking.patterns import ALL_PACKS, classify_key


def classify(key):
    return classify_key(key, ALL_PACKS)


@pytest.mark.parametrize(
    "key",
    [
        "HTTP_AUTHORIZATION",
        "Proxy-Authorization",
        "Cookie",
        "cookies",
        "Set-Cookie",
        "HTTP_COOKIE",
        "session_cookie",
        "api_keys",
        "hmac_key",
        "aes_key",
        "merchant_key",
        "shared_key",
        "passphrase",
        "passcode",
        "pwd",
        "vpc_AccessCode",
        "access_code",
    ],
)
def test_is_a_credential(key):
    assert classify(key) == "secret"


@pytest.mark.parametrize(
    "key",
    ["authorizationCode", "authorizationResponse", "cookie_consent", "cookie_policy", "cache_key", "sort_key"],
)
def test_a_name_about_one_is_not(key):
    assert classify(key) != "secret"


@pytest.mark.parametrize(
    "key",
    [
        # A key size, mode or algorithm between the stem and `key`. MPGS's
        # per-session `aes256Key` -- it decrypts the 3DS callback's
        # encryptedData -- reached Connect's and ottu_pg's logs in clear on 0.15.0.
        "aes256Key",
        "AES256_KEY",
        "aes_256_key",
        "aes128Key",
        "aesGcmKey",
        "hmacSha256Key",
        "hmac_sha256_key",
        "3desKey",
        "tripleDesKey",
        "desKey",
        "rsaKey",
        "macKey",
        "encryptedKey",
        # The key written out in an encoding.
        "privateKeyPem",
        "publicKeyPem",
        "aesKeyHex",
        "aesKeyBase64",
        "secretKeyBase64",
        # Words that only ever name key material.
        "symmetricKey",
        "cipherKey",
        "cryptoKey",
        "wrappedKey",
        "rawKey",
        "keyMaterial",
        # Payment-HSM and key-wrapping keys: zone PIN/master, terminal master,
        # base derivation, initial PIN encryption, key/data encryption keys.
        "zpk",
        "ZMK",
        "terminal_tmk",
        "bdk",
        "ipek",
        "kek",
        "wrapped_dek",
    ],
)
def test_a_crypto_key_name_is_a_credential(key):
    assert classify(key) == "secret"


@pytest.mark.parametrize(
    "key",
    [
        # An id, alias or version names a key and carries none of it.
        "sessionKeyId",
        "publicKeyId",
        "apiKeyId",
        "accessKeyId",
        "encryptionKeyId",
        "keyAlias",
        "keyVersion",
        "kid",
        "dekVersion",
        # A check value verifies a key; it is meant to be compared openly.
        "tmkCheckValue",
        "kcv",
        # The short stems inside ordinary words.
        "codes_key",
        "nodes_key",
        "episodes_key",
        "trackid",
        "track_id",
        "trackId",
        # Keys that index something, not key material.
        "cache_key",
        "sort_key",
        "primary_key",
        "idempotencyKey",
        "mac_address_key",
    ],
)
def test_a_name_about_a_key_is_not_a_credential(key):
    assert classify(key) != "secret"
