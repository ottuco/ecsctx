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
