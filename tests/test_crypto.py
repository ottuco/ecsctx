"""Tests for PII cryptographic primitives."""

import os

import pytest

from logctx.pii.crypto import (
    aes_protect,
    aes_reveal,
    hmac_tokenize,
    parse_penc_kid,
)


def _random_key() -> bytes:
    return os.urandom(32)


class TestHmacTokenize:
    def test_deterministic_same_inputs(self):
        key = _random_key()
        t1 = hmac_tokenize("user@example.com", key, "email", "prod")
        t2 = hmac_tokenize("user@example.com", key, "email", "prod")
        assert t1 == t2

    def test_different_values_differ(self):
        key = _random_key()
        t1 = hmac_tokenize("a@example.com", key, "email", "prod")
        t2 = hmac_tokenize("b@example.com", key, "email", "prod")
        assert t1 != t2

    def test_different_env_differ(self):
        key = _random_key()
        t1 = hmac_tokenize("user@example.com", key, "email", "prod")
        t2 = hmac_tokenize("user@example.com", key, "email", "dev")
        assert t1 != t2

    def test_different_field_type_differ(self):
        key = _random_key()
        t1 = hmac_tokenize("value", key, "email", "prod")
        t2 = hmac_tokenize("value", key, "phone", "prod")
        assert t1 != t2

    def test_output_format(self):
        key = _random_key()
        result = hmac_tokenize("test", key, "email", "prod")
        assert result.startswith("ptok:v1:")


class TestAesProtectReveal:
    def test_roundtrip(self):
        key = _random_key()
        plaintext = "user@example.com"
        ct = aes_protect(plaintext, key, "email", "prod", kid="rk1")
        result = aes_reveal(ct, key, "email", "prod")
        assert result == plaintext

    def test_different_ciphertexts_each_call(self):
        key = _random_key()
        ct1 = aes_protect("same", key, "email", "prod", kid="rk1")
        ct2 = aes_protect("same", key, "email", "prod", kid="rk1")
        assert ct1 != ct2

    def test_output_format(self):
        key = _random_key()
        ct = aes_protect("test", key, "email", "prod", kid="mykey")
        assert ct.startswith("penc:v1:mykey:")

    def test_kid_extraction(self):
        key = _random_key()
        ct = aes_protect("test", key, "email", "prod", kid="rk1")
        assert parse_penc_kid(ct) == "rk1"


class TestParsePencKid:
    def test_valid(self):
        assert parse_penc_kid("penc:v1:kid123:payload") == "kid123"

    def test_invalid_prefix(self):
        with pytest.raises(ValueError):
            parse_penc_kid("invalid:v1:kid:payload")

    def test_too_few_parts(self):
        with pytest.raises(ValueError):
            parse_penc_kid("penc:v1")
