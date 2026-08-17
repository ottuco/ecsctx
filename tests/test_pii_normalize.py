"""Tests for ecsctx.pii.normalize — input normalization for deterministic
tokenization.

The same business value must always produce the same token regardless of
formatting, so these functions run on every value before it is hashed.
"""

import pytest

from ecsctx.masking.tokens import safe_tokenize
from ecsctx.pii import configure_pii
from ecsctx.pii.normalize import (
    normalize_email,
    normalize_phone,
    normalize_value,
    strip_wrapping_quotes,
)


class TestStripWrappingQuotes:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ('"user@example.com"', "user@example.com"),
            ("'user@example.com'", "user@example.com"),
            ("plain", "plain"),
            ("", ""),
        ],
    )
    def test_matching_pair_is_stripped(self, value, expected):
        assert strip_wrapping_quotes(value) == expected

    def test_only_one_layer_stripped(self):
        assert strip_wrapping_quotes('""a@b.com""') == '"a@b.com"'

    def test_mismatched_quote_chars_left_alone(self):
        assert strip_wrapping_quotes("\"a@b.com'") == "\"a@b.com'"

    def test_apostrophe_inside_value_survives(self):
        """O'Brien must not lose characters — only a matching pair at both
        ends counts as wrapping punctuation."""
        assert strip_wrapping_quotes("O'Brien") == "O'Brien"

    def test_single_quote_char_is_not_a_pair(self):
        assert strip_wrapping_quotes('"') == '"'


class TestNormalizeEmail:
    def test_lowercased(self):
        assert normalize_email("User@Example.COM") == "user@example.com"

    def test_already_lower_unchanged(self):
        assert normalize_email("user@example.com") == "user@example.com"


class TestNormalizePhone:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("123-456-7890", "1234567890"),
            ("123.456.7890", "1234567890"),
            ("(123) 456 7890", "1234567890"),
            ("+965 1234 5678", "+96512345678"),
            ("+965-1234-5678", "+96512345678"),
        ],
    )
    def test_separators_stripped_leading_plus_kept(self, value, expected):
        assert normalize_phone(value) == expected

    def test_same_number_different_formatting_normalizes_equal(self):
        """The whole point: one business value, one token."""
        assert normalize_phone("123-456-7890") == normalize_phone("(123) 456.7890")


class TestNormalizeValue:
    def test_strips_whitespace_then_quotes_then_whitespace_again(self):
        """Quote-stripping runs between two strips, so padding outside AND
        inside the quotes is removed (the fix in this module)."""
        assert normalize_value('   "   User@Ex.COM   "   ', "email") == "user@ex.com"

    def test_padded_and_bare_normalize_equal(self):
        assert normalize_value("  user@ex.com  ", "email") == normalize_value(
            "user@ex.com", "email"
        )

    def test_quoted_and_bare_normalize_equal(self):
        assert normalize_value('"user@ex.com"', "email") == normalize_value(
            "user@ex.com", "email"
        )

    def test_dispatches_to_phone_normalizer(self):
        assert normalize_value(' "+965 1234 5678" ', "phone") == "+96512345678"

    def test_unknown_field_type_strips_only(self):
        """No type-specific normalizer: outer whitespace goes, case and
        inner spacing are preserved."""
        assert normalize_value("  Some Value  ", "generic") == "Some Value"


class TestNormalizationAppliedDuringTokenization:
    """The payoff, one layer up: normalization is actually wired into
    tokenize(), so differently-formatted spellings of one value correlate to
    the same token in Elasticsearch.

    Each case asserts a REAL token, not just equality — unconfigured PII
    makes every call return the same [PII_REDACTED] sentinel, which would
    satisfy a bare `a == b` even with normalization completely broken.
    """

    @staticmethod
    def _assert_same_token(variant, canonical, field_type):
        got = safe_tokenize(variant, field_type)
        expected = safe_tokenize(canonical, field_type)
        assert got.startswith("ptok:v1:"), f"not a real token: {got!r}"
        assert got == expected

    @pytest.mark.parametrize(
        "variant",
        [
            '"user@example.com"',
            "  user@example.com   ",
            '  "user@example.com"   ',
            '   "   user@example.com   "   ',
            "User@Example.COM",
        ],
        ids=["quoted", "padded", "padded-quoted", "padded-inside-quotes", "mixed-case"],
    )
    def test_email_variants_produce_the_canonical_token(self, variant, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        self._assert_same_token(variant, "user@example.com", "email")

    @pytest.mark.parametrize(
        "variant", ["(123) 456.7890", "123 456 7890", "  123-456-7890  "]
    )
    def test_phone_variants_produce_the_canonical_token(self, variant, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        self._assert_same_token(variant, "123-456-7890", "phone")

    def test_genuinely_different_values_do_not_collide(self, token_keyset_path):
        """Guards the other direction — normalization must not flatten two
        distinct people into one token."""
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        assert safe_tokenize("alice@example.com", "email") != safe_tokenize(
            "bob@example.com", "email"
        )
