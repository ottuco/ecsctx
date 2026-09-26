"""A truncated PAN renders bare: `450875******1019`, not `[CARD-MASKED:…]`.

The convention, from here on: **brackets mean nothing survived**. `[CVV-MASKED]`
and `[EXPIRY-MASKED]` stand where a value was destroyed, and `[EMAIL-MASKED]`
where no token could be made. Where something real is carried — a token, or a
PAN's BIN and last four — it is carried bare, with nothing wrapped around it.

Dropping the wrapper is not cosmetic. The marker's own text was doing three
jobs, and each one needs a replacement that does not depend on it:

1. `already_masked()` recognised a masked value by the literal `-MASKED:` /
   `-MASKED]`, keeping a re-passed value from being masked a second time;
2. `mask_card_value` recognised its own output via `_SINGLE_MARKER`;
3. `_text_has_card_context` — added in this same release to stop the
   standalone-CVV rule eating response codes — read the word "CARD" out of the
   marker. Once the card rule fires the digit run is gone, so the marker was the
   only card context left in the text. Miss this one and a CVV beside a masked
   PAN silently stops being masked, which is a PCI leak, not a regression in
   formatting.
"""

import pytest

from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS, mask_by_all_patterns, mask_card_value
from ecsctx.pii import configure_pii

PAN = "4508750000001019"
TRUNCATED = "450875******1019"


@pytest.fixture
def mask():
    f = MaskPIIFilter(packs=ALL_PACKS)
    return f._mask_value


class TestTheTruncationIsCarriedBare:
    def test_a_pan_under_a_card_key(self, mask):
        assert mask({"card_number": PAN}) == {"card_number": TRUNCATED}

    def test_a_pan_bare_in_a_field_value(self, mask):
        assert mask({"note": PAN}) == {"note": TRUNCATED}

    def test_a_pan_in_prose(self):
        assert mask_by_all_patterns(f"charged card {PAN} today") == (
            f"charged card {TRUNCATED} today"
        )

    def test_the_bin_and_last_four_are_all_that_survive(self, mask):
        out = mask({"card_number": PAN})["card_number"]
        assert out.startswith("450875")
        assert out.endswith("1019")
        assert PAN not in out
        assert "0000000" not in out


class TestBracketsStillMeanNothingSurvived:
    def test_a_cvv_keeps_its_label(self, mask):
        assert mask({"cvv": "123"}) == {"cvv": "[CVV-MASKED]"}

    def test_a_card_object_with_no_pan_keeps_what_is_not_sensitive(self, mask):
        """Walked since 0.13.0, so the label no longer stands for the whole
        object. `holder` is the cardholder's name and is masked as one; `scheme`
        is not cardholder data and reads through."""
        assert mask({"card": {"holder": "Far", "scheme": "visa"}}) == {
            "card": {"holder": "[NAME-MASKED]", "scheme": "visa"}
        }

    def test_a_card_key_holding_a_value_with_no_digits_at_all(self, mask):
        """Not a label any more -- see TestACardKeyShowsWhatIsNotAPan. A value
        with nothing card-shaped in it is what someone is debugging with."""
        assert mask({"card_number": "not-a-number"}) == {"card_number": "not-a-number"}


class TestReMaskingLeavesItAlone:
    """The same document is masked more than once — the structlog processor, the
    Sentry integration's own pass, and the handler filter."""

    def test_under_a_card_key_the_last_four_survive(self, mask):
        assert mask({"card_number": TRUNCATED}) == {"card_number": TRUNCATED}

    def test_under_any_other_key_it_is_not_tokenized(self, mask):
        """Otherwise it becomes a token of the partially-masked text, which
        correlates with nothing and loses the last four."""
        assert mask({"customer_ref": TRUNCATED}) == {"customer_ref": TRUNCATED}

    def test_in_prose_it_is_a_fixed_point(self):
        assert mask_by_all_patterns(TRUNCATED) == TRUNCATED
        assert mask_by_all_patterns(f"card {TRUNCATED} ok") == f"card {TRUNCATED} ok"

    def test_masking_twice_is_the_same_as_masking_once(self, mask):
        once = mask({"card_number": PAN, "note": f"paid with {PAN}"})
        assert mask(once) == once

    def test_a_full_pan_dressed_as_a_truncation_is_still_masked(self):
        """The shape is the marker now, so the shape has to be checked, not
        merely believed."""
        assert mask_card_value("450875******1019") == TRUNCATED
        assert mask_card_value(PAN) == TRUNCATED
        assert "4508750000001019" not in mask_card_value(f"[CARD-MASKED:{PAN}]")


class TestAValueAlreadyTruncatedUpstreamPassesThrough:
    """The surface this change widens, pinned deliberately rather than left to
    chance: with no wrapper, the shape is the marker, so a value an upstream
    system already truncated is read as masked and passed through.

    That is safe by construction, not by luck. The shape allows at most six
    leading digits and four trailing ones -- first 6 + last 4, which is exactly
    the most PCI DSS 3.5.1 permits anyone to keep -- with four or more stars
    between them. A string of this shape cannot carry a full PAN.

    And passing it through is better than the alternative: tokenizing it would
    produce a token of a partially-masked string, which correlates with nothing
    and loses the last four. That is the same reasoning as the re-masking case
    above; an upstream's truncation is no different from our own.
    """

    @pytest.mark.parametrize(
        "value", ["123456****7890", "999999****9999", "*********9301"]
    )
    def test_under_a_card_key(self, mask, value):
        assert mask({"card_number": value}) == {"card_number": value}

    @pytest.mark.parametrize("value", ["123456****7890", "999999****9999"])
    def test_under_a_tokenizable_key(self, mask, value):
        assert mask({"account_ref": value}) == {"account_ref": value}

    def test_a_full_pan_is_not_the_shape(self, mask):
        """Sixteen contiguous digits is a PAN whatever key it sits under."""
        assert mask({"account_ref": PAN}) == {"account_ref": TRUNCATED}
        assert mask({"card_number": PAN}) == {"card_number": TRUNCATED}

    @pytest.mark.parametrize("value", ["4508750**0001019", "45087500**01019"])
    def test_a_card_key_still_refuses_anything_off_the_shape(self, mask, value):
        """The pass-through is narrow. `4508750**0001019` keeps 14 of 16
        digits, well past what PCI DSS 3.5.1 allows, and no contiguous run for
        the card rule to catch -- so a card key refuses it outright."""
        assert mask({"card_number": value}) == {"card_number": "[CARD-MASKED]"}

    def test_a_short_partial_is_shown(self, mask):
        """`450875******101` is nine digits -- fewer than the twelve a PAN
        needs, and under the ten PCI DSS 3.5.1 permits keeping."""
        assert mask({"card_number": "450875******101"}) == {
            "card_number": "450875******101"
        }


class TestTheCvvBesideAMaskedPanStillMasks:
    """The leak this change opens if `_text_has_card_context` is not taught the
    bare shape. Rule 15 runs before rule 17, so by the time the CVV rule looks
    at the text the PAN is already truncated and `_CARD_SHAPE` no longer
    matches — the truncation itself is the only card context left.
    """

    def test_a_cvv_after_a_pan_in_one_string(self):
        # A word between them on purpose: "<pan> 123" is itself a valid
        # 19-digit space-separated PAN, and the card rule claims the whole run
        # -- correct, and not what this test is about.
        out = mask_by_all_patterns(f"{PAN} ref 123")
        assert TRUNCATED in out
        assert "[CVV-MASKED]" in out

    def test_a_cvv_after_an_already_truncated_pan(self):
        """The second pass over a document the first pass already masked."""
        out = mask_by_all_patterns(f"{TRUNCATED} ref 123")
        assert "[CVV-MASKED]" in out

    def test_a_status_code_with_no_card_anywhere_still_survives(self):
        """The other half of the same precondition, which must not regress."""
        assert mask_by_all_patterns("Response status: 400") == "Response status: 400"


class TestAnEmptyValueStaysEmpty:
    """`[ADDRESS-MASKED]` on an empty string reads as though something was
    hidden. Nothing was there — the same reason a null stays null."""

    def test_an_empty_string_under_a_pii_key(self, mask):
        assert mask({"customer_address_line1": ""}) == {"customer_address_line1": ""}

    def test_an_empty_string_under_a_card_key(self, mask):
        assert mask({"card_number": ""}) == {"card_number": ""}

    def test_a_null_still_stays_null(self, mask):
        assert mask({"email": None}) == {"email": None}


class TestExpiryIsReadable:
    """Expiry is Cardholder Data, not Sensitive Authentication Data.

    PCI DSS requires the PAN to be rendered unreadable and forbids storing SAD
    (CVV, full track, PIN) at all. Expiry is neither: it may be stored with
    protection, and these logs already sit in a restricted stream. Masking it
    cost the one thing worth reading -- an expired-card decline -- and
    `expiry_month: "01"` is twelve possible values.
    """

    @pytest.mark.parametrize(
        "key", ["expiry_month", "expiry_year", "expiry", "expiration_date", "exp_month", "card_expiry"]
    )
    def test_an_expiry_key_keeps_its_value(self, mask, key):
        assert mask({key: "01"}) == {key: "01"}

    def test_a_cvv_is_still_masked(self, mask):
        """The half that is not optional."""
        assert mask({"cvv": "123", "cvc": "456", "security_code": "789"}) == {
            "cvv": "[CVV-MASKED]",
            "cvc": "[CVV-MASKED]",
            "security_code": "[CVV-MASKED]",
        }

    def test_an_expiry_inside_a_pii_container_survives(self, mask):
        """Unclassifying the key was not enough on its own: inside a `payer` or
        `customer` object an unclassified key is masked as the container's
        type, so month and year came out [NAME-MASKED] -- less readable than
        the label they replaced. Expiry is a safe key now, so it escapes."""
        assert mask({"payer_details": {"expiry": {"month": "1", "year": "28"}}}) == {
            "payer_details": {"expiry": {"month": "1", "year": "28"}}
        }

    def test_a_name_beside_it_in_the_same_container_is_still_masked(self, mask):
        """The container sweep still works; expiry is the exception, not a hole."""
        out = mask({"payer_details": {"expiry": "12/28", "first_name": "Far"}})
        assert out["payer_details"]["expiry"] == "12/28"
        assert out["payer_details"]["first_name"] == "[NAME-MASKED]"

    def test_a_pan_pasted_into_an_expiry_field_is_still_truncated(self, mask):
        """The safe half of unclassifying the key: the value now reaches the
        content rules, and the card rule catches it there."""
        assert mask({"expiry_month": PAN}) == {"expiry_month": TRUNCATED}


class TestACardKeyShowsWhatIsNotAPan:
    """`[CARD-MASKED]` for every non-PAN value left nothing to debug with: a
    gateway token, a scheme name and an error string all looked identical."""

    @pytest.mark.parametrize(
        "value", ["not-a-number", "visa", "N/A", "tok_abc123", "null", "MISSING"]
    )
    def test_a_value_too_short_to_be_a_pan_passes_through(self, mask, value):
        """Twelve digits is the shortest PAN there is, so fewer than twelve
        cannot be one, whatever else the value contains."""
        assert mask({"card_number": value}) == {"card_number": value}

    def test_a_pan_embedded_in_a_longer_value_is_truncated_in_place(self, mask):
        assert mask({"card_number": "card 4508 7500 0000 1019 visa"}) == {
            "card_number": f"card {TRUNCATED} visa"
        }

    def test_a_clean_pan_still_truncates(self, mask):
        assert mask({"card_number": PAN}) == {"card_number": TRUNCATED}

    def test_a_card_object_is_walked_field_by_field(self, mask):
        """This relaxation used to be carved out for containers. Since 0.13.0 it
        applies to every leaf: the PAN truncates, and the holder is masked by
        its own rule rather than by the object disappearing around it."""
        assert mask({"card": {"number": PAN, "holder": "Far"}}) == {
            "card": {"number": TRUNCATED, "holder": "[NAME-MASKED]"}
        }

    def test_a_long_digit_run_that_is_not_a_pan_is_still_refused(self, mask):
        """Twelve or more digits under a card key gets content-scanned, not
        waved through: `4508750**0001019` keeps 14 of 16 digits."""
        out = mask({"card_number": "4508750**0001019"})["card_number"]
        assert out == "[CARD-MASKED]"


class TestAPanOutranksEveryOtherClassification:
    """Customers mistype the card number into the name box, and the key's own
    type used to win: the value was tokenized as a name.

    That is worse than it sounds. With a keyset configured, a document holding
    the PAN in a card key and in a name key carried a truncation AND a keyed
    hash of the same PAN -- the combination PCI DSS FAQ 1117 warns about, and
    the one `mask_card_value`'s docstring already says must never happen.

    The card path honoured that rule and every other path ignored it, so a key
    ecsctx recognised as PII came off WORSE than one it did not recognise at
    all: `holder` and `account_ref` were truncated correctly all along.
    """

    @pytest.fixture
    def mask_with_tokens(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        return MaskPIIFilter(packs=ALL_PACKS)._mask_value

    @pytest.mark.parametrize(
        "key",
        [
            "name_on_card",
            "customer_first_name",
            "cardholder_name",
            "payer_name",
            "customer_email",
            "customer_phone",
            "billing_address",
            "udf1",
            "contact",
            # `card_token` was here until 0.14.0. A credential shaped like a PAN
            # is masked whole now, never truncated: truncation showed ten digits
            # of a sixteen-digit gateway token (test_masking_credential_containers.py).
        ],
    )
    def test_a_pan_under_a_pii_key_is_truncated_not_tokenized(
        self, mask_with_tokens, key
    ):
        assert mask_with_tokens({key: PAN}) == {key: TRUNCATED}

    def test_the_faq_1117_combination_cannot_occur(self, mask_with_tokens):
        """One document, the PAN in both places, and no token of it anywhere."""
        out = mask_with_tokens(
            {"card_number": PAN, "name_on_card": PAN, "customer_email": PAN}
        )
        assert out == {
            "card_number": TRUNCATED,
            "name_on_card": TRUNCATED,
            "customer_email": TRUNCATED,
        }
        assert "ptok:" not in str(out)

    def test_a_pan_inside_a_pii_container_is_truncated(self, mask_with_tokens):
        """The `inherited` path: a leaf of a customer object, masked as the
        container's type rather than by a key of its own."""
        out = mask_with_tokens({"customer": {"first_name": PAN, "city": "Kuwait"}})
        assert out["customer"]["first_name"] == TRUNCATED

    @pytest.mark.parametrize(
        "value", [f"Jane Payer {PAN}", "4508 7500 0000 1019 Jane Payer"]
    )
    def test_a_pan_inside_a_pii_value_is_the_label_not_a_token(
        self, mask_with_tokens, value
    ):
        """Beside other text a PAN would be hashed with it, and the card rule
        cannot always tell where it ends."""
        assert mask_with_tokens({"customer_name": value}) == {
            "customer_name": "[NAME-MASKED]"
        }

    def test_a_pan_dressed_as_a_token_is_not_let_through(self, mask_with_tokens):
        """A token-shaped value is passed through as masked already, so the
        check for a PAN inside must look at it too."""
        out = mask_with_tokens({"customer_name": f"ptok:{PAN}"})
        assert out == {"customer_name": "[NAME-MASKED]"}

    @pytest.mark.parametrize(
        "phone",
        [
            "+966501234567",
            "+971 50 123 4567",
            "+201001234567",
            "+86 138 0013 8000",
            "+62 812 3456 7890",
            # 15 digits, the most E.164 allows.
            "+49 30 1234 5678 901",
        ],
    )
    def test_an_international_phone_number_still_tokenizes(
        self, mask_with_tokens, phone
    ):
        """As many digits as a PAN, but a phone number: written after "+" in a
        phone field, within the 15 digits E.164 allows."""
        out = mask_with_tokens({"customer_phone": phone})
        assert out["customer_phone"].startswith("ptok:v1:")

    @pytest.mark.parametrize(
        ("key", "value", "label"),
        [
            # Longer than E.164 allows.
            ("customer_phone", "+5123450000000008", "[PHONE-MASKED]"),
            ("customer_phone", "+9655123450000000008", "[PHONE-MASKED]"),
            # A phone number, then a PAN.
            ("customer_phone", "+96551234567 5123450000000008", "[PHONE-MASKED]"),
            ("customer_phone", "ptok:+5123450000000008", "[PHONE-MASKED]"),
            # Not written after "+", so not written as a phone number.
            ("customer_phone", "tel 378282246310005", "[PHONE-MASKED]"),
            # Outside a phone field "+" is no phone number: plus-addressing here.
            ("customer_email", "jane+5123450000000008@example.com", "[EMAIL-MASKED]"),
            ("customer_email", "jane+378282246310005@example.com", "[EMAIL-MASKED]"),
            ("customer_name", "Jane +5123450000000008", "[NAME-MASKED]"),
            (
                "card_details",
                "Mastercard Jane +5123450000000008 01/39",
                "[NAME-MASKED]",
            ),
        ],
    )
    def test_a_plus_does_not_make_a_pan_a_phone_number(
        self, mask_with_tokens, key, value, label
    ):
        assert mask_with_tokens({key: value}) == {key: label}

    def test_a_real_name_still_tokenizes(self, mask_with_tokens):
        """Not a blanket regression: only a PAN outranks the key."""
        out = mask_with_tokens({"customer_first_name": "Farhan"})
        assert out["customer_first_name"].startswith("ptok:v1:")

    def test_a_real_email_still_tokenizes(self, mask_with_tokens):
        out = mask_with_tokens({"customer_email": "far@example.com"})
        assert out["customer_email"].startswith("ptok:v1:")

    def test_without_the_pci_pack_it_does_not_fire(self, token_keyset_path):
        """It is a content-shaped test on a key-classified value, so it is
        gated like every other content rule. A service that never opted into
        PCI keeps tokenizing a 16-digit id in a name field, as it does today."""
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        out = MaskPIIFilter(packs=frozenset({"default"}))._mask_value(
            {"customer_first_name": PAN}
        )
        assert out["customer_first_name"].startswith("ptok:v1:")
