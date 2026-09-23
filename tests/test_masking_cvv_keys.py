"""A CVV key names the value, and fails closed; a key *about* a CVV does not.

The CVV key rule was a substring search on the lowercased key, which got it
wrong both ways:

- **Over-masking.** MPGS answers with the verdict of its CVV check --
  `response.cardSecurityCode = {"acquirerCode": "M", "gatewayCode": "MATCH"}`
  and `authorizationResponse.cardSecurityCodeError = "M"` -- and both went out
  as `[CVV-MASKED]`: the first thing anyone reads on a CVV decline. So did
  `cvv_required`, a flag.
- **Leaks.** The search ran on the *lowercased* key, where `-` and `.` survive,
  so `{"security-code": "123"}` shipped in clear; `cardCode` (Authorize.Net's
  CVV field) and `verification_value` were never classified at all.

The rule is now: a CVV word anywhere in the key is a CVV, UNLESS what follows
it names something about one (`required`, `result`, `error`, `indicator`, ...).
Anything else -- `cvv_input`, `cvv_hash`, a plural -- stays masked: a new
spelling of the value must not read through because nobody listed it.

`never_safe()` asks the classifier too, so a service can no longer list a name
the classifier masks (`cvv_number` and `password_hash` were accepted).
"""

import pytest

from ecsctx.masking.config import configure_masking_safe_keys
from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.patterns import ALL_PACKS, classify_key, never_safe
from ecsctx.processors import mask_sensitive_data


def classify(key):
    return classify_key(key, ALL_PACKS)


class TestTheValueIsACvv:
    @pytest.mark.parametrize(
        "key",
        [
            "cvv",
            "CVV2",
            "cvc",
            "cardCvv",
            "card_cvv",
            "securityCode",
            "security-code",
            "security.code",
            "card_security_code",
            "cardSecurityCode",
            "cvv2Value",
            "encryptedSecurityCode",
            "cvvNumber",
            "cvv_code",
            "csc",
            # Fail closed: spellings nobody listed are still the value.
            "cvv_input",
            "cvvEntered",
            "cvc_field",
            "cvv_val",
            "cvv_hash",
            "cvvs",
            # Never classified before this rule.
            "cardCode",
            "verification_value",
            "cvd_value",
            "cvNumber",
            "cav2",
        ],
    )
    def test_is_a_cvv(self, key):
        assert classify(key) == "cvv"


class TestAKeyAboutACvvIsNot:
    @pytest.mark.parametrize(
        "key",
        [
            "cvv_required",
            "cvv_required_for_card_payment",
            "require_cvv_for_token_payment",
            "cvc_check",
            "cvvResult",
            "cvvResponseCode",
            "cardSecurityCodeError",
            "cvcResultCode",
            "securityCodeIndicator",
            "cvv_length",
            "cvvType",
            "cvv_placeholder",
        ],
    )
    def test_reads_through(self, key):
        assert classify(key) is None

    def test_the_mpgs_verdict_code_reads_through(self):
        event = {"authorizationResponse": {"cardSecurityCodeError": "M", "stan": "145957"}}
        masked = mask_sensitive_data(None, None, event)
        assert masked["authorizationResponse"]["cardSecurityCodeError"] == "M"


class TestTheLeaksItCloses:
    def test_a_hyphenated_security_code_is_masked(self):
        masked = mask_sensitive_data(None, None, {"payload": {"security-code": "123"}})
        assert masked["payload"]["security-code"] == "[CVV-MASKED]"

    def test_a_hyphenated_security_code_in_text_is_masked(self):
        # The CVV content rules are the `pci` pack's, which ottu_pg turns on.
        masked = MaskPIIFilter(packs=ALL_PACKS)._mask_value('card rejected, "security-code": "123"')
        assert "123" not in masked

    def test_authorize_nets_card_code_is_masked(self):
        masked = mask_sensitive_data(None, None, {"payment": {"creditCard": {"cardCode": "999"}}})
        assert masked["payment"]["creditCard"]["cardCode"] == "[CVV-MASKED]"


class TestNoServiceMayListWhatTheClassifierMasks:
    @pytest.mark.parametrize(
        "key",
        ["cvv_number", "cvvCode", "cvv2_value", "securityCodeValue", "tokens", "password_hash", "secret_data", "token_value"],
    )
    def test_is_never_safe(self, key):
        assert never_safe(key)
        with pytest.raises(ValueError):
            configure_masking_safe_keys([key])
        configure_masking_safe_keys(None)

    @pytest.mark.parametrize("key", ["cvv_required", "cardSecurityCodeError", "tokenization_status"])
    def test_a_name_about_one_may_be_listed(self, key):
        assert not never_safe(key)
