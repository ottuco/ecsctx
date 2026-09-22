"""Key names are matched as names, not as substrings of names.

Every rule here comes from a real MPGS response that came back tokenized in
production. The pattern is always the same: a sensitive word appears *inside* a
longer name that means something else.

    authorizationCode            the acquirer's approval code -- a payment verdict
    schemeTokenProvisioningMode  an enum, e.g. CARD_ON_FILE
    requestorName                the 3DS requestor, which is a merchant
    domainName                   a hostname
    payerInteraction             an enum, e.g. OUT_OF_BAND

Connect's own second masking layer already refuses to mask `authcode` for
exactly this reason -- "Masking it would blank a payment verdict field" -- so
before this change the two services disagreed about the same value.

The direction of the fix is: a credential word must END the key (`scheme_token`
names a token; `tokenization_status` names something about one), `authorization`
must BE the key, and a `*name` key is a person only when something in the name
says which person.
"""

import pytest

from ecsctx.masking.patterns import ALL_PACKS, classify_key


def classify(key):
    return classify_key(key, ALL_PACKS)


class TestGatewayFieldsAreNotCredentials:
    @pytest.mark.parametrize(
        "key",
        [
            "authorizationCode",
            "authorization_code",
            "authorizationResponse",
            "schemeTokenProvisioningMode",
            "tokenization_status",
            "token_type",
        ],
    )
    def test_a_credential_word_inside_a_longer_name(self, key):
        assert classify(key) is None

    @pytest.mark.parametrize(
        "key",
        [
            "authorization",
            "Authorization",
            "authorization_header",
            "authorisation",
            "schemeToken",
            "authenticationToken",
            "api_token",
            "access_token",
            "token",
            "tokens",
            "password",
            "client_secret",
            "api_key",
            "bearer",
        ],
    )
    def test_a_real_credential_still_masks(self, key):
        assert classify(key) == "secret"


class TestOnlyAPersonHasAName:
    @pytest.mark.parametrize(
        "key",
        [
            "requestorName",
            "domainName",
            "domain_name",
            "merchantName",
            "schemeName",
            "payerInteraction",
            "fileName",
            "hostName",
        ],
    )
    def test_a_name_key_that_names_no_person(self, key):
        assert classify(key) is None

    @pytest.mark.parametrize(
        "key",
        [
            "name",
            "names",
            "customer_name",
            "customerName",
            "payer_name",
            "payerName",
            "cardholder_name",
            "cardholderName",
            "nameOnCard",
            "name_on_card",
            "first_name",
            "firstName",
            "lastname",
            "surname",
            "full_name",
            "nickname",
            "holder",
            "cardholder",
            "beneficiary",
            "recipient",
            "payer",
        ],
    )
    def test_a_person_still_masks(self, key):
        assert classify(key) == "name"


class TestASafeKeyWorksInBothSpellings:
    """A safe key is listed one way and the payload writes it the other. Before,
    `domain_name` was listed and `domainName` was masked as a person."""

    @pytest.mark.parametrize(
        "pair", [("domain_name", "domainName"), ("display_name", "displayName"), ("file_name", "fileName")]
    )
    def test_both_spellings_resolve_the_same(self, pair):
        listed, camel = pair
        assert classify(listed) == classify(camel) is None

    def test_a_service_safe_key_works_in_camel_case_too(self):
        safe = frozenset({"pg_name"})
        assert classify_key("pg_name", ALL_PACKS, safe) is None
        assert classify_key("pgName", ALL_PACKS, safe) is None


class TestSensitiveAuthenticationData:
    @pytest.mark.parametrize(
        "key", ["track2", "track2Data", "track_2", "magstripe", "pinBlock", "pin", "emvRequest"]
    )
    def test_track_and_pin_are_their_own_type(self, key):
        assert classify(key) == "sad"

    @pytest.mark.parametrize("key", ["shipping", "mapping", "backtrack", "pinned", "spinner"])
    def test_a_word_merely_containing_one_is_not(self, key):
        assert classify(key) != "sad"
