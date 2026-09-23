"""Sensitive Authentication Data is named by what it holds, not by a word in it.

0.13.0 made `track` a SAD word so a card object's `track2` could never reach a
log once card containers started being walked. It matched `track` as a *word*,
and a word is also the head of `track_id` -- KNET's merchant track id, and the
"Track ID" line Connect puts in every payment's details. Both shipped as
`[SAD-MASKED]` on jade, and because SAD may never be listed as safe, no setting
could undo it.

The fix keys on the tail: `track`/`magnetic` followed by nothing or by a word
naming the data (`track2`, `raw_track`, `trackData`) is the stripe image;
followed by an id-ish word it names the payment.

The same round found the gap in the other direction: a wallet's payment
cryptogram (Samsung Pay `cryptogram`, MPGS `onlinePaymentCryptogram`) and 3DS
authentication values (`cavv`, UCAF data) had no rule at all, and ottu_pg logged
the Samsung Pay one in clear. They are one-time values that authenticate a
transaction -- nothing reads them in a log. A verdict *about* one
(`cavvResponseCode`) is not one.
"""

import pytest

from ecsctx.masking.patterns import ALL_PACKS, classify_key
from ecsctx.processors import mask_sensitive_data


def classify(key):
    return classify_key(key, ALL_PACKS)


class TestTrackDataIsNotATrackingId:
    @pytest.mark.parametrize(
        "key",
        ["Track ID", "track_id", "trackId", "trackid", "TrackID", "track_number", "trackingNumber", "tracking_id"],
    )
    def test_a_tracking_id_reads_through(self, key):
        assert classify(key) is None

    @pytest.mark.parametrize(
        "key",
        [
            "track",
            "track1",
            "track2",
            "track_2",
            "Track 2",
            "track3",
            "trackTwo",
            "trackData",
            "track2Data",
            "track2_equivalent_data",
            "raw_track",
            "encrypted_track",
            "card_track",
            "magnetic",
            "magnetic_stripe",
            "magstripe",
        ],
    )
    def test_the_stripe_image_is_still_sad(self, key):
        assert classify(key) == "sad"

    @pytest.mark.parametrize("key", ["emv_tags", "iccData", "chip_data", "de55", "field55"])
    def test_chip_data_is_sad(self, key):
        assert classify(key) == "sad"

    def test_connects_payment_details_line_keeps_its_track_id(self):
        # The live shape: Connect's attempt-details response.
        event = {"payment_details": {"Track ID": "HOT45EE6", "Card Expiry Month": "01"}}
        masked = mask_sensitive_data(None, None, event)
        assert masked["payment_details"]["Track ID"] == "HOT45EE6"


class TestCryptogramsAndAuthenticationValues:
    @pytest.mark.parametrize(
        "key",
        [
            "cryptogram",
            "onlinePaymentCryptogram",
            "payment_cryptogram",
            "cavv",
            "CAVV",
            "tavv",
            "aav",
            "ucaf",
            "ucafAuthenticationData",
            "ucaf_authentication_data",
            "cavvValue",
        ],
    )
    def test_the_value_is_sad(self, key):
        assert classify(key) == "sad"

    @pytest.mark.parametrize(
        "key",
        ["cavvResponseCode", "cavv_result", "ucafCollectionIndicator", "ucaf_collection_indicator", "eci", "xid"],
    )
    def test_a_verdict_or_indicator_about_one_is_not(self, key):
        assert classify(key) != "sad"

    def test_samsung_pay_decrypted_payload_hides_the_cryptogram(self):
        # ottu_pg's `payment.data_decrypted` for Samsung Pay, which shipped the
        # cryptogram in clear: nothing classified the key.
        event = {
            "payload": {
                "processed_data": {
                    "cryptogram": "AgAAAAAAAIR8CQrXcIhbQAAAAAA=",
                    "eci_indicator": "05",
                    "currency_code": "KWD",
                }
            }
        }
        masked = mask_sensitive_data(None, None, event)["payload"]["processed_data"]
        assert masked["cryptogram"] == "[SAD-MASKED]"
        assert masked["eci_indicator"] == "05"
