"""`key_field_type`: what the engine makes of a key name, for values that reach
a log outside a mapping.

ottu_pg's card delete route is `DELETE /v1/pbl/card/token/<token>/`: the token
reaches the log in the message and `url.path`, where no key sits next to it.
The service knows the route's own parameter names (`token`), so it can ask the
engine what that name means under its packs and safe keys, and mask the
segment with `mask_by_field_type` exactly as a `token` field would be.
"""

from ecsctx.masking import configure_masking_packs, configure_masking_safe_keys, key_field_type


def test_a_credential_name():
    assert key_field_type("token") == "secret"


def test_a_pii_name():
    assert key_field_type("customer_email") == "email"


def test_a_name_that_means_nothing():
    assert key_field_type("uid") is None


def test_it_follows_the_services_safe_keys():
    configure_masking_safe_keys(["merchantid"])
    assert key_field_type("merchantId") is None


def test_it_follows_the_services_packs():
    configure_masking_packs(["default"])
    assert key_field_type("transaction_id") is None
    configure_masking_packs(["default", "financial_ids"])
    assert key_field_type("transaction_id") == "payment_id"
