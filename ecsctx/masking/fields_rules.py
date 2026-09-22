from typing import NamedTuple


class FieldRule(NamedTuple):
    field_type: str
    tokenizable: bool
    exemptable: bool


FIELD_RULES: dict[str, FieldRule] = {
    # field_type: FieldRule(field_type, tokenizable, exemptable)
    "cvv": FieldRule("cvv", False, False),
    # Track data, PIN blocks, EMV images: Sensitive Authentication Data that is
    # not the CVV. Never stored after authorization in any form, so unlike a PAN
    # there is nothing to truncate and nothing to tokenize — only the label.
    "sad": FieldRule("sad", False, False),
    "secret": FieldRule("secret", True, False),
    "payment_id": FieldRule("payment_id", True, False),
    # Card numbers are truncated (patterns.mask_card_value), never tokenized:
    # a keyed hash beside the truncated PAN would let the two be correlated.
    # A direct mask_by_field_type(v, "card") caller gets the bare label.
    "card": FieldRule("card", False, False),
    # Expiry is cardholder data when stored with a PAN; nothing needs it in a log.
    "pem_key": FieldRule("pem_key", True, False),
    "iban": FieldRule("iban", True, False),
    "jwt": FieldRule("jwt", True, False),
    "ssn": FieldRule("ssn", True, False),
    "email": FieldRule("email", True, True),
    "phone": FieldRule("phone", True, True),
    "address": FieldRule("address", True, True),
    "name": FieldRule("name", True, True),
    "generic": FieldRule("generic", True, True),
}


def get_field_rule(field_type: str) -> FieldRule:
    field_rule = FIELD_RULES.get(field_type)
    if not field_rule:
        field_rule = FieldRule(field_type, True, True)
    return field_rule

