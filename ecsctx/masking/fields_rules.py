from typing import NamedTuple


class FieldRule(NamedTuple):
    field_type: str
    tokenizable: bool
    exemptable: bool


FIELD_RULES: dict[str, FieldRule] = {
    # field_type: FieldRule(field_type, tokenizable, exemptable)
    "cvv": FieldRule("cvv", False, False),
    "secret": FieldRule("secret", True, False),
    "payment_id": FieldRule("payment_id", True, False),
    # Retained though the content rule no longer routes through here:
    # _mask_truncated_card builds its label directly. Kept non-exemptable
    # so any direct mask_by_field_type(v, "card") caller still fails closed
    # instead of falling back to the permissive default rule.
    "card": FieldRule("card", True, False),
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

