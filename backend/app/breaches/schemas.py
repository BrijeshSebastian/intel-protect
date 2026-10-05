"""
Validation schemas for Breach Monitor.
Enforces email formatting, type constraints, and length restrictions on breach queries.
"""
from marshmallow import Schema, fields, validate, EXCLUDE


class BreachCheckSchema(Schema):
    """Schema for validating breach assessment check requests."""
    email = fields.Email(
        required=False,
        allow_none=True,
        validate=validate.Length(max=255),
        error_messages={"invalid": "Invalid email address format."}
    )

    class Meta:
        unknown = EXCLUDE


breach_check_schema = BreachCheckSchema()
