import re
from marshmallow import Schema, fields, validate, validates, ValidationError


class RegisterSchema(Schema):
    """Validation schema for user registration requests."""
    email = fields.Email(
        required=True,
        error_messages={"required": "Email address is required.", "invalid": "Invalid email address format."}
    )
    username = fields.String(
        required=True,
        validate=[
            validate.Length(min=3, max=80, error="Username must be between 3 and 80 characters."),
            validate.Regexp(r'^[a-zA-Z0-9_-]+$', error="Username must contain only letters, numbers, underscores, or hyphens.")
        ]
    )
    password = fields.String(
        required=True,
        load_only=True,
        validate=[validate.Length(min=8, max=128, error="Password must be between 8 and 128 characters.")]
    )
    full_name = fields.String(
        required=False,
        allow_none=True,
        validate=[validate.Length(max=150, error="Full name cannot exceed 150 characters.")]
    )

    @validates("email")
    def validate_email_clean(self, value, **kwargs):
        if not value or len(value.strip()) == 0:
            raise ValidationError("Email address cannot be empty.")

    @validates("password")
    def validate_password_strength(self, value, **kwargs):
        if not re.search(r'[A-Z]', value):
            raise ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', value):
            raise ValidationError("Password must contain at least one lowercase letter.")
        if not re.search(r'[0-9]', value) and not re.search(r'[^A-Za-z0-9]', value):
            raise ValidationError("Password must contain at least one digit or special symbol.")


class LoginSchema(Schema):
    """Validation schema for user authentication requests."""
    email = fields.Email(
        required=True,
        error_messages={"required": "Email address is required.", "invalid": "Invalid email address format."}
    )
    password = fields.String(
        required=True,
        load_only=True,
        error_messages={"required": "Password is required."}
    )


register_schema = RegisterSchema()
login_schema = LoginSchema()
