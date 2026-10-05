"""
Validation schemas for Exposure Monitor.
Enforces type, structure, and length boundaries on user-submitted footprint requests.
"""
from marshmallow import Schema, fields, validate, EXCLUDE


class ExposureAnalysisSchema(Schema):
    """Schema for validating exposure footprint analysis requests."""
    identifiers = fields.Dict(
        keys=fields.String(),
        values=fields.String(validate=validate.Length(max=500)),
        required=False
    )
    text = fields.String(
        required=False,
        allow_none=True,
        validate=validate.Length(max=50000)
    )
    custom_text = fields.String(
        required=False,
        allow_none=True,
        validate=validate.Length(max=50000)
    )
    exposure_text = fields.String(
        required=False,
        allow_none=True,
        validate=validate.Length(max=50000)
    )

    class Meta:
        unknown = EXCLUDE


exposure_analysis_schema = ExposureAnalysisSchema()
