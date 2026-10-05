"""
Exposure Monitor REST API Routes.
Exposes endpoints for analyzing user exposure, retrieving history,
and inspecting detailed entity and anomaly explanations.
Enforces @token_required authentication, ownership isolation, and PII-safe serialization.
"""
from flask import Blueprint, request, g
from marshmallow import ValidationError
from backend.app.common.utils import api_response
from backend.app.common.security import token_required
from backend.app.exposure.schemas import exposure_analysis_schema
from backend.app.exposure.service import (
    analyze_exposure,
    get_user_exposure_history,
    get_exposure_record_by_id,
    delete_exposure_record
)

exposure_bp = Blueprint("exposure", __name__, url_prefix="/api/exposure")


@exposure_bp.route("/analyze", methods=["POST"])
@token_required
def run_exposure_analysis():
    """
    POST /api/exposure/analyze
    Analyzes identity exposure for provided identifiers or text snippet.
    Returns composite exposure score, category breakdown, sensitivity, and anomaly analysis.
    """
    raw_payload = request.get_json(silent=True) or {}
    try:
        validated_data = exposure_analysis_schema.load(raw_payload)
    except ValidationError as err:
        return api_response(
            error={
                "code": "VALIDATION_ERROR",
                "message": "Input validation failed.",
                "details": err.messages
            },
            status_code=400
        )

    identifiers = validated_data.get("identifiers") or {}
    custom_text = validated_data.get("text") or validated_data.get("exposure_text") or validated_data.get("custom_text")

    # If payload is flat dict with name/email/phone, accept it as identifiers
    if not identifiers and not custom_text:
        identifiers = {
            k: v for k, v in raw_payload.items()
            if k in ("name", "email", "phone", "username", "location", "address")
        }

    user_id = str(g.current_user.id)
    result = analyze_exposure(
        identifiers=identifiers,
        user_id=user_id,
        custom_text=custom_text
    )

    return api_response(
        data=result,
        message="Exposure analysis completed successfully.",
        status_code=201
    )


@exposure_bp.route("/history", methods=["GET"])
@exposure_bp.route("", methods=["GET"])
@token_required
def list_exposure_history():
    """
    GET /api/exposure/history or GET /api/exposure
    Retrieves paginated history of exposure analyses for the authenticated user.
    """
    page = request.args.get("page", 1, type=int)
    limit = min(request.args.get("limit", 10, type=int), 50)
    offset = (page - 1) * limit

    records, total = get_user_exposure_history(
        user_id=str(g.current_user.id),
        limit=limit,
        offset=offset
    )

    return api_response(
        data={
            "records": records,
            "total": total,
            "page": page,
            "limit": limit,
            "pages": (total + limit - 1) // limit if limit > 0 else 1
        },
        status_code=200
    )


@exposure_bp.route("/<uuid:record_id>", methods=["GET"])
@token_required
def get_exposure_detail(record_id):
    """
    GET /api/exposure/<id>
    Retrieves detailed breakdown for a specific exposure record with user data isolation.
    """
    record_dict = get_exposure_record_by_id(
        record_id=str(record_id),
        user_id=str(g.current_user.id)
    )
    return api_response(
        data={"exposure_record": record_dict},
        status_code=200
    )


@exposure_bp.route("/<uuid:record_id>", methods=["DELETE"])
@token_required
def remove_exposure_record(record_id):
    """
    DELETE /api/exposure/<id>
    Removes an exposure record with user data isolation.
    """
    delete_exposure_record(
        record_id=str(record_id),
        user_id=str(g.current_user.id)
    )
    return api_response(
        data={"deleted": True},
        message="Exposure record removed successfully.",
        status_code=200
    )
