"""
Breach Monitor API Routes.
Exposes endpoints for breach verification, history, catalogs, and recommendations.
"""
from flask import Blueprint, request, g
from marshmallow import ValidationError
from backend.app.common.utils import api_response
from backend.app.common.security import token_required
from backend.app.breaches.schemas import breach_check_schema
from backend.app.breaches.service import (
    check_email_breaches,
    get_user_breach_history,
    get_breach_result_by_id,
    delete_breach_result,
    get_breach_catalog,
    get_user_recommendations,
    dismiss_recommendation
)

breaches_bp = Blueprint("breaches", __name__, url_prefix="/api/breaches")
recommendations_bp = Blueprint("recommendations", __name__, url_prefix="/api/recommendations")


@breaches_bp.route("/check", methods=["POST"])
@token_required
def run_breach_check():
    """
    POST /api/breaches/check
    Checks an email address against breach catalog.
    Evaluates exposure risk score, ML priority, and generates recommendations.
    """
    raw_payload = request.get_json(silent=True) or {}
    try:
        validated_data = breach_check_schema.load(raw_payload)
    except ValidationError as err:
        return api_response(
            error={
                "code": "VALIDATION_ERROR",
                "message": "Input validation failed.",
                "details": err.messages
            },
            status_code=400
        )

    email = validated_data.get("email")

    # If email not provided in payload, default to current user's email
    if not email and hasattr(g.current_user, "email"):
        email = g.current_user.email

    user_id = str(g.current_user.id)
    result = check_email_breaches(email=email, user_id=user_id)

    return api_response(
        data=result,
        message="Breach assessment completed successfully.",
        status_code=201
    )


@breaches_bp.route("/history", methods=["GET"])
@breaches_bp.route("", methods=["GET"])
@token_required
def list_breach_history():
    """
    GET /api/breaches/history or GET /api/breaches
    Retrieves paginated past breach lookups for the authenticated user.
    """
    page = request.args.get("page", default=1, type=int)
    limit = request.args.get("limit", default=10, type=int)
    page = max(1, page)
    limit = max(1, min(100, limit))
    offset = (page - 1) * limit

    records, total = get_user_breach_history(
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


@breaches_bp.route("/catalog", methods=["GET"])
@token_required
def list_breach_catalog():
    """
    GET /api/breaches/catalog
    Lists catalog of tracked security incidents (requires Bearer JWT authentication).
    """
    page = request.args.get("page", default=1, type=int)
    limit = request.args.get("limit", default=50, type=int)
    page = max(1, page)
    limit = max(1, min(100, limit))
    offset = (page - 1) * limit

    records, total = get_breach_catalog(limit=limit, offset=offset)

    return api_response(
        data={
            "catalog": records,
            "total": total,
            "page": page,
            "limit": limit
        },
        status_code=200
    )


@breaches_bp.route("/<uuid:result_id>", methods=["GET"])
@token_required
def get_breach_detail(result_id):
    """
    GET /api/breaches/<id>
    Retrieves detailed breakdown for a specific breach search result.
    """
    result = get_breach_result_by_id(
        result_id=str(result_id),
        user_id=str(g.current_user.id)
    )
    return api_response(data=result, status_code=200)


@breaches_bp.route("/<uuid:result_id>", methods=["DELETE"])
@token_required
def remove_breach_result(result_id):
    """
    DELETE /api/breaches/<id>
    Deletes a breach lookup record with data isolation.
    """
    delete_breach_result(
        result_id=str(result_id),
        user_id=str(g.current_user.id)
    )
    return api_response(
        data=None,
        message="Breach record deleted successfully.",
        status_code=200
    )


# --------------------------------------------------------------------------
# Recommendations API
# --------------------------------------------------------------------------

@recommendations_bp.route("", methods=["GET"])
@token_required
def list_recommendations():
    """
    GET /api/recommendations
    Retrieves active or all security recommendations for user.
    """
    active_only = request.args.get("active", default="true").lower() in ("true", "1", "yes")
    recs = get_user_recommendations(
        user_id=str(g.current_user.id),
        active_only=active_only
    )
    return api_response(data={"recommendations": recs}, status_code=200)


@recommendations_bp.route("/<uuid:rec_id>/dismiss", methods=["PATCH", "POST"])
@token_required
def dismiss_user_recommendation(rec_id):
    """
    PATCH /api/recommendations/<id>/dismiss
    Marks recommendation as dismissed.
    """
    updated = dismiss_recommendation(
        recommendation_id=str(rec_id),
        user_id=str(g.current_user.id)
    )
    return api_response(
        data={"recommendation": updated},
        message="Recommendation dismissed successfully.",
        status_code=200
    )
