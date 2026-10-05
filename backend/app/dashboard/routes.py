"""
Dashboard REST API Routes.
Exposes endpoints for retrieving consolidated privacy risk intelligence.
Enforces @token_required authentication and strict user data isolation.
"""
from flask import Blueprint, request, g
from backend.app.common.security import token_required
from backend.app.common.utils import api_response
from backend.app.dashboard.service import get_user_dashboard_data

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")


def _check_user_access():
    """Enforces ownership: rejecting explicit requests for foreign user_id data."""
    requested_user_id = request.args.get("user_id")
    if requested_user_id and str(requested_user_id) != str(g.current_user.id):
        return api_response(
            error={
                "code": "FORBIDDEN",
                "message": "Access denied: cannot access another user's dashboard data."
            },
            status_code=403
        )
    return None


@dashboard_bp.route("", methods=["GET"])
@dashboard_bp.route("/summary", methods=["GET"])
@token_required
def get_dashboard_summary():
    """
    GET /api/dashboard or GET /api/dashboard/summary
    Retrieves unified threat intelligence dashboard data for the authenticated user.
    Aggregates overall risk score, module-specific metrics, 5-category distribution,
    recent activity timeline, and active security recommendations.
    """
    denial = _check_user_access()
    if denial:
        return denial

    user_id = str(g.current_user.id)
    dashboard_data = get_user_dashboard_data(user_id=user_id)
    return api_response(
        data=dashboard_data,
        message="Dashboard summary retrieved successfully.",
        status_code=200
    )


@dashboard_bp.route("/risk", methods=["GET"])
@token_required
def get_dashboard_risk():
    """
    GET /api/dashboard/risk
    Retrieves overall composite risk score and individual module scores.
    """
    denial = _check_user_access()
    if denial:
        return denial

    user_id = str(g.current_user.id)
    data = get_user_dashboard_data(user_id=user_id)
    return api_response(
        data={
            "overall_risk": data["overall_risk"],
            "document_risk": data["document_risk"],
            "exposure_risk": data["exposure_risk"],
            "breach_risk": data["breach_risk"],
            "risk_distribution": data["risk_distribution"]
        },
        status_code=200
    )


@dashboard_bp.route("/recommendations", methods=["GET"])
@token_required
def get_dashboard_recommendations():
    """
    GET /api/dashboard/recommendations
    Retrieves cross-module deduplicated security recommendations.
    """
    denial = _check_user_access()
    if denial:
        return denial

    user_id = str(g.current_user.id)
    data = get_user_dashboard_data(user_id=user_id)
    return api_response(
        data={"recommendations": data["active_recommendations"]},
        status_code=200
    )


@dashboard_bp.route("/history", methods=["GET"])
@token_required
def get_dashboard_history():
    """
    GET /api/dashboard/history
    Retrieves chronological cross-subsystem threat activity feed.
    """
    denial = _check_user_access()
    if denial:
        return denial

    user_id = str(g.current_user.id)
    data = get_user_dashboard_data(user_id=user_id)
    return api_response(
        data={"recent_activity": data["recent_activity"]},
        status_code=200
    )


@dashboard_bp.route("/recommendations/<uuid:rec_id>/dismiss", methods=["PATCH", "POST"])
@token_required
def dismiss_dashboard_recommendation(rec_id):
    """
    PATCH /api/dashboard/recommendations/<id>/dismiss
    Marks recommendation as dismissed across the unified engine.
    """
    from backend.app.dashboard.service import dismiss_unified_recommendation
    user_id = str(g.current_user.id)
    updated = dismiss_unified_recommendation(recommendation_id=str(rec_id), user_id=user_id)
    return api_response(
        data={"recommendation": updated},
        message="Recommendation dismissed successfully.",
        status_code=200
    )

