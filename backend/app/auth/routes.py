from flask import Blueprint, request, current_app, g
from marshmallow import ValidationError

from backend.app.common.utils import api_response
from backend.app.common.security import token_required
from backend.app.auth.schemas import register_schema, login_schema
from backend.app.auth.service import (
    register_user,
    authenticate_user,
    rotate_refresh_token,
    logout_session
)
from backend.app import limiter

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


def _set_refresh_cookie(response, raw_token: str):
    """Configures secure HttpOnly cookie for refresh token."""
    is_prod = current_app.config.get("FLASK_ENV") == "production"
    response.set_cookie(
        key="refresh_token",
        value=raw_token,
        max_age=7 * 24 * 3600,  # 7 days
        httponly=True,
        samesite="Strict",
        path="/api/auth",
        secure=is_prod
    )


def _clear_refresh_cookie(response):
    """Clears the HttpOnly refresh token cookie on client."""
    response.delete_cookie(key="refresh_token", path="/api/auth")


@auth_bp.route("/register", methods=["POST"])
@limiter.limit("20 per minute")
def register():
    """
    POST /api/auth/register
    Registers a new user account with Argon2id password hash.
    """
    json_data = request.get_json(silent=True)
    if not json_data:
        return api_response(
            error={"code": "BAD_REQUEST", "message": "Request body must be valid JSON."},
            status_code=400
        )

    try:
        data = register_schema.load(json_data)
    except ValidationError as err:
        return api_response(
            error={
                "code": "VALIDATION_ERROR",
                "message": "Input validation failed.",
                "details": err.messages
            },
            status_code=400
        )

    user_dict = register_user(
        email=data["email"],
        username=data["username"],
        password=data["password"],
        full_name=data.get("full_name")
    )

    return api_response(
        data={"user": user_dict},
        message="User registered successfully.",
        status_code=201
    )


@auth_bp.route("/login", methods=["POST"])
@limiter.limit("20 per minute")
def login():
    """
    POST /api/auth/login
    Authenticates user, issues access token in JSON and refresh token in HttpOnly cookie.
    """
    json_data = request.get_json(silent=True)
    if not json_data:
        return api_response(
            error={"code": "BAD_REQUEST", "message": "Request body must be valid JSON."},
            status_code=400
        )

    try:
        data = login_schema.load(json_data)
    except ValidationError as err:
        return api_response(
            error={
                "code": "VALIDATION_ERROR",
                "message": "Input validation failed.",
                "details": err.messages
            },
            status_code=400
        )

    access_token, raw_refresh_token, user = authenticate_user(
        email=data["email"],
        password=data["password"]
    )

    resp, status_code = api_response(
        data={
            "access_token": access_token,
            "user": user.to_dict()
        },
        message="Login successful.",
        status_code=200
    )

    # Deliver raw refresh token strictly via HttpOnly cookie
    _set_refresh_cookie(resp, raw_refresh_token)
    return resp, status_code


@auth_bp.route("/refresh", methods=["POST"])
def refresh():
    """
    POST /api/auth/refresh
    Rotates refresh token and issues new access token.
    Detects reuse and revokes entire family on theft detection.
    """
    raw_token = request.cookies.get("refresh_token")
    if not raw_token:
        return api_response(
            error={"code": "UNAUTHORIZED", "message": "Refresh token cookie not provided."},
            status_code=401
        )

    new_access_token, new_raw_token, user = rotate_refresh_token(raw_token)

    resp, status_code = api_response(
        data={
            "access_token": new_access_token,
            "user": user.to_dict()
        },
        message="Session refreshed successfully.",
        status_code=200
    )

    # Rotate cookie with new refresh token
    _set_refresh_cookie(resp, new_raw_token)
    return resp, status_code


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """
    POST /api/auth/logout
    Revokes the current refresh session and clears the HttpOnly cookie.
    """
    raw_token = request.cookies.get("refresh_token")
    if raw_token:
        logout_session(raw_token)

    resp, status_code = api_response(
        data={"logged_out": True},
        message="Logged out successfully.",
        status_code=200
    )

    _clear_refresh_cookie(resp)
    return resp, status_code


@auth_bp.route("/me", methods=["GET"])
@token_required
def get_current_user_profile():
    """
    GET /api/auth/me
    Protected endpoint returning authenticated user's safe profile.
    """
    return api_response(
        data={"user": g.current_user.to_dict()},
        status_code=200
    )
