import logging
from flask import current_app
from backend.app.common.utils import api_response

logger = logging.getLogger(__name__)


class AppError(Exception):
    """Base application exception."""
    def __init__(self, message="An internal error occurred", code="INTERNAL_ERROR", status_code=500, details=None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}


class DatabaseConnectionError(AppError):
    """Raised when database connection fails."""
    def __init__(self, message="Database connectivity error", details=None):
        super().__init__(message=message, code="DATABASE_ERROR", status_code=503, details=details)


def register_error_handlers(app):
    """Register centralized JSON error handlers on the Flask app."""

    @app.errorhandler(AppError)
    def handle_app_error(err):
        return api_response(
            data=None,
            error={
                "code": err.code,
                "message": err.message,
                "details": err.details
            },
            status_code=err.status_code
        )

    @app.errorhandler(400)
    def handle_400(err):
        return api_response(
            data=None,
            error={
                "code": "BAD_REQUEST",
                "message": getattr(err, "description", "Invalid request parameters.")
            },
            status_code=400
        )

    @app.errorhandler(404)
    def handle_404(err):
        return api_response(
            data=None,
            error={
                "code": "NOT_FOUND",
                "message": getattr(err, "description", "The requested resource was not found.")
            },
            status_code=404
        )

    @app.errorhandler(405)
    def handle_405(err):
        return api_response(
            data=None,
            error={
                "code": "METHOD_NOT_ALLOWED",
                "message": "The HTTP method is not allowed for this endpoint."
            },
            status_code=405
        )

    @app.errorhandler(500)
    def handle_500(err):
        logger.error(f"Unhandled 500 error: {err}", exc_info=True)
        return api_response(
            data=None,
            error={
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected server error occurred. Please try again later."
            },
            status_code=500
        )
