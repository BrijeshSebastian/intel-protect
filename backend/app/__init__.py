import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import text

from backend.app.config import get_config
from backend.app.common.utils import api_response
from backend.app.common.errors import register_error_handlers
from backend.app.common.logging import setup_pii_safe_logging

# Configure basic logging with PII redaction filter
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
setup_pii_safe_logging()
logger = logging.getLogger("intel_protect")

# Global extension singletons
db = SQLAlchemy()
migrate = Migrate()
cors = CORS()
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://",
    default_limits=["1000 per day", "200 per hour"]
)


def create_app(config_name=None):
    """
    Application Factory for Intel-Protect.
    Initializes Flask application, configuration, extensions, and core routes.
    """
    app = Flask(__name__)
    
    # Load configuration
    cfg = get_config(config_name)
    app.config.from_object(cfg)
    
    if hasattr(cfg, "init_app"):
        cfg.init_app(app)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)
    cors.init_app(
        app,
        resources={r"/api/*": {"origins": app.config.get("CORS_ORIGINS", ["*"])}},
        supports_credentials=True
    )

    # Register centralized error handlers
    register_error_handlers(app)

    # Security headers middleware
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        
        # Content Security Policy
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self' http://localhost:5001 http://127.0.0.1:5001 http://localhost:5000 http://127.0.0.1:5000;"
        )
        response.headers["Content-Security-Policy"] = csp_policy

        if app.config.get("IS_PRODUCTION") or app.config.get("ENV") == "production" or app.config.get("FLASK_ENV") == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response

    # Purge stale temporary files on application startup (crash recovery)
    try:
        from backend.app.documents.service import cleanup_stale_temp_files
        cleanup_stale_temp_files()
    except Exception as e:
        logger.warning(f"Could not purge stale temp files at startup: {e}")

    # Register blueprints
    from backend.app.auth import auth_bp
    from backend.app.documents import documents_bp
    from backend.app.exposure.routes import exposure_bp
    from backend.app.breaches.routes import breaches_bp, recommendations_bp
    from backend.app.dashboard.routes import dashboard_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(exposure_bp)
    app.register_blueprint(breaches_bp)
    app.register_blueprint(recommendations_bp)
    app.register_blueprint(dashboard_bp)

    # Import models to ensure they are registered with SQLAlchemy/Alembic
    import backend.app.models

    # Core Health Check API
    @app.route("/api/health", methods=["GET"])
    def health_check():
        """
        Health check endpoint.
        Verifies that Flask is operational and PostgreSQL is connected.
        """
        db_status = "disconnected"
        try:
            # Perform a lightweight ping to verify actual DB connectivity
            db.session.execute(text("SELECT 1"))
            db_status = "connected"
            return api_response(
                data={
                    "status": "healthy",
                    "service": "Intel-Protect API",
                    "version": "1.0.0",
                    "database": db_status
                },
                status_code=200
            )
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return api_response(
                data={
                    "status": "degraded",
                    "service": "Intel-Protect API",
                    "version": "1.0.0",
                    "database": "disconnected"
                },
                error={
                    "code": "DATABASE_UNAVAILABLE",
                    "message": "Database connectivity check failed."
                },
                status_code=503
            )

    @app.route("/", methods=["GET"])
    def index():
        return api_response(
            data={
                "name": "Intel-Protect Data Exposure Monitor API",
                "version": "1.0.0",
                "docs": "/api/health"
            },
            message="Welcome to Intel-Protect API"
        )

    return app
