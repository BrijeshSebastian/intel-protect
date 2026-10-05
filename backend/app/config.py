import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root or backend directory
BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / ".env")


class BaseConfig:
    """Base configuration common to all environments."""
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-insecure-secret-key-min-32-chars-long")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }
    
    # CORS allowed origins
    _cors_raw = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173")
    CORS_ORIGINS = [origin.strip() for origin in _cors_raw.split(",") if origin.strip()]

    # Rate limiting configuration (Flask-Limiter)
    RATELIMIT_ENABLED = True
    RATELIMIT_DEFAULT = "1000 per day; 200 per hour"
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_STRATEGY = "fixed-window"


class DevelopmentConfig(BaseConfig):
    """Configuration for local development."""
    DEBUG = True
    TESTING = False
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "postgresql://postgres:postgres@localhost:5432/intel_protect_db"
    )


class TestingConfig(BaseConfig):
    """Configuration for running automated test suites."""
    DEBUG = False
    TESTING = True
    RATELIMIT_ENABLED = False
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "TEST_DATABASE_URL",
        "postgresql://postgres:postgres@localhost:5432/intel_protect_test_db"
    )


class ProductionConfig(BaseConfig):
    """Configuration for production deployment."""
    DEBUG = False
    TESTING = False
    ENV = "production"
    IS_PRODUCTION = True
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")

    @classmethod
    def init_app(cls, app):
        assert os.getenv("SECRET_KEY"), "SECRET_KEY environment variable must be set in production"
        assert os.getenv("DATABASE_URL"), "DATABASE_URL environment variable must be set in production"


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config(config_name=None):
    """Retrieve configuration object by environment name."""
    env_name = config_name or os.getenv("FLASK_ENV", "development").lower()
    return config_by_name.get(env_name, DevelopmentConfig)
