import pytest
from backend.app import create_app, db


@pytest.fixture(scope="session")
def app():
    """Create and configure a Flask application instance for testing."""
    test_app = create_app(config_name="testing")
    with test_app.app_context():
        yield test_app


@pytest.fixture(scope="session")
def client(app):
    """Test client for issuing HTTP requests."""
    return app.test_client()


@pytest.fixture(scope="session")
def db_session(app):
    """Database session fixture."""
    with app.app_context():
        yield db.session
