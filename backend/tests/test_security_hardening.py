"""
Automated Security Hardening & Audit Verification Tests (Phase 10).
Tests:
1. Standard Security HTTP Headers (X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy)
2. Production HSTS Header attachment
3. Stale Temporary File Startup Cleanup
4. Marshmallow Input Validation for Exposure and Breach endpoints
5. Rate Limiter Throttling Enforcement (429 Too Many Requests)
"""
import os
import time
from pathlib import Path
import pytest
from flask import Flask

from backend.app import create_app, limiter
from backend.app.common.security import create_access_token
from backend.app.documents.service import cleanup_stale_temp_files, TEMP_DIR


def test_security_headers_present(client):
    """Verifies that mandatory OWASP security headers are attached to all API responses."""
    res = client.get("/api/health")
    assert res.status_code == 200
    headers = res.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-XSS-Protection") == "1; mode=block"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "Content-Security-Policy" in headers
    assert "default-src 'self'" in headers.get("Content-Security-Policy")


def test_production_hsts_header(app):
    """Verifies that Strict-Transport-Security header is attached when FLASK_ENV=production."""
    prod_app = create_app("production")
    with prod_app.test_client() as prod_client:
        res = prod_client.get("/api/health")
        assert res.status_code == 200
        assert "Strict-Transport-Security" in res.headers
        assert "max-age=31536000" in res.headers["Strict-Transport-Security"]


def test_stale_temp_file_startup_cleanup():
    """Verifies that stale temporary files older than threshold are safely purged."""
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    stale_file = TEMP_DIR / "stale_test_doc_orphan.tmp"
    stale_file.write_text("sensitivedataorphan")
    
    # Backdate modification time to 2 hours ago
    past_time = time.time() - 7200
    os.utime(stale_file, (past_time, past_time))
    
    fresh_file = TEMP_DIR / "fresh_test_doc.tmp"
    fresh_file.write_text("freshfile")

    try:
        deleted = cleanup_stale_temp_files(max_age_seconds=3600)
        assert deleted >= 1
        assert not stale_file.exists()
        assert fresh_file.exists()
    finally:
        if fresh_file.exists():
            fresh_file.unlink()
        if stale_file.exists():
            stale_file.unlink()


@pytest.fixture
def auth_user(app):
    """Creates a test user and returns (user, token, headers)."""
    from backend.app import db
    from backend.app.models.user import User
    with app.app_context():
        user = User(
            email=f"sec_test_{time.time_ns()}@intelprotect.internal",
            username=f"sec_user_{time.time_ns()}",
            password_hash="argon2_test_hash",
            is_active=True
        )
        db.session.add(user)
        db.session.commit()
        token = create_access_token(str(user.id), user.email)
        headers = {"Authorization": f"Bearer {token}"}
        return user, token, headers


def test_exposure_input_validation_schema(client, auth_user):
    """Verifies that malformed or oversized input to /api/exposure/analyze is rejected with 400."""
    _, _, headers = auth_user
    invalid_payload = {
        "identifiers": "not-a-dictionary-must-be-dict",
        "text": 123456
    }
    res = client.post("/api/exposure/analyze", json=invalid_payload, headers=headers)
    assert res.status_code == 400
    data = res.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "VALIDATION_ERROR"


def test_breach_input_validation_schema(client, auth_user):
    """Verifies that malformed email format to /api/breaches/check is rejected with 400."""
    _, _, headers = auth_user
    invalid_payload = {
        "email": "not-a-valid-email-format-missing-domain"
    }
    res = client.post("/api/breaches/check", json=invalid_payload, headers=headers)
    assert res.status_code == 400
    data = res.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert "email" in data["error"]["details"]


def test_rate_limiter_throttles_excessive_requests():
    """Verifies that rate limiter enforces request thresholds and returns 429 when enabled."""
    lim_app = Flask("rate_test_app")
    lim_app.config["RATELIMIT_ENABLED"] = True
    lim_app.config["RATELIMIT_STORAGE_URI"] = "memory://"
    lim_app.config["TESTING"] = False
    
    lim = limiter
    lim.init_app(lim_app)

    @lim_app.route("/rate-limited-test")
    @lim.limit("3 per minute")
    def limited_endpoint():
        return {"status": "ok"}, 200

    with lim_app.test_client() as lim_client:
        # First 3 requests should pass
        for _ in range(3):
            r = lim_client.get("/rate-limited-test")
            assert r.status_code == 200

        # 4th request must be throttled with 429 Too Many Requests
        r4 = lim_client.get("/rate-limited-test")
        assert r4.status_code == 429
