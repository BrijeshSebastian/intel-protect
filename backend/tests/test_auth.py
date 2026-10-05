import uuid
from datetime import datetime, timezone, timedelta
import pytest
from backend.app import db
from backend.app.models.user import User
from backend.app.models.refresh_token import RefreshToken
from backend.app.common.security import create_access_token, hash_token


@pytest.fixture(autouse=True)
def clean_database(app):
    """Clean database tables before each test execution."""
    with app.app_context():
        RefreshToken.query.delete()
        User.query.delete()
        db.session.commit()


# ==============================================================================
# 1. REGISTRATION TESTS
# ==============================================================================

def test_register_valid_user(client):
    """Test successful user registration with valid credentials."""
    payload = {
        "email": "testuser@example.com",
        "username": "testuser",
        "password": "Password123!",
        "full_name": "Test User"
    }
    response = client.post("/api/auth/register", json=payload)
    assert response.status_code == 201

    data = response.get_json()
    assert data["success"] is True
    assert "user" in data["data"]
    user_info = data["data"]["user"]
    assert user_info["email"] == "testuser@example.com"
    assert user_info["username"] == "testuser"
    assert user_info["full_name"] == "Test User"
    assert "password" not in user_info
    assert "password_hash" not in user_info

    # Verify user stored in DB with Argon2id hash
    user_in_db = User.query.filter_by(email="testuser@example.com").first()
    assert user_in_db is not None
    assert user_in_db.password_hash.startswith("$argon2id$")


def test_register_duplicate_email(client):
    """Test that registering an existing email returns 409 Conflict."""
    payload = {
        "email": "duplicate@example.com",
        "username": "user1",
        "password": "Password123!"
    }
    res1 = client.post("/api/auth/register", json=payload)
    assert res1.status_code == 201

    # Second registration with same email but different username
    payload2 = {
        "email": "DUPLICATE@example.com",  # Test case insensitivity
        "username": "user2",
        "password": "Password123!"
    }
    res2 = client.post("/api/auth/register", json=payload2)
    assert res2.status_code == 409
    data = res2.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "DUPLICATE_ENTITY"


def test_register_duplicate_username(client):
    """Test that registering an existing username returns 409 Conflict."""
    payload1 = {
        "email": "user1@example.com",
        "username": "common_username",
        "password": "Password123!"
    }
    assert client.post("/api/auth/register", json=payload1).status_code == 201

    payload2 = {
        "email": "user2@example.com",
        "username": "common_username",
        "password": "Password123!"
    }
    res2 = client.post("/api/auth/register", json=payload2)
    assert res2.status_code == 409
    assert res2.get_json()["error"]["code"] == "DUPLICATE_ENTITY"


def test_register_invalid_email_format(client):
    """Test rejection of malformed email addresses."""
    payload = {
        "email": "not-an-email",
        "username": "validuser",
        "password": "Password123!"
    }
    response = client.post("/api/auth/register", json=payload)
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"


def test_register_missing_fields(client):
    """Test rejection when required fields are omitted."""
    # Missing email
    res1 = client.post("/api/auth/register", json={"username": "user", "password": "Password123!"})
    assert res1.status_code == 400

    # Missing password
    res2 = client.post("/api/auth/register", json={"email": "u@e.com", "username": "user"})
    assert res2.status_code == 400


def test_register_weak_passwords(client):
    """Test password strength validation rules."""
    # Too short (< 8 chars)
    res1 = client.post("/api/auth/register", json={"email": "a@b.com", "username": "u1", "password": "Sh1!"})
    assert res1.status_code == 400

    # No uppercase letter
    res2 = client.post("/api/auth/register", json={"email": "a@b.com", "username": "u2", "password": "password123!"})
    assert res2.status_code == 400

    # No numbers or special characters
    res3 = client.post("/api/auth/register", json={"email": "a@b.com", "username": "u3", "password": "PasswordOnly"})
    assert res3.status_code == 400


# ==============================================================================
# 2. LOGIN TESTS
# ==============================================================================

def test_login_successful(client):
    """Test valid login sets HttpOnly cookie and returns access token in JSON body."""
    # Register first
    client.post("/api/auth/register", json={
        "email": "loginuser@example.com",
        "username": "loginuser",
        "password": "Password123!"
    })

    login_res = client.post("/api/auth/login", json={
        "email": "loginuser@example.com",
        "password": "Password123!"
    })
    assert login_res.status_code == 200

    payload = login_res.get_json()
    assert payload["success"] is True
    assert "access_token" in payload["data"]
    assert "user" in payload["data"]
    # CRITICAL SECURITY CHECK: Refresh token must NEVER appear in JSON response
    assert "refresh_token" not in payload["data"]
    assert "refresh_token" not in payload

    # Verify HttpOnly cookie header was set
    cookies = login_res.headers.getlist("Set-Cookie")
    refresh_cookie = [c for c in cookies if "refresh_token=" in c]
    assert len(refresh_cookie) == 1
    cookie_str = refresh_cookie[0]
    assert "HttpOnly" in cookie_str
    assert "Path=/api/auth" in cookie_str
    assert "SameSite=Strict" in cookie_str


def test_login_wrong_password(client):
    """Test authentication failure with incorrect password."""
    client.post("/api/auth/register", json={
        "email": "user@example.com",
        "username": "user",
        "password": "CorrectPassword1!"
    })

    res = client.post("/api/auth/login", json={
        "email": "user@example.com",
        "password": "WrongPassword1!"
    })
    assert res.status_code == 401
    assert res.get_json()["error"]["code"] == "INVALID_CREDENTIALS"


def test_login_nonexistent_account(client):
    """Test authentication failure for non-existent account."""
    res = client.post("/api/auth/login", json={
        "email": "nonexistent@example.com",
        "password": "Password123!"
    })
    assert res.status_code == 401
    assert res.get_json()["error"]["code"] == "INVALID_CREDENTIALS"


# ==============================================================================
# 3. ACCESS TOKEN & PROTECTED ROUTES TESTS
# ==============================================================================

def test_protected_route_with_valid_token(client):
    """Test access to /api/auth/me with valid Bearer access token."""
    reg_res = client.post("/api/auth/register", json={
        "email": "me_user@example.com",
        "username": "me_user",
        "password": "Password123!"
    })
    user_id = reg_res.get_json()["data"]["user"]["id"]

    login_res = client.post("/api/auth/login", json={
        "email": "me_user@example.com",
        "password": "Password123!"
    })
    access_token = login_res.get_json()["data"]["access_token"]

    # Access protected route
    me_res = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert me_res.status_code == 200
    user_data = me_res.get_json()["data"]["user"]
    assert user_data["id"] == user_id
    assert user_data["email"] == "me_user@example.com"


def test_protected_route_missing_token(client):
    """Test access rejection without Authorization header."""
    res = client.get("/api/auth/me")
    assert res.status_code == 401
    assert res.get_json()["error"]["code"] == "UNAUTHORIZED"


def test_protected_route_tampered_token(client):
    """Test access rejection with modified or invalid token."""
    res = client.get(
        "/api/auth/me",
        headers={"Authorization": "Bearer invalid.jwt.token"}
    )
    assert res.status_code == 401
    assert res.get_json()["error"]["code"] == "INVALID_TOKEN"


def test_protected_route_expired_token(client, app):
    """Test access rejection with an expired access token."""
    with app.app_context():
        user = User(
            email="exp@example.com",
            username="expuser",
            password_hash="dummy"
        )
        db.session.add(user)
        db.session.commit()

        # Issue token expired 10 minutes ago
        expired_token = create_access_token(str(user.id), user.email, expires_in_minutes=-10)

    res = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"}
    )
    assert res.status_code == 401
    assert res.get_json()["error"]["code"] == "TOKEN_EXPIRED"


# ==============================================================================
# 4. REFRESH TOKEN ROTATION & REUSE DETECTION TESTS
# ==============================================================================

def test_refresh_token_rotation_success(client):
    """Test refresh token rotation issues new access token and rotates cookie."""
    client.post("/api/auth/register", json={
        "email": "refresh_user@example.com",
        "username": "refresh_user",
        "password": "Password123!"
    })

    login_res = client.post("/api/auth/login", json={
        "email": "refresh_user@example.com",
        "password": "Password123!"
    })
    initial_access_token = login_res.get_json()["data"]["access_token"]

    # Extract initial cookie
    cookie = login_res.headers.get("Set-Cookie")
    raw_token_1 = cookie.split("refresh_token=")[1].split(";")[0]

    # Perform refresh
    refresh_res = client.post("/api/auth/refresh")
    assert refresh_res.status_code == 200

    new_access_token = refresh_res.get_json()["data"]["access_token"]
    assert new_access_token != initial_access_token

    # Extract rotated cookie
    new_cookie = refresh_res.headers.get("Set-Cookie")
    raw_token_2 = new_cookie.split("refresh_token=")[1].split(";")[0]
    assert raw_token_2 != raw_token_1

    # Verify old token record in database is marked revoked and linked to new token
    old_hash = hash_token(raw_token_1)
    old_record = RefreshToken.query.filter_by(token_hash=old_hash).first()
    assert old_record is not None
    assert old_record.revoked_at is not None
    assert old_record.replaced_by is not None

    # Verify new token record exists and is active
    new_hash = hash_token(raw_token_2)
    new_record = RefreshToken.query.filter_by(token_hash=new_hash).first()
    assert new_record is not None
    assert new_record.is_active is True
    assert new_record.token_family == old_record.token_family


def test_refresh_token_reuse_detection_and_family_revocation(client):
    """
    CRITICAL SECURITY TEST:
    Verifies that reusing an already rotated token triggers immediate
    family-wide revocation, terminating all active sessions in that chain.
    """
    client.post("/api/auth/register", json={
        "email": "reuse_victim@example.com",
        "username": "reuse_victim",
        "password": "Password123!"
    })

    # Step 1: Login -> produces Token A
    login_res = client.post("/api/auth/login", json={
        "email": "reuse_victim@example.com",
        "password": "Password123!"
    })
    token_a = login_res.headers.get("Set-Cookie").split("refresh_token=")[1].split(";")[0]

    # Step 2: Legitimate refresh -> produces Token B (Token A is rotated)
    refresh_1 = client.post("/api/auth/refresh")
    assert refresh_1.status_code == 200
    token_b = refresh_1.headers.get("Set-Cookie").split("refresh_token=")[1].split(";")[0]

    # Step 3: Legitimate refresh -> produces Token C (Token B is rotated)
    refresh_2 = client.post("/api/auth/refresh")
    assert refresh_2.status_code == 200
    token_c = refresh_2.headers.get("Set-Cookie").split("refresh_token=")[1].split(";")[0]

    # Verify Token C is currently active
    hash_c = hash_token(token_c)
    rec_c = RefreshToken.query.filter_by(token_hash=hash_c).first()
    assert rec_c.is_active is True

    # Step 4: ATTACK SIMULATION - Attacker presents previously rotated Token A!
    client.set_cookie("refresh_token", token_a, path="/api/auth")
    reuse_attack = client.post("/api/auth/refresh")

    # MUST fail with 401 and TOKEN_REUSE_DETECTED
    assert reuse_attack.status_code == 401
    assert reuse_attack.get_json()["error"]["code"] == "TOKEN_REUSE_DETECTED"

    # Step 5: VERIFY FAMILY REVOCATION
    # Every token in this family (A, B, C) must now be revoked!
    all_family_tokens = RefreshToken.query.filter_by(token_family=rec_c.token_family).all()
    assert len(all_family_tokens) == 3
    for tok in all_family_tokens:
        assert tok.revoked_at is not None

    # Step 6: Legitimate user tries to use Token C -> fails because family was revoked!
    client.set_cookie("refresh_token", token_c, path="/api/auth")
    legit_attempt = client.post("/api/auth/refresh")
    assert legit_attempt.status_code == 401


# ==============================================================================
# 5. LOGOUT TESTS
# ==============================================================================

def test_logout_revokes_token_and_clears_cookie(client):
    """Test logout revokes the refresh session and clears cookie."""
    client.post("/api/auth/register", json={
        "email": "logout_user@example.com",
        "username": "logout_user",
        "password": "Password123!"
    })

    login_res = client.post("/api/auth/login", json={
        "email": "logout_user@example.com",
        "password": "Password123!"
    })
    raw_token = login_res.headers.get("Set-Cookie").split("refresh_token=")[1].split(";")[0]

    # Logout
    logout_res = client.post("/api/auth/logout")
    assert logout_res.status_code == 200
    assert logout_res.get_json()["data"]["logged_out"] is True

    # Check database: token family should be revoked
    t_hash = hash_token(raw_token)
    t_rec = RefreshToken.query.filter_by(token_hash=t_hash).first()
    assert t_rec.revoked_at is not None

    # Try to refresh with the logged out session -> should fail
    client.set_cookie("refresh_token", raw_token, path="/api/auth")
    refresh_after_logout = client.post("/api/auth/refresh")
    assert refresh_after_logout.status_code == 401
