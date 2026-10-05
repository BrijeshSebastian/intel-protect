import os
import uuid
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from functools import wraps

import jwt
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from flask import request, current_app, g

from backend.app.common.utils import api_response
from backend.app.common.errors import AppError

# Initialize Argon2id password hasher (OWASP recommended parameters)
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MB
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID        # Argon2id
)


def hash_password(password: str) -> str:
    """Hash plaintext password using Argon2id."""
    return ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Verify password against Argon2id hash."""
    try:
        return ph.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception:
        return False


def hash_token(raw_token: str) -> str:
    """Generate SHA-256 hex digest of a raw token."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def generate_raw_token() -> str:
    """Generate a high-entropy cryptographically secure random token string."""
    return secrets.token_urlsafe(64)


def create_access_token(user_id: str, email: str, expires_in_minutes: int = 15) -> str:
    """
    Issue a short-lived JSON Web Token (JWT).
    Contains only essential non-sensitive identity claims.
    """
    now = datetime.now(timezone.utc)
    secret_key = current_app.config.get("SECRET_KEY")
    if not secret_key:
        raise AppError("Missing server SECRET_KEY", code="CONFIG_ERROR", status_code=500)

    payload = {
        "sub": str(user_id),
        "email": email,
        "iat": now,
        "exp": now + timedelta(minutes=expires_in_minutes),
        "jti": str(uuid.uuid4())
    }

    return jwt.encode(payload, secret_key, algorithm="HS256")


def decode_access_token(token: str) -> dict:
    """
    Decode and validate a JWT access token.
    Raises jwt.ExpiredSignatureError or jwt.InvalidTokenError on failure.
    """
    secret_key = current_app.config.get("SECRET_KEY")
    return jwt.decode(token, secret_key, algorithms=["HS256"])


def token_required(f):
    """
    Decorator to protect API endpoints using Bearer JWT access tokens.
    Extracts Bearer token, validates signature/expiration, and verifies active user.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header or not auth_header.startswith("Bearer "):
            return api_response(
                error={
                    "code": "UNAUTHORIZED",
                    "message": "Authorization header with Bearer token is required."
                },
                status_code=401
            )

        token = auth_header.split(" ", 1)[1].strip()

        try:
            payload = decode_access_token(token)
            user_id = payload.get("sub")
            if not user_id:
                return api_response(
                    error={
                        "code": "INVALID_TOKEN",
                        "message": "Token payload missing subject identifier."
                    },
                    status_code=401
                )

            # Lazy import to avoid circular dependency
            from backend.app.models.user import User
            user = User.query.filter_by(id=user_id, is_active=True).first()
            if not user:
                return api_response(
                    error={
                        "code": "USER_NOT_FOUND",
                        "message": "User account inactive or does not exist."
                    },
                    status_code=401
                )

            g.current_user = user
        except jwt.ExpiredSignatureError:
            return api_response(
                error={
                    "code": "TOKEN_EXPIRED",
                    "message": "Access token has expired. Please refresh your session."
                },
                status_code=401
            )
        except jwt.InvalidTokenError:
            return api_response(
                error={
                    "code": "INVALID_TOKEN",
                    "message": "Access token is invalid or malformed."
                },
                status_code=401
            )
        except Exception as e:
            return api_response(
                error={
                    "code": "AUTH_ERROR",
                    "message": "Authentication failed."
                },
                status_code=401
            )

        return f(*args, **kwargs)

    return decorated
