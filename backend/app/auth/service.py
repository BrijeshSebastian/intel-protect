import uuid
import logging
from datetime import datetime, timezone, timedelta

from backend.app import db
from backend.app.models.user import User
from backend.app.models.refresh_token import RefreshToken
from backend.app.common.security import (
    hash_password,
    verify_password,
    generate_raw_token,
    hash_token,
    create_access_token
)
from backend.app.common.errors import AppError

logger = logging.getLogger("intel_protect.auth")


class DuplicateUserError(AppError):
    def __init__(self, message="Account with this identifier already exists.", field="email"):
        super().__init__(message=message, code="DUPLICATE_ENTITY", status_code=409, details={"field": field})


class InvalidCredentialsError(AppError):
    def __init__(self, message="Invalid email or password."):
        super().__init__(message=message, code="INVALID_CREDENTIALS", status_code=401)


class TokenReuseError(AppError):
    def __init__(self, message="Security alert: Token reuse detected. Session terminated."):
        super().__init__(message=message, code="TOKEN_REUSE_DETECTED", status_code=401)


class InvalidRefreshTokenError(AppError):
    def __init__(self, message="Invalid or expired refresh token."):
        super().__init__(message=message, code="INVALID_REFRESH_TOKEN", status_code=401)


def register_user(email: str, username: str, password: str, full_name: str = None) -> dict:
    """
    Registers a new user account with normalized email, Argon2id password hash,
    and returns safe serialized profile.
    """
    clean_email = email.strip().lower()
    clean_username = username.strip()

    # Check for existing email
    if User.query.filter_by(email=clean_email).first():
        raise DuplicateUserError("An account with this email address already exists.", field="email")

    # Check for existing username
    if User.query.filter_by(username=clean_username).first():
        raise DuplicateUserError("This username is already registered.", field="username")

    # Hash with Argon2id
    hashed_pw = hash_password(password)

    new_user = User(
        email=clean_email,
        username=clean_username,
        password_hash=hashed_pw,
        full_name=full_name.strip() if full_name else None
    )

    db.session.add(new_user)
    db.session.commit()

    logger.info(f"New user registered successfully: id={new_user.id}")
    return new_user.to_dict()


def authenticate_user(email: str, password: str) -> tuple[str, str, User]:
    """
    Authenticates user credentials against Argon2id hash.
    Generates short-lived access JWT and cryptographically random refresh token.
    Returns (access_token, raw_refresh_token, user).
    """
    clean_email = email.strip().lower()
    user = User.query.filter_by(email=clean_email, is_active=True).first()

    if not user or not verify_password(user.password_hash, password):
        # Prevent timing attacks and user enumeration
        raise InvalidCredentialsError()

    # Update last login timestamp
    user.last_login = datetime.now(timezone.utc)

    # Issue access token (JWT - 15 minutes)
    access_token = create_access_token(str(user.id), user.email, expires_in_minutes=15)

    # Issue cryptographically secure refresh token
    raw_refresh_token = generate_raw_token()
    token_hash = hash_token(raw_refresh_token)
    token_family = uuid.uuid4()

    new_refresh_record = RefreshToken(
        user_id=user.id,
        token_hash=token_hash,
        token_family=token_family,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7)
    )

    db.session.add(new_refresh_record)
    db.session.commit()

    logger.info(f"User authenticated: id={user.id}, token_family={token_family}")
    return access_token, raw_refresh_token, user


def rotate_refresh_token(raw_token: str) -> tuple[str, str, User]:
    """
    Rotates a refresh token with strict reuse detection.
    If a previously revoked or replaced token is submitted, the entire token
    family is revoked immediately as a countermeasure against token theft.
    """
    if not raw_token:
        raise InvalidRefreshTokenError("Refresh token cookie missing.")

    hashed_input = hash_token(raw_token)
    token_record = RefreshToken.query.filter_by(token_hash=hashed_input).first()

    if not token_record:
        raise InvalidRefreshTokenError("Unrecognized refresh token.")

    # REUSE DETECTION: Token was already revoked or replaced!
    if token_record.revoked_at is not None or token_record.replaced_by is not None:
        logger.warning(
            f"SECURITY ALERT: Reused refresh token detected! "
            f"token_id={token_record.id}, family={token_record.token_family}, user_id={token_record.user_id}. "
            f"Revoking entire token family."
        )
        # Invalidate all tokens belonging to this family
        RefreshToken.query.filter_by(
            token_family=token_record.token_family,
            revoked_at=None
        ).update({"revoked_at": datetime.now(timezone.utc)})
        db.session.commit()

        raise TokenReuseError()

    # EXPIRATION CHECK
    if token_record.is_expired:
        token_record.revoked_at = datetime.now(timezone.utc)
        db.session.commit()
        raise InvalidRefreshTokenError("Refresh token has expired. Please log in again.")

    # USER STATUS CHECK
    user = token_record.user
    if not user or not user.is_active:
        raise InvalidRefreshTokenError("Associated user account is deactivated.")

    # NORMAL ROTATION: Generate replacement token inside the same token_family
    new_raw_token = generate_raw_token()
    new_token_hash = hash_token(new_raw_token)

    new_token_record = RefreshToken(
        user_id=user.id,
        token_hash=new_token_hash,
        token_family=token_record.token_family,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7)
    )

    db.session.add(new_token_record)
    db.session.flush()  # Populate new_token_record.id

    # Revoke old token and link to successor
    token_record.revoked_at = datetime.now(timezone.utc)
    token_record.replaced_by = new_token_record.id

    db.session.commit()

    # Issue fresh access token (15 minutes)
    new_access_token = create_access_token(str(user.id), user.email, expires_in_minutes=15)

    logger.info(f"Refresh token rotated: user_id={user.id}, family={token_record.token_family}")
    return new_access_token, new_raw_token, user


def logout_session(raw_token: str) -> bool:
    """
    Terminates the current session by revoking the refresh token and its family.
    """
    if not raw_token:
        return False

    hashed_input = hash_token(raw_token)
    token_record = RefreshToken.query.filter_by(token_hash=hashed_input).first()

    if token_record:
        # Revoke all tokens in this family for clean logout
        RefreshToken.query.filter_by(
            token_family=token_record.token_family,
            revoked_at=None
        ).update({"revoked_at": datetime.now(timezone.utc)})
        db.session.commit()
        logger.info(f"User logged out: token_family={token_record.token_family}")
        return True

    return False
