from datetime import datetime, timedelta, timezone
from typing import Any
import jwt

from app.config.settings import settings


def create_access_token(subject: str | Any, expires_delta: timedelta = None) -> str:
    """
    Generates a JWT access token for the given subject (e.g. user ID).
    Standardizes on UTC timestamps.
    """
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode = {
        "exp": int(expire.timestamp()),
        "sub": str(subject),
        "iat": int(datetime.now(timezone.utc).timestamp()),
    }

    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any] | None:
    """
    Decodes and validates a JWT access token.
    Returns the payload dict if valid, or None if expired/invalid.
    """
    try:
        return jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
    except jwt.PyJWTError:
        return None
