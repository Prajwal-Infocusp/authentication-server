from typing import Optional, Union
from pydantic import BaseModel, EmailStr, Field, field_validator
from pydantic_core import PydanticCustomError

from app.schemas.user import validate_password_strength


class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)

    @field_validator("email", mode="after")
    @classmethod
    def lowercase_email(cls, v: EmailStr) -> EmailStr:
        return v.lower()


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=1)


class LogoutRequest(BaseModel):
    """
    Revoke refresh tokens. The user is identified from the supplied refresh
    token, so no access token is required. When ``all_sessions`` is true, every
    active refresh token for that user is revoked; otherwise only the supplied
    token is revoked.
    """
    refresh_token: str = Field(..., min_length=1)
    all_sessions: bool = False


class MessageResponse(BaseModel):
    message: str


class PasswordChangeRequest(BaseModel):
    """
    Change the password of the authenticated user. ``code`` is required only
    when the user has 2FA enabled (enforced in the service, which has the user
    object); it is optional at the schema level.
    """
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=128)
    code: Optional[str] = Field(default=None, min_length=6, max_length=6, pattern=r"^\d{6}$")

    @field_validator("new_password")
    @classmethod
    def _check_new_password_strength(cls, v: str) -> str:
        return validate_password_strength(v)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int


class Login2FAResponse(BaseModel):
    requires_2fa: bool = True
    login_token: str


# Unified response model for the login endpoint
LoginResponse = Union[TokenResponse, Login2FAResponse]
