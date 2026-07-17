import re
import uuid
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, field_validator, ConfigDict
from pydantic_core import PydanticCustomError


def validate_password_strength(v: str) -> str:
    """
    Shared password-strength check: at least one uppercase, lowercase, digit,
    and special character. Reused by every schema that accepts a password
    (registration, password change, ...). Length limits are enforced via the
    Field(min_length=8, max_length=128) constraint on each password field.
    """
    if not re.search(r"[A-Z]", v):
        raise PydanticCustomError(
            "value_error", "Password must contain at least one uppercase letter."
        )
    if not re.search(r"[a-z]", v):
        raise PydanticCustomError(
            "value_error", "Password must contain at least one lowercase letter."
        )
    if not re.search(r"\d", v):
        raise PydanticCustomError(
            "value_error", "Password must contain at least one digit."
        )
    if not re.search(r"[^A-Za-z0-9]", v):
        raise PydanticCustomError(
            "value_error", "Password must contain at least one special character."
        )
    return v


class UserRegister(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("name", mode="before")
    @classmethod
    def trim_name(cls, v: str) -> str:
        if isinstance(v, str):
            return v.strip()
        return v

    @field_validator("name")
    @classmethod
    def validate_name_length(cls, v: str) -> str:
        # Re-check the length constraint after trimming whitespace
        if len(v) < 2 or len(v) > 100:
            raise PydanticCustomError(
                "value_error", "Name must be between 2 and 100 characters."
            )
        return v

    @field_validator("email", mode="after")
    @classmethod
    def lowercase_email(cls, v: EmailStr) -> EmailStr:
        return v.lower()

    @field_validator("password")
    @classmethod
    def _check_password_strength(cls, v: str) -> str:
        return validate_password_strength(v)


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    email: EmailStr
    is_email_verified: bool
    is_2fa_enabled: bool
    created_at: datetime
