import uuid
from datetime import datetime, timezone
from typing import List, Optional, TYPE_CHECKING
from sqlalchemy import String, Boolean, text, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.token import RefreshToken, EmailVerificationToken, PasswordResetToken, LoginToken, PendingTOTPSetup, TwoFactorAttempt


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_email_verified: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false"), nullable=False
    )
    totp_secret: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    is_2fa_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false"), nullable=False
    )
    
    # Using DateTime(timezone=True) maps to TIMESTAMPTZ in PostgreSQL
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("TIMEZONE('utc', NOW())"),
    )
    # onupdate runs on the Python/ORM side and produces a timezone-aware UTC
    # timestamp, consistent with the rest of the codebase. (A bare
    # server_onupdate would not fire on UPDATE without a DB trigger, so it is
    # intentionally omitted.)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("TIMEZONE('utc', NOW())"),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships (one-to-many, cascade delete)
    refresh_tokens: Mapped[List["RefreshToken"]] = relationship(
        "RefreshToken",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    email_verification_tokens: Mapped[List["EmailVerificationToken"]] = relationship(
        "EmailVerificationToken",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    password_reset_tokens: Mapped[List["PasswordResetToken"]] = relationship(
        "PasswordResetToken",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    login_tokens: Mapped[List["LoginToken"]] = relationship(
        "LoginToken",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    pending_totp_setup: Mapped[Optional["PendingTOTPSetup"]] = relationship(
        "PendingTOTPSetup",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        uselist=False,
    )
    two_factor_attempt: Mapped[Optional["TwoFactorAttempt"]] = relationship(
        "TwoFactorAttempt",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        uselist=False,
    )
