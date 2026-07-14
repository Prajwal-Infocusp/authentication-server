import uuid
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.db.models.token import RefreshToken, LoginToken, PendingTOTPSetup


class TokenRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_refresh_token(
        self, user_id: uuid.UUID, token_hash: str, expires_at: datetime
    ) -> RefreshToken:
        """
        Creates and persists a new RefreshToken in the database.
        """
        db_token = RefreshToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
        )
        self.db.add(db_token)
        return db_token

    async def get_refresh_token_by_hash(self, token_hash: str) -> RefreshToken | None:
        """
        Retrieves a RefreshToken by its SHA-256 hash.
        """
        stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def revoke_refresh_token(self, refresh_token: RefreshToken) -> None:
        """
        Revokes a single refresh token by setting revoked_at to the current UTC time.
        """
        refresh_token.revoked_at = datetime.now(timezone.utc)

    async def create_login_token(
        self, user_id: uuid.UUID, token_hash: str, expires_at: datetime
    ) -> LoginToken:
        """
        Creates and persists a new LoginToken in the database.
        """
        db_token = LoginToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
        )
        self.db.add(db_token)
        return db_token

    async def get_login_token_by_hash(self, token_hash: str) -> LoginToken | None:
        """
        Retrieves a LoginToken by its SHA-256 hash.
        """
        stmt = select(LoginToken).where(LoginToken.token_hash == token_hash)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def mark_login_token_used(self, login_token: LoginToken) -> None:
        """
        Marks a login token as used by setting used_at to current UTC time.
        """
        login_token.used_at = datetime.now(timezone.utc)

    async def increment_login_token_attempts(self, login_token: LoginToken) -> int:
        """
        Increments the failed-verification counter on a login token and returns
        the new value.
        """
        login_token.attempts = (login_token.attempts or 0) + 1
        return login_token.attempts

    async def invalidate_unused_login_tokens(self, user_id: uuid.UUID) -> None:
        """
        Marks all of a user's currently-unused login tokens as used. Called when
        issuing a fresh login token so at most one login token is ever active
        per user, bounding the number of TOTP guesses an attacker can make.
        """
        stmt = (
            update(LoginToken)
            .where(LoginToken.user_id == user_id)
            .where(LoginToken.used_at.is_(None))
            .values(used_at=datetime.now(timezone.utc))
        )
        await self.db.execute(stmt)

    async def create_or_update_pending_totp_setup(
        self, user_id: uuid.UUID, secret: str, expires_at: datetime
    ) -> PendingTOTPSetup:
        """
        Creates a new pending TOTP setup for a user. If a pending setup already
        exists, it updates the secret and expiration, enforcing the uniqueness
        constraint and preventing multiple setup rows.
        """
        stmt = select(PendingTOTPSetup).where(PendingTOTPSetup.user_id == user_id)
        result = await self.db.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            existing.secret = secret
            existing.expires_at = expires_at
            existing.created_at = datetime.now(timezone.utc)
            return existing
        else:
            db_setup = PendingTOTPSetup(
                user_id=user_id,
                secret=secret,
                expires_at=expires_at,
            )
            self.db.add(db_setup)
            return db_setup

    async def get_pending_totp_setup(self, user_id: uuid.UUID) -> PendingTOTPSetup | None:
        """
        Retrieves the pending TOTP setup for a user.
        """
        stmt = select(PendingTOTPSetup).where(PendingTOTPSetup.user_id == user_id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def delete_pending_totp_setup(self, pending_setup: PendingTOTPSetup) -> None:
        """
        Deletes a pending TOTP setup record.
        """
        await self.db.delete(pending_setup)

    async def revoke_user_refresh_tokens(self, user_id: uuid.UUID) -> None:
        """
        Revokes all active (unrevoked) refresh tokens for the given user
        by setting revoked_at to the current UTC timestamp.
        """
        stmt = (
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id)
            .where(RefreshToken.revoked_at.is_(None))
            .values(revoked_at=datetime.now(timezone.utc))
        )
        await self.db.execute(stmt)
