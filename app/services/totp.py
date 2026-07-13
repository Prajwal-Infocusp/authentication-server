import base64
import io
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict
import pyotp
import qrcode
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.settings import settings
from app.db.repositories.user import UserRepository
from app.db.repositories.token import TokenRepository
from app.db.models.user import User
from app.security.jwt import create_access_token


class MFAAlreadyEnabledError(Exception):
    """
    Raised when attempting to configure 2FA for a user who already has it enabled.
    """
    pass


class NoPendingSetupError(Exception):
    """
    Raised when verifying/enabling 2FA but no pending configuration exists.
    """
    pass


class PendingSetupExpiredError(Exception):
    """
    Raised when the pending setup window has expired.
    """
    pass


class InvalidTOTPCodeError(Exception):
    """
    Raised when the provided TOTP code is incorrect or out of sync.
    """
    pass


class InvalidLoginTokenError(Exception):
    """
    Raised when the provided temporary login token does not exist.
    """
    pass


class ExpiredLoginTokenError(Exception):
    """
    Raised when the temporary login token has expired.
    """
    pass


class LoginTokenAlreadyUsedError(Exception):
    """
    Raised when trying to use a login token that has already been consumed.
    """
    pass


class TOTPService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.user_repo = UserRepository(db)
        self.token_repo = TokenRepository(db)

    def _hash_token(self, token: str) -> str:
        """
        Helper method to hash high-entropy tokens with SHA-256.
        """
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    async def initiate_setup(self, user: User) -> Dict[str, Any]:
        """
        Initiates a new TOTP setup flow:
        1. Checks if 2FA is already enabled.
        2. Generates a cryptographically secure base32 secret.
        3. Constructs the otpauth:// URI.
        4. Generates a Base64-encoded QR code.
        5. Saves/overwrites the pending setup in pending_totp_setups.
        """
        if user.is_2fa_enabled:
            raise MFAAlreadyEnabledError()

        # Generate base32 secret
        secret = pyotp.random_base32()

        # Construct otpauth URI
        # Issuer and Email name are sanitized in the provisioning URI
        totp = pyotp.TOTP(secret)
        otpauth_url = totp.provisioning_uri(
            name=user.email, issuer_name=settings.PROJECT_NAME
        )

        # Generate QR code as Base64-encoded PNG image
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(otpauth_url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        qr_code_base64 = f"data:image/png;base64,{base64.b64encode(buffered.getvalue()).decode('utf-8')}"

        # Expiration default: 10 minutes
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

        try:
            await self.token_repo.create_or_update_pending_totp_setup(
                user_id=user.id, secret=secret, expires_at=expires_at
            )
            await self.db.commit()
        except Exception as e:
            await self.db.rollback()
            raise e

        return {
            "secret": secret,
            "otpauth_url": otpauth_url,
            "qr_code": qr_code_base64,
        }

    async def enable_2fa(self, user: User, code: str) -> None:
        """
        Confirms and enables 2FA for a user:
        1. Loads the pending setup.
        2. Verifies the TOTP code.
        3. Copies the secret to the User model.
        4. Sets is_2fa_enabled to True.
        5. Removes the pending setup.
        """
        if user.is_2fa_enabled:
            raise MFAAlreadyEnabledError()

        pending_setup = await self.token_repo.get_pending_totp_setup(user.id)
        if not pending_setup:
            raise NoPendingSetupError()

        if datetime.now(timezone.utc) > pending_setup.expires_at:
            raise PendingSetupExpiredError()

        # Verify code
        totp = pyotp.TOTP(pending_setup.secret)
        if not totp.verify(code):
            raise InvalidTOTPCodeError()

        # Update user and clean up pending setup
        user.totp_secret = pending_setup.secret
        user.is_2fa_enabled = True

        try:
            await self.token_repo.revoke_user_refresh_tokens(user.id)
            await self.token_repo.delete_pending_totp_setup(pending_setup)
            await self.db.commit()
        except Exception as e:
            await self.db.rollback()
            raise e

    async def verify_login_2fa(self, login_token_plain: str, code: str) -> Dict[str, Any]:
        """
        Verifies login step two using the temporary login token:
        1. Query and validate the temporary login token.
        2. Verify the user's TOTP code.
        3. Mark the login token as used.
        4. Issue final access and refresh tokens.
        """
        # 1. Fetch and validate login token
        hashed_lt = self._hash_token(login_token_plain)
        login_token = await self.token_repo.get_login_token_by_hash(hashed_lt)
        
        if not login_token:
            raise InvalidLoginTokenError()

        if login_token.used_at is not None:
            raise LoginTokenAlreadyUsedError()

        if datetime.now(timezone.utc) > login_token.expires_at:
            raise ExpiredLoginTokenError()

        # 2. Fetch and validate user
        user = await self.user_repo.get_by_id(login_token.user_id)
        if not user or not user.is_2fa_enabled or not user.totp_secret:
            raise InvalidLoginTokenError()

        # 3. Verify TOTP code. On failure, record the attempt and invalidate the
        #    login token once the allowed number of attempts is exhausted, so a
        #    single token cannot be used to brute-force the 6-digit TOTP code.
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(code):
            attempts = await self.token_repo.increment_login_token_attempts(login_token)
            if attempts >= settings.MAX_LOGIN_TOKEN_ATTEMPTS:
                await self.token_repo.mark_login_token_used(login_token)
            try:
                await self.db.commit()
            except Exception as e:
                await self.db.rollback()
                raise e
            raise InvalidTOTPCodeError()

        # 4. Success -> Mark token as used, issue JWT & refresh tokens
        await self.token_repo.mark_login_token_used(login_token)
        
        access_token = create_access_token(subject=user.id)
        plain_refresh_token = secrets.token_urlsafe(32)
        hashed_rt = self._hash_token(plain_refresh_token)
        expires_at = datetime.now(timezone.utc) + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )

        try:
            await self.token_repo.create_refresh_token(
                user_id=user.id,
                token_hash=hashed_rt,
                expires_at=expires_at,
            )
            await self.db.commit()
        except Exception as e:
            await self.db.rollback()
            raise e

        return {
            "access_token": access_token,
            "refresh_token": plain_refresh_token,
            "token_type": "Bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        }
