from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models.user import User
from app.api.deps import get_current_user
from app.schemas.user import UserRegister, UserResponse
from app.schemas.auth import UserLogin, LoginResponse, TokenResponse
from app.schemas.totp import TOTPSetupResponse, TOTPEnableRequest, TOTPVerifyRequest
from app.services.user import UserService, EmailAlreadyRegisteredError
from app.services.auth import AuthService, InvalidCredentialsError
from app.services.totp import (
    TOTPService,
    MFAAlreadyEnabledError,
    NoPendingSetupError,
    PendingSetupExpiredError,
    InvalidTOTPCodeError,
    InvalidLoginTokenError,
    ExpiredLoginTokenError,
    LoginTokenAlreadyUsedError,
)

router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserRegister,
    db: AsyncSession = Depends(get_db),
):
    """
    Endpoint to register a new user.
    
    Returns 201 Created on success, 409 Conflict if email is already taken,
    and automatically returns 422 if input validation fails.
    """
    user_service = UserService(db)
    try:
        user = await user_service.register_user(user_data)
        return user
    except EmailAlreadyRegisteredError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered.",
        )
    except Exception:
        # Avoid exposing raw DB/system tracebacks to the client (500)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred. Please try again later.",
        )


@router.post("/login", response_model=LoginResponse, status_code=status.HTTP_200_OK)
async def login(
    credentials: UserLogin,
    db: AsyncSession = Depends(get_db),
):
    """
    Endpoint to authenticate a user.
    
    Returns a set of JWT access and refresh tokens if 2FA is disabled,
    or a temporary login token if 2FA is enabled.
    """
    auth_service = AuthService(db)
    try:
        result = await auth_service.login(
            email=credentials.email,
            password=credentials.password
        )
        return result
    except InvalidCredentialsError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred. Please try again later.",
        )


@router.post("/2fa/setup", response_model=TOTPSetupResponse, status_code=status.HTTP_200_OK)
async def setup_2fa(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Endpoint to begin the Authenticator App 2FA setup process.
    Generates a secure secret, provisioning URI, and Base64 QR code.
    """
    totp_service = TOTPService(db)
    try:
        setup_data = await totp_service.initiate_setup(current_user)
        return setup_data
    except MFAAlreadyEnabledError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Two-factor authentication is already enabled.",
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while setting up 2FA.",
        )


@router.post("/2fa/enable", status_code=status.HTTP_200_OK)
async def enable_2fa(
    payload: TOTPEnableRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Endpoint to confirm and enable two-factor authentication.
    Verifies the TOTP code against the pending setup.
    """
    totp_service = TOTPService(db)
    try:
        await totp_service.enable_2fa(current_user, payload.code)
        return {"message": "Two-factor authentication enabled successfully. Existing refresh tokens have been revoked. Please log in again after your current session expires."}
    except MFAAlreadyEnabledError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Two-factor authentication is already enabled.",
        )
    except NoPendingSetupError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending 2FA setup found. Please initiate setup first.",
        )
    except PendingSetupExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Pending 2FA setup has expired. Please initiate setup again.",
        )
    except InvalidTOTPCodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid two-factor authentication code.",
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while enabling 2FA.",
        )


@router.post("/2fa/verify", response_model=TokenResponse, status_code=status.HTTP_200_OK)
async def verify_2fa(
    payload: TOTPVerifyRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Endpoint to verify 2FA login using the temporary login token
    and a 6-digit TOTP code. If verified, issues final session JWTs.
    """
    totp_service = TOTPService(db)
    try:
        tokens = await totp_service.verify_login_2fa(
            login_token_plain=payload.login_token,
            code=payload.code
        )
        return tokens
    except InvalidLoginTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid login token or user account configuration.",
        )
    except ExpiredLoginTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login token has expired. Please log in again.",
        )
    except LoginTokenAlreadyUsedError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login token has already been used.",
        )
    except InvalidTOTPCodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid two-factor authentication code.",
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during 2FA verification.",
        )
