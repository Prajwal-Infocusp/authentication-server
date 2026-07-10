from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.schemas.user import UserRegister, UserResponse
from app.services.user import UserService, EmailAlreadyRegisteredError

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
