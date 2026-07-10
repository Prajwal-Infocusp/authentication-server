from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.models.user import User
from app.schemas.user import UserRegister
from app.security.password import hash_password


class EmailAlreadyRegisteredError(Exception):
    """
    Raised when attempting to register a user with an email that is already in use.
    """
    pass


class UserService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_user_by_email(self, email: str) -> User | None:
        """
        Retrieves a user by their email address.
        """
        stmt = select(User).where(User.email == email)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def register_user(self, user_data: UserRegister) -> User:
        """
        Registers a new user in the database.
        
        Flow:
        1. Check if email exists -> raise EmailAlreadyRegisteredError
        2. Hash password using bcrypt
        3. Save to database, commit, refresh, and return
        """
        # 1. Check if user already exists
        existing_user = await self.get_user_by_email(user_data.email)
        if existing_user:
            raise EmailAlreadyRegisteredError()

        # 2. Hash password
        hashed_pw = hash_password(user_data.password)

        # 3. Create new user instance
        new_user = User(
            name=user_data.name,
            email=user_data.email,
            password_hash=hashed_pw,
        )

        # 4. Insert and commit
        try:
            self.db.add(new_user)
            await self.db.commit()
            await self.db.refresh(new_user)
            return new_user
        except Exception as e:
            await self.db.rollback()
            raise e
