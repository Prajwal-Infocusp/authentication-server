from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError

from app.db.models.user import User
from app.db.repositories.user import UserRepository
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
        self.user_repo = UserRepository(db)

    async def register_user(self, user_data: UserRegister) -> User:
        """
        Registers a new user in the database.

        Flow:
        1. Check if email exists -> raise EmailAlreadyRegisteredError
        2. Hash password using bcrypt
        3. Save to database, commit, refresh, and return

        The unique constraint on users.email is also enforced at the database
        level: if two requests race past the existence check, the losing insert
        raises IntegrityError, which is translated into EmailAlreadyRegisteredError
        (409) rather than surfacing as a generic 500.
        """
        # 1. Check if user already exists
        existing_user = await self.user_repo.get_by_email(user_data.email)
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
            await self.user_repo.create(new_user)
            await self.db.commit()
            await self.db.refresh(new_user)
            return new_user
        except IntegrityError:
            # Lost a race with a concurrent registration of the same email.
            await self.db.rollback()
            raise EmailAlreadyRegisteredError()
        except Exception as e:
            await self.db.rollback()
            raise e
