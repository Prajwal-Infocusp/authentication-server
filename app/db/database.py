from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from app.config.settings import settings

# Create async database engine
# We set pool_pre_ping=True to check connection health, and customize pool sizes for production
engine = create_async_engine(
    settings.ASYNC_DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    pool_size=20,
    max_overflow=10,
)

# Async session factory
SessionLocal = async_sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,  # Recommended: prevents fetching attributes of committed instances
)

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency for generating request-scoped database sessions.
    Using an async context manager ensures that the session is properly closed 
    even in case of exceptions.
    """
    async with SessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
