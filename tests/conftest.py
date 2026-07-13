import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.pool import NullPool

from app.main import app
from app.db.database import get_db
from app.config.settings import settings


@pytest_asyncio.fixture
async def db_session():
    """
    Yields an AsyncSession joined to an outer transaction via SAVEPOINTs.

    The application services call ``session.commit()`` themselves. By binding
    the session to a live connection that already has an outer transaction open
    and using ``join_transaction_mode="create_savepoint"``, those commits only
    release savepoints - the outer transaction is rolled back at teardown, so
    no test data ever persists to the database (true per-test isolation).

    A fresh ``NullPool`` engine is created per test so connections are never
    cached and reused across event loops (pytest-asyncio uses a new loop per
    test), which previously caused ``got Future attached to a different loop``
    errors surfacing as spurious 500s.
    """
    engine = create_async_engine(settings.ASYNC_DATABASE_URL, poolclass=NullPool)
    async with engine.connect() as connection:
        transaction = await connection.begin()
        session = AsyncSession(
            bind=connection,
            join_transaction_mode="create_savepoint",
            expire_on_commit=False,
        )
        try:
            yield session
        finally:
            await session.close()
            if transaction.is_active:
                await transaction.rollback()
    await engine.dispose()


@pytest_asyncio.fixture
async def client(db_session):
    """
    AsyncClient wired to the ASGI app with the get_db dependency overridden to
    reuse the isolated, savepoint-bound test session.
    """
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
    app.dependency_overrides.clear()
