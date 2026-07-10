import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.main import app
from app.db.database import get_db
from app.config.settings import settings

# Setup a test async engine and session factory
test_engine = create_async_engine(settings.ASYNC_DATABASE_URL, echo=False)
TestSessionLocal = async_sessionmaker(
    bind=test_engine,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)


@pytest.fixture(scope="function")
async def db_session():
    """
    Fixture that yields an AsyncSession inside a rolled-back transaction.
    This guarantees that test data is never persisted to the database.
    """
    async with test_engine.begin() as conn:
        session = TestSessionLocal(bind=conn)
        yield session
        await session.close()
        await conn.rollback()  # Rollback transaction to clean up test data


@pytest.fixture(scope="function")
async def client(db_session):
    """
    Fixture that returns an AsyncClient with the get_db dependency overridden.
    """
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    # In modern HTTPX, we use ASGITransport to point to the ASGI app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_register_success(client):
    payload = {
        "name": "   Jane Doe   ",  # whitespace to test trimming
        "email": "JANE@example.com",  # mixed case to test normalization
        "password": "StrongPassword123!"
    }
    response = await client.post("/auth/register", json=payload)
    assert response.status_code == 201
    
    data = response.json()
    assert data["name"] == "Jane Doe"  # verified stripped name
    assert data["email"] == "jane@example.com"  # verified lowercased email
    assert "id" in data
    assert data["is_email_verified"] is False
    assert data["is_2fa_enabled"] is False
    assert "password" not in data
    assert "password_hash" not in data
    assert "totp_secret" not in data


@pytest.mark.asyncio
async def test_register_duplicate_email(client):
    payload = {
        "name": "Jane Doe",
        "email": "jane_dup@example.com",
        "password": "StrongPassword123!"
    }
    # First registration
    response = await client.post("/auth/register", json=payload)
    assert response.status_code == 201
    
    # Second registration with same email
    response2 = await client.post("/auth/register", json=payload)
    assert response2.status_code == 409
    assert response2.json() == {"detail": "Email already registered."}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name,email,password",
    [
        # Weak password (no uppercase, no special, etc.)
        ("Jane Doe", "jane_weak@example.com", "simple12"),
        # Short password
        ("Jane Doe", "jane_short@example.com", "S1!a"),
        # Password too long (> 128)
        ("Jane Doe", "jane_long@example.com", "StrongPassword123!" * 10),
        # Short name
        ("J", "jane_short_name@example.com", "StrongPassword123!"),
        # Name too long (> 100)
        ("J" * 101, "jane_long_name@example.com", "StrongPassword123!"),
        # Invalid email
        ("Jane Doe", "not-an-email", "StrongPassword123!"),
    ]
)
async def test_register_validation_errors(client, name, email, password):
    payload = {
        "name": name,
        "email": email,
        "password": password
    }
    response = await client.post("/auth/register", json=payload)
    assert response.status_code == 422
