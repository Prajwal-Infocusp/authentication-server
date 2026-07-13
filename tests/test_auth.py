import pytest

# Shared fixtures (db_session, client) live in tests/conftest.py.


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
