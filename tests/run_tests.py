import asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.db.database import engine
from app.db.base import Base

async def run_tests():
    print("==================================================")
    print("Running Registration Flow Integration Tests...")
    print("==================================================")
    
    # Clean up test users to guarantee a clean slate
    async with engine.begin() as conn:
        # Delete user rows
        await conn.execute(Base.metadata.tables["users"].delete())
        print("Cleaned up database 'users' table.")
        
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        
        # Test Case 1: Successful Registration
        # Also tests name trimming and email normalization to lowercase
        payload = {
            "name": "   Jane Doe   ",
            "email": "JANE@example.com",
            "password": "StrongPassword123!"
        }
        print("\nRunning Test 1: Successful Registration...")
        res = await client.post("/auth/register", json=payload)
        assert res.status_code == 201, f"Failed: Expected 201, got {res.status_code}: {res.text}"
        
        data = res.json()
        assert data["name"] == "Jane Doe", f"Failed: name not trimmed: {data['name']}"
        assert data["email"] == "jane@example.com", f"Failed: email not lowercased: {data['email']}"
        assert "id" in data, "Failed: 'id' key missing from response"
        assert data["is_email_verified"] is False, "Failed: is_email_verified should default to False"
        assert data["is_2fa_enabled"] is False, "Failed: is_2fa_enabled should default to False"
        assert "password" not in data, "Security leak: plain-text password returned"
        assert "password_hash" not in data, "Security leak: password_hash returned"
        assert "totp_secret" not in data, "Security leak: totp_secret returned"
        print("-> SUCCESS: User registered and returned sanitized response schema.")

        # Test Case 2: Duplicate Email
        print("\nRunning Test 2: Prevent Duplicate Email Registration...")
        res = await client.post("/auth/register", json=payload)
        assert res.status_code == 409, f"Failed: Expected 409 Conflict, got {res.status_code}: {res.text}"
        assert res.json() == {"detail": "Email already registered."}, f"Failed: unexpected detail message: {res.json()}"
        print("-> SUCCESS: Attempted duplicate registration was rejected with 409 Conflict.")

        # Test Case 3: Input Validation Constraints
        print("\nRunning Test 3: Input Validation Constraints (Pydantic schemas)...")
        validation_payloads = [
            # 3a. Weak password (no uppercase)
            {"name": "Jane Doe", "email": "jane_weak1@example.com", "password": "weakpassword123!"},
            # 3b. Weak password (no lowercase)
            {"name": "Jane Doe", "email": "jane_weak2@example.com", "password": "WEAKPASSWORD123!"},
            # 3c. Weak password (no digits)
            {"name": "Jane Doe", "email": "jane_weak3@example.com", "password": "WeakPassword!"},
            # 3d. Weak password (no special character)
            {"name": "Jane Doe", "email": "jane_weak4@example.com", "password": "WeakPassword123"},
            # 3e. Name too short
            {"name": "J", "email": "jane_short_name@example.com", "password": "StrongPassword123!"},
            # 3f. Invalid email format
            {"name": "Jane Doe", "email": "invalid-email-format", "password": "StrongPassword123!"},
        ]
        
        for idx, p in enumerate(validation_payloads, start=1):
            res = await client.post("/auth/register", json=p)
            assert res.status_code == 422, f"Failed sub-test 3.{idx}: Expected 422, got {res.status_code} for payload: {p}"
            
        print("-> SUCCESS: All weak passwords, short names, and invalid emails rejected with 422.")
        
    await engine.dispose()
    print("\n==================================================")
    print("ALL TESTS PASSED SUCCESSFULLY!")
    print("==================================================")

if __name__ == "__main__":
    asyncio.run(run_tests())
