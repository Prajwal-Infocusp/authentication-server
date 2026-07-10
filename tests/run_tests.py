import asyncio
import hashlib
import base64
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select
import pyotp

from app.main import app
from app.db.database import engine, SessionLocal
from app.db.base import Base
from app.db.models.user import User
from app.db.models.token import RefreshToken, LoginToken, PendingTOTPSetup


async def run_tests():
    print("==================================================")
    print("Running Authentication & 2FA Service Integration Tests...")
    print("==================================================")
    
    # 0. Clean up tables
    async with engine.begin() as conn:
        await conn.execute(Base.metadata.tables["pending_totp_setups"].delete())
        await conn.execute(Base.metadata.tables["login_tokens"].delete())
        await conn.execute(Base.metadata.tables["refresh_tokens"].delete())
        await conn.execute(Base.metadata.tables["users"].delete())
        print("Cleaned up database tables.")
        
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        
        # Setup: Register a user
        reg_payload = {
            "name": "John Doe",
            "email": "john@example.com",
            "password": "StrongPassword123!"
        }
        print("\nSetting up test user...")
        reg_res = await client.post("/auth/register", json=reg_payload)
        assert reg_res.status_code == 201
        print("-> Test user registered successfully.")

        # Test Case 1: Login with 2FA Disabled
        print("\nRunning Test 1: Login (2FA Disabled)...")
        login_payload = {
            "email": "john@example.com",
            "password": "StrongPassword123!"
        }
        res = await client.post("/auth/login", json=login_payload)
        assert res.status_code == 200
        login_data = res.json()
        assert "access_token" in login_data
        assert "refresh_token" in login_data
        access_token = login_data["access_token"]
        auth_headers = {"Authorization": f"Bearer {access_token}"}
        print("-> SUCCESS: Standard tokens returned.")

        # Test Case 2: Initiate 2FA Setup
        print("\nRunning Test 2: Initiate 2FA Setup...")
        res = await client.post("/auth/2fa/setup", headers=auth_headers)
        assert res.status_code == 200, f"Failed: {res.text}"
        setup_data = res.json()
        
        assert "secret" in setup_data
        assert "otpauth_url" in setup_data
        assert "qr_code" in setup_data
        
        secret = setup_data["secret"]
        # Verify base64 QR code format and prefix
        qr_string = setup_data["qr_code"]
        assert qr_string.startswith("data:image/png;base64,")
        raw_b64 = qr_string.replace("data:image/png;base64,", "")
        try:
            base64.b64decode(raw_b64)
            is_valid_base64 = True
        except Exception:
            is_valid_base64 = False
        assert is_valid_base64 is True, "Failed: QR code body is not valid base64"
        
        # Verify pending setup was saved to database
        async with SessionLocal() as session:
            stmt = select(PendingTOTPSetup)
            result = await session.execute(stmt)
            db_setups = result.scalars().all()
            assert len(db_setups) == 1, "Failed: pending setup row not found"
            assert db_setups[0].secret == secret, "Failed: saved secret mismatch"
            
        print("-> SUCCESS: 2FA setup generated secret, otpauth URL, and base64 QR code.")

        # Test Case 3: Re-initiating Setup Replaces Previous (No Duplicates)
        print("\nRunning Test 3: Re-initiating Setup Replaces Previous Setup...")
        res = await client.post("/auth/2fa/setup", headers=auth_headers)
        assert res.status_code == 200
        setup_data_2 = res.json()
        secret_2 = setup_data_2["secret"]
        
        assert secret != secret_2, "Failed: new secret should be different"
        
        async with SessionLocal() as session:
            stmt = select(PendingTOTPSetup)
            result = await session.execute(stmt)
            db_setups = result.scalars().all()
            # Verify there is still only 1 row in the table
            assert len(db_setups) == 1, f"Failed: expected 1 pending setup row, got {len(db_setups)}"
            assert db_setups[0].secret == secret_2, "Failed: secret was not updated in db"
            
        print("-> SUCCESS: Existing pending setup replaced successfully. Uniqueness enforced.")

        # Test Case 4: Enable 2FA with Code
        print("\nRunning Test 4: Enable 2FA with Verification Code...")
        # Generate code from the pending secret using pyotp
        totp = pyotp.TOTP(secret_2)
        current_code = totp.now()
        
        # 4a. Verify with bad code fails
        res = await client.post("/auth/2fa/enable", json={"code": "000000"}, headers=auth_headers)
        assert res.status_code == 400
        assert res.json()["detail"] == "Invalid two-factor authentication code."
        
        # 4b. Verify with correct code succeeds
        res = await client.post("/auth/2fa/enable", json={"code": current_code}, headers=auth_headers)
        assert res.status_code == 200
        assert res.json()["message"] == "Two-factor authentication enabled successfully. Existing refresh tokens have been revoked. Please log in again after your current session expires."
        
        # Verify user is updated in database, pending setup is deleted, and refresh tokens are revoked
        async with SessionLocal() as session:
            stmt = select(User).where(User.email == "john@example.com")
            result = await session.execute(stmt)
            db_user = result.scalar_one()
            assert db_user.is_2fa_enabled is True
            assert db_user.totp_secret == secret_2
            
            stmt_setup = select(PendingTOTPSetup)
            result_setup = await session.execute(stmt_setup)
            assert result_setup.scalar_one_or_none() is None, "Failed: pending setup row was not deleted"
            
            # Verify all previous refresh tokens are marked as revoked
            stmt_rt = select(RefreshToken).where(RefreshToken.user_id == db_user.id)
            result_rt = await session.execute(stmt_rt)
            db_rts = result_rt.scalars().all()
            assert len(db_rts) > 0, "Failed: no refresh tokens found to verify revocation"
            for rt in db_rts:
                assert rt.revoked_at is not None, "Failed: refresh token was not revoked when 2FA was enabled"
            
        print("-> SUCCESS: 2FA verified, enabled, pending setup cleaned up, and active refresh tokens revoked.")

        # Test Case 5: Setup or Enable when 2FA already enabled fails
        print("\nRunning Test 5: Re-setup or Re-enable when 2FA is active...")
        res = await client.post("/auth/2fa/setup", headers=auth_headers)
        assert res.status_code == 400
        assert res.json()["detail"] == "Two-factor authentication is already enabled."
        
        res = await client.post("/auth/2fa/enable", json={"code": current_code}, headers=auth_headers)
        assert res.status_code == 400
        assert res.json()["detail"] == "Two-factor authentication is already enabled."
        print("-> SUCCESS: Correctly rejected.")

        # Test Case 6: Login with 2FA Enabled (Step 1)
        print("\nRunning Test 6: Login with 2FA Enabled (Step 1)...")
        res = await client.post("/auth/login", json=login_payload)
        assert res.status_code == 200
        login_data_2fa = res.json()
        
        assert login_data_2fa["requires_2fa"] is True
        assert "login_token" in login_data_2fa
        assert "access_token" not in login_data_2fa
        login_token = login_data_2fa["login_token"]
        print("-> SUCCESS: Login returned requires_2fa=True and temporary login token.")

        # Test Case 7: Verify Login 2FA (Step 2)
        print("\nRunning Test 7: Verify Login 2FA (Step 2)...")
        current_code_2 = totp.now()
        
        # 7a. Verify with bad code fails
        res = await client.post(
            "/auth/2fa/verify", 
            json={"login_token": login_token, "code": "000000"}
        )
        assert res.status_code == 400
        assert res.json()["detail"] == "Invalid two-factor authentication code."
        
        # 7b. Verify with correct code succeeds and issues tokens
        res = await client.post(
            "/auth/2fa/verify", 
            json={"login_token": login_token, "code": current_code_2}
        )
        assert res.status_code == 200, f"Failed: {res.text}"
        token_data = res.json()
        assert "access_token" in token_data
        assert "refresh_token" in token_data
        assert token_data["token_type"] == "Bearer"
        assert token_data["expires_in"] == 900
        
        # Verify login token is marked used
        hashed_lt = hashlib.sha256(login_token.encode("utf-8")).hexdigest()
        async with SessionLocal() as session:
            stmt = select(LoginToken).where(LoginToken.token_hash == hashed_lt)
            result = await session.execute(stmt)
            db_lt = result.scalar_one()
            assert db_lt.used_at is not None, "Failed: login token not marked used"
            
        print("-> SUCCESS: Issued final access/refresh tokens and marked login token as used.")

        # Test Case 8: Reuse of Login Token is Rejected
        print("\nRunning Test 8: Prevent Login Token Reuse...")
        res = await client.post(
            "/auth/2fa/verify", 
            json={"login_token": login_token, "code": totp.now()}
        )
        assert res.status_code == 401
        assert res.json()["detail"] == "Login token has already been used."
        print("-> SUCCESS: Rejected reuse attempt.")
        
    await engine.dispose()
    print("\n==================================================")
    print("ALL TESTS PASSED SUCCESSFULLY!")
    print("==================================================")

if __name__ == "__main__":
    asyncio.run(run_tests())
