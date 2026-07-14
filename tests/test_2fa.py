from datetime import datetime, timedelta, timezone

import pyotp
import pytest
from sqlalchemy import select

from app.config.settings import settings
from app.db.models.user import User
from app.db.models.token import RefreshToken, TwoFactorAttempt

# Shared fixtures (db_session, client) live in tests/conftest.py.

PASSWORD = "StrongPass1!"


async def _enable_2fa(client, email):
    """
    Register -> login -> setup -> enable 2FA.
    Returns (access_token, totp_secret). The access token predates 2FA but
    stays valid (stateless JWT), so it authenticates the disable call.
    """
    r = await client.post(
        "/auth/register", json={"name": "TFA User", "email": email, "password": PASSWORD}
    )
    assert r.status_code == 201, r.text

    login = await client.post("/auth/login", json={"email": email, "password": PASSWORD})
    access = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {access}"}

    setup = await client.post("/auth/2fa/setup", headers=headers)
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]

    enable = await client.post(
        "/auth/2fa/enable", json={"code": pyotp.TOTP(secret).now()}, headers=headers
    )
    assert enable.status_code == 200, enable.text
    return access, secret


# ---------------------------------------------------------------------------
# Success + state changes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disable_success_clears_state_and_revokes_tokens(client, db_session):
    access, secret = await _enable_2fa(client, "disable_ok@example.com")
    headers = {"Authorization": f"Bearer {access}"}

    resp = await client.post(
        "/auth/2fa/disable",
        json={"password": PASSWORD, "code": pyotp.TOTP(secret).now()},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert "disabled successfully" in resp.json()["message"].lower()

    user = (
        await db_session.execute(select(User).where(User.email == "disable_ok@example.com"))
    ).scalar_one()
    assert user.is_2fa_enabled is False
    assert user.totp_secret is None

    # All refresh tokens for the user must be revoked (symmetric with enable).
    rts = (
        await db_session.execute(select(RefreshToken).where(RefreshToken.user_id == user.id))
    ).scalars().all()
    assert len(rts) > 0
    assert all(rt.revoked_at is not None for rt in rts)


@pytest.mark.asyncio
async def test_login_no_longer_requires_2fa_after_disable(client):
    access, secret = await _enable_2fa(client, "relogin@example.com")
    headers = {"Authorization": f"Bearer {access}"}

    await client.post(
        "/auth/2fa/disable",
        json={"password": PASSWORD, "code": pyotp.TOTP(secret).now()},
        headers=headers,
    )

    login = await client.post("/auth/login", json={"email": "relogin@example.com", "password": PASSWORD})
    assert login.status_code == 200
    body = login.json()
    assert "access_token" in body
    assert "requires_2fa" not in body


@pytest.mark.asyncio
async def test_can_re_setup_2fa_after_disable(client):
    access, secret = await _enable_2fa(client, "resetup@example.com")
    headers = {"Authorization": f"Bearer {access}"}

    await client.post(
        "/auth/2fa/disable",
        json={"password": PASSWORD, "code": pyotp.TOTP(secret).now()},
        headers=headers,
    )
    # setup must work again (no "already enabled").
    resp = await client.post("/auth/2fa/setup", headers=headers)
    assert resp.status_code == 200, resp.text


# ---------------------------------------------------------------------------
# Failure / validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disable_requires_authentication(client):
    resp = await client.post("/auth/2fa/disable", json={"password": PASSWORD, "code": "123456"})
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_disable_rejects_bad_code_format(client):
    access, _ = await _enable_2fa(client, "badfmt@example.com")
    headers = {"Authorization": f"Bearer {access}"}
    resp = await client.post(
        "/auth/2fa/disable", json={"password": PASSWORD, "code": "abc"}, headers=headers
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_disable_when_not_enabled(client):
    # Register + login, but never enable 2FA.
    await client.post(
        "/auth/register", json={"name": "No TFA", "email": "no2fa@example.com", "password": PASSWORD}
    )
    login = await client.post("/auth/login", json={"email": "no2fa@example.com", "password": PASSWORD})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    resp = await client.post(
        "/auth/2fa/disable", json={"password": PASSWORD, "code": "123456"}, headers=headers
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Two-factor authentication is not enabled."


@pytest.mark.asyncio
async def test_disable_wrong_password(client):
    access, secret = await _enable_2fa(client, "wrongpw@example.com")
    headers = {"Authorization": f"Bearer {access}"}
    resp = await client.post(
        "/auth/2fa/disable",
        json={"password": "WrongPass9!", "code": pyotp.TOTP(secret).now()},
        headers=headers,
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Invalid password."


@pytest.mark.asyncio
async def test_disable_wrong_code_increments_counter(client, db_session):
    access, _ = await _enable_2fa(client, "wrongcode@example.com")
    headers = {"Authorization": f"Bearer {access}"}

    resp = await client.post(
        "/auth/2fa/disable", json={"password": PASSWORD, "code": "000000"}, headers=headers
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Invalid two-factor authentication code."

    user = (
        await db_session.execute(select(User).where(User.email == "wrongcode@example.com"))
    ).scalar_one()
    row = (
        await db_session.execute(
            select(TwoFactorAttempt).where(TwoFactorAttempt.user_id == user.id)
        )
    ).scalar_one()
    assert row.failed_attempts == 1
    assert row.locked_until is None
    # 2FA is still enabled after a failed attempt.
    assert user.is_2fa_enabled is True


# ---------------------------------------------------------------------------
# Lockout + decay
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disable_locks_after_max_attempts(client, db_session):
    access, secret = await _enable_2fa(client, "lockout@example.com")
    headers = {"Authorization": f"Bearer {access}"}

    max_attempts = settings.MFA_DISABLE_MAX_ATTEMPTS
    statuses = []
    for _ in range(max_attempts):
        r = await client.post(
            "/auth/2fa/disable", json={"password": PASSWORD, "code": "000000"}, headers=headers
        )
        statuses.append(r.status_code)

    # First (max-1) are 400; the one that hits the cap is 429.
    assert statuses[:-1] == [400] * (max_attempts - 1)
    assert statuses[-1] == 429

    # Even a CORRECT code is now rejected with 429 while locked.
    locked = await client.post(
        "/auth/2fa/disable",
        json={"password": PASSWORD, "code": pyotp.TOTP(secret).now()},
        headers=headers,
    )
    assert locked.status_code == 429
    assert "Retry-After" in locked.headers

    # 2FA remains enabled - lockout prevented the disable.
    user = (
        await db_session.execute(select(User).where(User.email == "lockout@example.com"))
    ).scalar_one()
    assert user.is_2fa_enabled is True


@pytest.mark.asyncio
async def test_disable_attempt_decay_resets_stale_counter(client, db_session):
    access, _ = await _enable_2fa(client, "decay@example.com")
    headers = {"Authorization": f"Bearer {access}"}

    # One real failure to create the row.
    await client.post(
        "/auth/2fa/disable", json={"password": PASSWORD, "code": "000000"}, headers=headers
    )

    user = (
        await db_session.execute(select(User).where(User.email == "decay@example.com"))
    ).scalar_one()
    row = (
        await db_session.execute(
            select(TwoFactorAttempt).where(TwoFactorAttempt.user_id == user.id)
        )
    ).scalar_one()

    # Simulate 4 accumulated failures that are older than the decay window.
    stale = datetime.now(timezone.utc) - timedelta(
        minutes=settings.MFA_DISABLE_LOCKOUT_MINUTES + 5
    )
    row.failed_attempts = 4
    row.last_failed_at = stale
    await db_session.commit()

    # A new failure should DECAY the stale count to 0, then increment to 1
    # (not lock, despite 4 + 1 == 5 without decay).
    resp = await client.post(
        "/auth/2fa/disable", json={"password": PASSWORD, "code": "000000"}, headers=headers
    )
    assert resp.status_code == 400

    await db_session.refresh(row)
    assert row.failed_attempts == 1
    assert row.locked_until is None
