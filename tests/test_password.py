import pyotp
import pytest
from sqlalchemy import select

from app.config.settings import settings
from app.db.models.user import User
from app.db.models.token import RefreshToken

# Shared fixtures (db_session, client) live in tests/conftest.py.

OLD_PASSWORD = "OldStrongPass1!"
NEW_PASSWORD = "NewStrongPass9!"


async def _register_and_login(client, email, password=OLD_PASSWORD):
    r = await client.post(
        "/auth/register", json={"name": "PW User", "email": email, "password": password}
    )
    assert r.status_code == 201, r.text
    login = await client.post("/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200, login.text
    return login.json()  # access_token, refresh_token, ...


async def _enable_2fa(client, email):
    """Register + login + enable 2FA. Returns (access_token, secret)."""
    login = await _register_and_login(client, email)
    access = login["access_token"]
    headers = {"Authorization": f"Bearer {access}"}
    secret = (await client.post("/auth/2fa/setup", headers=headers)).json()["secret"]
    r = await client.post(
        "/auth/2fa/enable", json={"code": pyotp.TOTP(secret).now()}, headers=headers
    )
    assert r.status_code == 200, r.text
    return access, secret


# ---------------------------------------------------------------------------
# Success (no 2FA)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_change_password_success_no_2fa(client):
    login = await _register_and_login(client, "pw_ok@example.com")
    headers = {"Authorization": f"Bearer {login['access_token']}"}
    old_refresh = login["refresh_token"]

    resp = await client.post(
        "/auth/change-password",
        json={"current_password": OLD_PASSWORD, "new_password": NEW_PASSWORD},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["access_token"] and body["refresh_token"]
    assert body["token_type"] == "Bearer"

    # Old refresh token was revoked; the freshly returned one works.
    assert (await client.post("/auth/refresh", json={"refresh_token": old_refresh})).status_code == 401
    assert (await client.post("/auth/refresh", json={"refresh_token": body["refresh_token"]})).status_code == 200

    # Old password no longer logs in; new one does.
    assert (await client.post("/auth/login", json={"email": "pw_ok@example.com", "password": OLD_PASSWORD})).status_code == 401
    assert (await client.post("/auth/login", json={"email": "pw_ok@example.com", "password": NEW_PASSWORD})).status_code == 200


@pytest.mark.asyncio
async def test_change_password_revokes_all_refresh_tokens(client, db_session):
    await client.post(
        "/auth/register", json={"name": "PW", "email": "pw_revoke@example.com", "password": OLD_PASSWORD}
    )
    # Two sessions/devices.
    s1 = (await client.post("/auth/login", json={"email": "pw_revoke@example.com", "password": OLD_PASSWORD})).json()
    s2 = (await client.post("/auth/login", json={"email": "pw_revoke@example.com", "password": OLD_PASSWORD})).json()
    headers = {"Authorization": f"Bearer {s1['access_token']}"}

    resp = await client.post(
        "/auth/change-password",
        json={"current_password": OLD_PASSWORD, "new_password": NEW_PASSWORD},
        headers=headers,
    )
    assert resp.status_code == 200

    # Both pre-change refresh tokens are dead.
    assert (await client.post("/auth/refresh", json={"refresh_token": s1["refresh_token"]})).status_code == 401
    assert (await client.post("/auth/refresh", json={"refresh_token": s2["refresh_token"]})).status_code == 401

    user = (
        await db_session.execute(select(User).where(User.email == "pw_revoke@example.com"))
    ).scalar_one()
    # Exactly one active (unrevoked) refresh token remains: the freshly issued one.
    rts = (
        await db_session.execute(select(RefreshToken).where(RefreshToken.user_id == user.id))
    ).scalars().all()
    active = [rt for rt in rts if rt.revoked_at is None]
    assert len(active) == 1


# ---------------------------------------------------------------------------
# Success (2FA enabled)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_change_password_success_with_2fa(client):
    access, secret = await _enable_2fa(client, "pw_2fa@example.com")
    headers = {"Authorization": f"Bearer {access}"}

    resp = await client.post(
        "/auth/change-password",
        json={
            "current_password": OLD_PASSWORD,
            "new_password": NEW_PASSWORD,
            "code": pyotp.TOTP(secret).now(),
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["access_token"]


@pytest.mark.asyncio
async def test_change_password_2fa_missing_code(client):
    access, _ = await _enable_2fa(client, "pw_2fa_nocode@example.com")
    headers = {"Authorization": f"Bearer {access}"}

    resp = await client.post(
        "/auth/change-password",
        json={"current_password": OLD_PASSWORD, "new_password": NEW_PASSWORD},
        headers=headers,
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Two-factor authentication code is required."


@pytest.mark.asyncio
async def test_change_password_2fa_wrong_code(client):
    access, _ = await _enable_2fa(client, "pw_2fa_badcode@example.com")
    headers = {"Authorization": f"Bearer {access}"}

    resp = await client.post(
        "/auth/change-password",
        json={"current_password": OLD_PASSWORD, "new_password": NEW_PASSWORD, "code": "000000"},
        headers=headers,
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Invalid two-factor authentication code."


@pytest.mark.asyncio
async def test_change_password_2fa_lockout(client):
    access, secret = await _enable_2fa(client, "pw_lock@example.com")
    headers = {"Authorization": f"Bearer {access}"}

    max_attempts = settings.MFA_DISABLE_MAX_ATTEMPTS
    statuses = []
    for _ in range(max_attempts):
        r = await client.post(
            "/auth/change-password",
            json={"current_password": OLD_PASSWORD, "new_password": NEW_PASSWORD, "code": "000000"},
            headers=headers,
        )
        statuses.append(r.status_code)

    assert statuses[:-1] == [400] * (max_attempts - 1)
    assert statuses[-1] == 429

    # Even a correct code is rejected while locked.
    locked = await client.post(
        "/auth/change-password",
        json={"current_password": OLD_PASSWORD, "new_password": NEW_PASSWORD, "code": pyotp.TOTP(secret).now()},
        headers=headers,
    )
    assert locked.status_code == 429
    assert "Retry-After" in locked.headers


# ---------------------------------------------------------------------------
# Failure / validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_change_password_requires_authentication(client):
    resp = await client.post(
        "/auth/change-password",
        json={"current_password": OLD_PASSWORD, "new_password": NEW_PASSWORD},
    )
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_change_password_wrong_current(client):
    login = await _register_and_login(client, "pw_wrong@example.com")
    headers = {"Authorization": f"Bearer {login['access_token']}"}

    resp = await client.post(
        "/auth/change-password",
        json={"current_password": "WrongCurrent1!", "new_password": NEW_PASSWORD},
        headers=headers,
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Current password is incorrect."


@pytest.mark.asyncio
async def test_change_password_weak_new(client):
    login = await _register_and_login(client, "pw_weak@example.com")
    headers = {"Authorization": f"Bearer {login['access_token']}"}

    resp = await client.post(
        "/auth/change-password",
        json={"current_password": OLD_PASSWORD, "new_password": "weak"},
        headers=headers,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_change_password_same_as_current(client):
    login = await _register_and_login(client, "pw_same@example.com")
    headers = {"Authorization": f"Bearer {login['access_token']}"}

    resp = await client.post(
        "/auth/change-password",
        json={"current_password": OLD_PASSWORD, "new_password": OLD_PASSWORD},
        headers=headers,
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "New password must be different from the current password."
