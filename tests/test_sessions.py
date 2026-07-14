import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.db.models.user import User
from app.db.models.token import RefreshToken

# Shared fixtures (db_session, client) live in tests/conftest.py.

PASSWORD = "StrongPass1!"


async def _register(client, email, name="Test User"):
    resp = await client.post(
        "/auth/register",
        json={"name": name, "email": email, "password": PASSWORD},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _login(client, email):
    """Register (if needed) is caller's job; returns the login response body."""
    resp = await client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _auth_session(client, email):
    """Register + login, returning (access_token, refresh_token)."""
    await _register(client, email)
    body = await _login(client, email)
    return body["access_token"], body["refresh_token"]


# ---------------------------------------------------------------------------
# GET /auth/me
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_me_requires_authentication(client):
    resp = await client.get("/auth/me")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_me_rejects_invalid_token(client):
    resp = await client.get("/auth/me", headers={"Authorization": "Bearer not-a-real-token"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_me_returns_current_user(client):
    access, _ = await _auth_session(client, "me@example.com")
    resp = await client.get("/auth/me", headers={"Authorization": f"Bearer {access}"})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["email"] == "me@example.com"
    assert data["is_2fa_enabled"] is False
    assert data["is_email_verified"] is False
    # Secrets must never be exposed.
    for secret_field in ("password", "password_hash", "totp_secret"):
        assert secret_field not in data


# ---------------------------------------------------------------------------
# POST /auth/refresh
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_requires_token(client):
    resp = await client.post("/auth/refresh", json={})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_refresh_rejects_unknown_token(client):
    resp = await client.post("/auth/refresh", json={"refresh_token": "does-not-exist"})
    assert resp.status_code == 401
    assert "invalid" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_refresh_issues_and_rotates_tokens(client):
    _, refresh = await _auth_session(client, "refresh@example.com")

    resp = await client.post("/auth/refresh", json={"refresh_token": refresh})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["access_token"]
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 900
    # The refresh token is high-entropy random -> always rotates to a new value.
    assert body["refresh_token"] != refresh


@pytest.mark.asyncio
async def test_refresh_old_token_revoked_after_rotation(client):
    _, refresh = await _auth_session(client, "rotate@example.com")

    first = await client.post("/auth/refresh", json={"refresh_token": refresh})
    assert first.status_code == 200
    new_refresh = first.json()["refresh_token"]

    # Old (rotated-out) token is now revoked.
    reused = await client.post("/auth/refresh", json={"refresh_token": refresh})
    assert reused.status_code == 401
    assert "revoked" in reused.json()["detail"].lower()

    # The freshly minted token still works.
    ok = await client.post("/auth/refresh", json={"refresh_token": new_refresh})
    assert ok.status_code == 200


@pytest.mark.asyncio
async def test_refresh_rejects_expired_token(client, db_session):
    await _register(client, "expired@example.com")
    user = (
        await db_session.execute(select(User).where(User.email == "expired@example.com"))
    ).scalar_one()

    plain = "expired-refresh-token"
    db_session.add(
        RefreshToken(
            user_id=user.id,
            token_hash=hashlib.sha256(plain.encode()).hexdigest(),
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
    )
    await db_session.commit()

    resp = await client.post("/auth/refresh", json={"refresh_token": plain})
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# POST /auth/logout  (no bearer token required; user derived from refresh token)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_logout_requires_refresh_token(client):
    resp = await client.post("/auth/logout", json={})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_logout_single_session_without_bearer(client):
    _, refresh = await _auth_session(client, "logout@example.com")

    resp = await client.post("/auth/logout", json={"refresh_token": refresh})
    assert resp.status_code == 200, resp.text

    # Token can no longer be refreshed.
    reused = await client.post("/auth/refresh", json={"refresh_token": refresh})
    assert reused.status_code == 401


@pytest.mark.asyncio
async def test_logout_is_idempotent(client):
    _, refresh = await _auth_session(client, "idem@example.com")

    assert (await client.post("/auth/logout", json={"refresh_token": refresh})).status_code == 200
    # Logging out an already-revoked token still succeeds.
    assert (await client.post("/auth/logout", json={"refresh_token": refresh})).status_code == 200


@pytest.mark.asyncio
async def test_logout_unknown_token_is_noop(client):
    resp = await client.post("/auth/logout", json={"refresh_token": "totally-unknown-token"})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_logout_single_leaves_other_sessions_active(client):
    await _register(client, "multi@example.com")
    a = (await _login(client, "multi@example.com"))["refresh_token"]
    b = (await _login(client, "multi@example.com"))["refresh_token"]
    c = (await _login(client, "multi@example.com"))["refresh_token"]

    resp = await client.post("/auth/logout", json={"refresh_token": a})
    assert resp.status_code == 200

    assert (await client.post("/auth/refresh", json={"refresh_token": a})).status_code == 401
    assert (await client.post("/auth/refresh", json={"refresh_token": b})).status_code == 200
    assert (await client.post("/auth/refresh", json={"refresh_token": c})).status_code == 200


@pytest.mark.asyncio
async def test_logout_all_sessions_revokes_everything(client):
    await _register(client, "nukeall@example.com")
    tokens = [(await _login(client, "nukeall@example.com"))["refresh_token"] for _ in range(3)]

    resp = await client.post(
        "/auth/logout", json={"refresh_token": tokens[0], "all_sessions": True}
    )
    assert resp.status_code == 200

    for t in tokens:
        assert (await client.post("/auth/refresh", json={"refresh_token": t})).status_code == 401


@pytest.mark.asyncio
async def test_logout_only_affects_token_owner(client):
    await _register(client, "owner_a@example.com")
    await _register(client, "owner_b@example.com")
    a_refresh = (await _login(client, "owner_a@example.com"))["refresh_token"]
    b_refresh = (await _login(client, "owner_b@example.com"))["refresh_token"]

    # A logs out of all sessions using A's token; B must be untouched.
    resp = await client.post(
        "/auth/logout", json={"refresh_token": a_refresh, "all_sessions": True}
    )
    assert resp.status_code == 200

    assert (await client.post("/auth/refresh", json={"refresh_token": a_refresh})).status_code == 401
    assert (await client.post("/auth/refresh", json={"refresh_token": b_refresh})).status_code == 200
