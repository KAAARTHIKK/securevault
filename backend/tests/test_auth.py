"""B-01: login OK / wrong password / JWT expiry, plus login rate limiting."""
import time

from jose import jwt

from backend.app import models
from backend.app.config import get_settings
from backend.tests.conftest import make_user


def test_b01_login_success_and_wrong_password(client, db_session):
    make_user(db_session, "alice", "correct-pw")

    ok = client.post("/api/v1/auth/login", json={"username": "alice", "password": "correct-pw"})
    assert ok.status_code == 200
    assert "access_token" in ok.json()

    bad = client.post("/api/v1/auth/login", json={"username": "alice", "password": "wrong-pw"})
    assert bad.status_code == 401
    assert bad.json()["detail"]["error"]["code"] == "UNAUTHORIZED"


def test_b01_expired_jwt_rejected(client, db_session):
    make_user(db_session, "bob", "pw")
    settings = get_settings()
    expired = jwt.encode(
        {"sub": "11111111-1111-1111-1111-111111111111", "exp": int(time.time()) - 10},
        settings.jwt_secret,
        algorithm="HS256",
    )

    resp = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer %s" % expired})
    assert resp.status_code == 401


def test_login_is_rate_limited_after_repeated_failures(client, db_session):
    """Doc 06 Phase 4 hardening: password guessing is throttled per user+IP."""
    make_user(db_session, "throttled", "right-pw")
    settings = get_settings()

    for _ in range(settings.login_max_attempts):
        resp = client.post("/api/v1/auth/login", json={"username": "throttled", "password": "wrong"})
        assert resp.status_code == 401

    blocked = client.post("/api/v1/auth/login", json={"username": "throttled", "password": "wrong"})
    assert blocked.status_code == 429
    assert blocked.json()["detail"]["error"]["code"] == "RATE_LIMITED"
    assert int(blocked.headers["Retry-After"]) >= 1

    # the correct password is throttled too -- the limiter is on the account, not the guess
    still_blocked = client.post("/api/v1/auth/login", json={"username": "throttled", "password": "right-pw"})
    assert still_blocked.status_code == 429


def test_failed_login_is_audited(client, db_session):
    make_user(db_session, "audited", "right-pw")
    client.post("/api/v1/auth/login", json={"username": "audited", "password": "wrong"})
    rows = db_session.query(models.AuditLog).filter(models.AuditLog.action == "LOGIN_FAILED").all()
    assert len(rows) == 1
    assert rows[0].detail["username"] == "audited"
