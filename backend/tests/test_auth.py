"""B-01: login OK / wrong password / JWT expiry."""
import time

from jose import jwt

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
