"""B-02: non-admin calling /admin/* gets 403."""
from backend.tests.conftest import login, make_user


def test_b02_non_admin_forbidden_from_admin_routes(client, db_session):
    make_user(db_session, "regular", "pw", is_admin=False, key_stale=False)
    token = login(client, "regular", "pw")

    resp = client.post(
        "/api/v1/admin/users",
        json={"username": "new_user", "password": "pw2", "attributes": [], "is_admin": False},
        headers={"Authorization": "Bearer %s" % token},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"]["code"] == "FORBIDDEN"
