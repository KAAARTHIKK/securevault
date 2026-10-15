"""B-05: revoke bumps version, staleifies remaining holders, rekey job lists affected files."""
from backend.app import models
from backend.tests.conftest import login, make_user


def test_b05_revoke_bumps_version_staleifies_holders_and_lists_files(client, db_session):
    holder_a = make_user(db_session, "holder_a", "pw", attributes=["DEPT_CSE", "ROLE_FACULTY"], key_stale=False)
    make_user(db_session, "holder_b", "pw", attributes=["DEPT_CSE", "ROLE_FACULTY"], key_stale=False)
    make_user(db_session, "the_admin", "pw", is_admin=True, key_stale=False)

    file_row = models.File(
        owner_id=holder_a.id, object_key="objects/f1/1.svlt", version=1, status="active",
        wrap_mode="ABE", policy_logical="ROLE_FACULTY", policy_versioned="(ROLE_FACULTY_V1)",
        enc_filename=b"x", name_nonce=b"y", plaintext_size=1, ciphertext_size=1,
        ciphertext_sha256="0" * 64,
    )
    db_session.add(file_row)
    db_session.commit()

    admin_token = login(client, "the_admin", "pw")
    resp = client.delete(
        "/api/v1/admin/users/%s/attributes/ROLE_FACULTY" % holder_a.id,
        headers={"Authorization": "Bearer %s" % admin_token},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["files_total"] == 1

    db_session.expire_all()

    attr = db_session.query(models.Attribute).filter(models.Attribute.name == "ROLE_FACULTY").first()
    assert attr.current_version == 2

    holder_b = db_session.query(models.User).filter(models.User.username == "holder_b").first()
    assert holder_b.key_stale is True

    holder_b_token = login(client, "holder_b", "pw")
    stale_check = client.get("/api/v1/files", headers={"Authorization": "Bearer %s" % holder_b_token})
    assert stale_check.status_code == 409
    assert stale_check.json()["detail"]["error"]["code"] == "KEY_STALE"
