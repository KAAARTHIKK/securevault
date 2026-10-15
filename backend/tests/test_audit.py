"""B-07: audit rows written for every action."""
import requests

from backend.app import models
from backend.tests.conftest import login, make_user


def test_b07_audit_rows_written_for_core_actions(client, db_session, moto_s3):
    make_user(db_session, "auditor", "pw", key_stale=True)

    token = login(client, "auditor", "pw")
    headers = {"Authorization": "Bearer %s" % token}

    issue_resp = client.post("/api/v1/keys/issue", headers=headers)
    assert issue_resp.status_code == 200

    init_resp = client.post("/api/v1/files/init", json={"ciphertext_size": 5, "wrap_mode": "ECC"}, headers=headers)
    body = init_resp.json()
    requests.put(body["upload_url"], data=b"hello", headers={"Content-Type": "application/octet-stream"})
    client.post(
        "/api/v1/files/%s/complete" % body["file_id"],
        json={
            "policy_logical": "", "policy_versioned": "",
            "enc_filename": "AAAA", "name_nonce": "AAAA",
            "plaintext_size": 5, "ciphertext_sha256": "0" * 64,
        },
        headers=headers,
    )
    client.delete("/api/v1/files/%s" % body["file_id"], headers=headers)

    actions = {row.action for row in db_session.query(models.AuditLog).all()}
    assert {"LOGIN", "KEY_ISSUE", "UPLOAD", "DELETE"} <= actions
