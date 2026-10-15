"""B-03 (presign expiry), B-04 (size mismatch), B-06 (delete removes S3 object).

moto does not enforce presigned-URL time expiry (it validates the signature
but not the X-Amz-Expires window), so B-03 checks what is under our control:
the backend requests the configured TTL from S3 and the URL works within it.
Real expiry enforcement happens on AWS's side against a real bucket.
"""
from urllib.parse import parse_qs, urlparse

import requests

from backend.app.config import get_settings
from backend.tests.conftest import login, make_user


def test_b03_presigned_put_has_correct_ttl_and_is_usable(client, db_session, moto_s3):
    make_user(db_session, "uploader", "pw", key_stale=False)
    token = login(client, "uploader", "pw")

    resp = client.post(
        "/api/v1/files/init",
        json={"ciphertext_size": 10, "wrap_mode": "ECC"},
        headers={"Authorization": "Bearer %s" % token},
    )
    assert resp.status_code == 200
    body = resp.json()

    settings = get_settings()
    assert body["expires_in"] == settings.presign_ttl_seconds

    query = parse_qs(urlparse(body["upload_url"]).query)
    assert int(query["X-Amz-Expires"][0]) == settings.presign_ttl_seconds

    put_resp = requests.put(
        body["upload_url"], data=b"0123456789", headers={"Content-Type": "application/octet-stream"}
    )
    assert put_resp.status_code < 300


def test_b04_complete_with_wrong_size_returns_422(client, db_session, moto_s3):
    make_user(db_session, "uploader2", "pw", key_stale=False)
    token = login(client, "uploader2", "pw")
    headers = {"Authorization": "Bearer %s" % token}

    init_resp = client.post("/api/v1/files/init", json={"ciphertext_size": 100, "wrap_mode": "ECC"}, headers=headers)
    assert init_resp.status_code == 200
    body = init_resp.json()

    put_resp = requests.put(
        body["upload_url"], data=b"x" * 50, headers={"Content-Type": "application/octet-stream"}
    )
    assert put_resp.status_code < 300

    complete_resp = client.post(
        "/api/v1/files/%s/complete" % body["file_id"],
        json={
            "policy_logical": "", "policy_versioned": "",
            "enc_filename": "AAAA", "name_nonce": "AAAA",
            "plaintext_size": 50, "ciphertext_sha256": "0" * 64,
        },
        headers=headers,
    )
    assert complete_resp.status_code == 422
    assert complete_resp.json()["detail"]["error"]["code"] == "SIZE_MISMATCH"


def test_b06_delete_removes_s3_object(client, db_session, moto_s3):
    make_user(db_session, "owner", "pw", key_stale=False)
    token = login(client, "owner", "pw")
    headers = {"Authorization": "Bearer %s" % token}

    init_resp = client.post("/api/v1/files/init", json={"ciphertext_size": 10, "wrap_mode": "ECC"}, headers=headers)
    body = init_resp.json()
    requests.put(body["upload_url"], data=b"0123456789", headers={"Content-Type": "application/octet-stream"})
    client.post(
        "/api/v1/files/%s/complete" % body["file_id"],
        json={
            "policy_logical": "", "policy_versioned": "",
            "enc_filename": "AAAA", "name_nonce": "AAAA",
            "plaintext_size": 10, "ciphertext_sha256": "0" * 64,
        },
        headers=headers,
    )

    del_resp = client.delete("/api/v1/files/%s" % body["file_id"], headers=headers)
    assert del_resp.status_code == 204

    bucket = get_settings().s3_bucket
    from botocore.exceptions import ClientError
    try:
        moto_s3.head_object(Bucket=bucket, Key=body["object_key"])
        assert False, "object should have been deleted"
    except ClientError:
        pass
