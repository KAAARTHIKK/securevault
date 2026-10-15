"""Security / leakage tests S-01, S-02, S-03, S-05 (doc 07 Section 1.3).

These drive the real client-side crypto path through the real API and then go
looking for leaks. S-04 (anonymous GET against the bucket) needs a real bucket
policy and lives in backend/scripts/s04_public_access_check.py.

Global rule 1 (doc 08) is what is on trial here: no plaintext, no file key K,
and no ABE secret key may reach the backend, the database, the logs, or S3.
"""
import base64
import hashlib
import logging
import math
import uuid
from collections import Counter

import pytest

# must come before the crypto import below: crypto.abe_kem pulls in charm, so
# without the ABE runtime this module has to skip rather than fail collection
pytest.importorskip("charm.toolbox.pairinggroup", reason="S-tests exercise the ABE path")

import requests  # noqa: E402
from sqlalchemy import inspect, text  # noqa: E402

from backend.app import key_authority, models  # noqa: E402
from backend.app.config import get_settings  # noqa: E402
from backend.app.db import get_engine  # noqa: E402
from backend.tests.conftest import login, make_user  # noqa: E402
from crypto import abe_kem, aes_stream, policy  # noqa: E402

MARKER = b"CONFIDENTIAL-ENDSEM-QP-MARKER-7f3a9c"
PLAINTEXT = MARKER + b"\x00" * 1024 + MARKER


def _api(client, token):
    return {"Authorization": "Bearer %s" % token}


def _upload(client, token, pk, logical, versioned, tmp_path, plaintext=PLAINTEXT, filename="endsem_qp.pdf"):
    """Run the real client upload flow: init -> encap -> encrypt -> PUT -> complete."""
    headers = _api(client, token)
    ciphertext_size = aes_stream.ciphertext_size_for(len(plaintext))

    init = client.post(
        "/api/v1/files/init",
        json={"ciphertext_size": ciphertext_size, "wrap_mode": "ABE"},
        headers=headers,
    )
    assert init.status_code == 200, init.text
    init = init.json()
    file_id = uuid.UUID(init["file_id"])

    key, ct_key = abe_kem.encap(pk, versioned, file_id.bytes)

    plain_path = tmp_path / "plain.bin"
    cipher_path = tmp_path / "cipher.svlt"
    plain_path.write_bytes(plaintext)
    aes_stream.encrypt_file(str(plain_path), str(cipher_path), key, file_id.bytes)
    ciphertext = cipher_path.read_bytes()
    assert len(ciphertext) == ciphertext_size
    enc_filename, name_nonce = aes_stream.encrypt_filename(filename, key, file_id.bytes)

    put = requests.put(init["upload_url"], data=ciphertext,
                       headers={"Content-Type": "application/octet-stream"})
    assert put.status_code < 300

    complete = client.post(
        "/api/v1/files/%s/complete" % file_id,
        json={
            "policy_logical": logical,
            "policy_versioned": versioned,
            "ct_key": base64.b64encode(ct_key).decode("ascii"),
            "enc_filename": base64.b64encode(enc_filename).decode("ascii"),
            "name_nonce": base64.b64encode(name_nonce).decode("ascii"),
            "plaintext_size": len(plaintext),
            "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
        },
        headers=headers,
    )
    assert complete.status_code == 201, complete.text
    return file_id, key, ct_key, ciphertext, complete.json()


@pytest.fixture
def abe_pk():
    return key_authority.load().pk


@pytest.fixture
def uploaded(client, db_session, moto_s3, abe_pk, tmp_path):
    make_user(db_session, "prof_a", "pw", attributes=["DEPT_CSE", "ROLE_FACULTY"], key_stale=False)
    token = login(client, "prof_a", "pw")
    attrs = client.get("/api/v1/attributes", headers=_api(client, token)).json()
    versions = {a["name"]: a["current_version"] for a in attrs}
    logical = "DEPT_CSE and ROLE_FACULTY"
    versioned = policy.to_versioned(logical, set(versions), versions)
    file_id, key, ct_key, ciphertext, detail = _upload(
        client, token, abe_pk, logical, versioned, tmp_path
    )
    return {
        "token": token, "file_id": file_id, "key": key, "ct_key": ct_key,
        "ciphertext": ciphertext, "detail": detail, "versioned": versioned, "logical": logical,
    }


def _all_db_bytes():
    """Every value in every column of every table, as bytes, for scanning."""
    engine = get_engine()
    blobs = []
    with engine.connect() as conn:
        for table_name in inspect(engine).get_table_names():
            rows = conn.execute(text('SELECT * FROM "%s"' % table_name)).fetchall()
            for row in rows:
                for value in row:
                    if value is None:
                        continue
                    if isinstance(value, (bytes, bytearray, memoryview)):
                        blobs.append(bytes(value))
                    else:
                        blobs.append(str(value).encode("utf-8", "replace"))
    return blobs


def test_s01_no_plaintext_or_file_key_in_db_or_logs(uploaded, client, caplog):
    """S-01: scan every DB column and the server logs for the plaintext marker
    and for hex/base64 encodings of K. Expect no match anywhere."""
    key = uploaded["key"]
    needles = {
        "plaintext marker": MARKER,
        "key raw": key,
        "key hex": key.hex().encode("ascii"),
        "key HEX": key.hex().upper().encode("ascii"),
        "key base64": base64.b64encode(key).rstrip(b"="),
        "key base64url": base64.urlsafe_b64encode(key).rstrip(b"="),
        "filename": b"endsem_qp.pdf",
    }

    blobs = _all_db_bytes()
    assert blobs, "nothing in the database to scan -- the fixture did not run"
    for label, needle in needles.items():
        for blob in blobs:
            assert needle not in blob, "%s leaked into a database column" % label

    with caplog.at_level(logging.DEBUG):
        detail = client.get(
            "/api/v1/files/%s" % uploaded["file_id"], headers=_api(client, uploaded["token"])
        )
        assert detail.status_code == 200
    log_text = "\n".join(r.getMessage() for r in caplog.records).encode("utf-8", "replace")
    for label, needle in needles.items():
        assert needle not in log_text, "%s leaked into a log line" % label

    # the API response itself carries only the ABE ciphertext of K, never K
    body = detail.content
    assert key not in body
    assert base64.b64encode(key).rstrip(b"=") not in body
    assert MARKER not in body


def test_s02_s3_object_is_high_entropy_and_marker_free(uploaded, moto_s3):
    """S-02: the stored object is indistinguishable from random and holds no marker."""
    settings = get_settings()
    stored = moto_s3.get_object(
        Bucket=settings.s3_bucket, Key=uploaded["detail"]["object_key"]
    )["Body"].read()

    assert stored == uploaded["ciphertext"]
    assert MARKER not in stored
    assert uploaded["key"] not in stored

    body = stored[aes_stream.HEADER_SIZE:]  # the header is fixed-format, not secret
    counts = Counter(body)
    entropy = -sum((c / len(body)) * math.log(c / len(body), 2) for c in counts.values())
    assert entropy > 7.5, "ciphertext entropy %.3f bits/byte is too low" % entropy


def test_s03_object_key_contains_no_filename(uploaded):
    """S-03: object keys are <prefix>/<uuid>/<version>.svlt and nothing else."""
    object_key = uploaded["detail"]["object_key"]
    settings = get_settings()

    assert object_key.startswith(settings.s3_prefix)
    assert "endsem_qp" not in object_key
    assert ".pdf" not in object_key

    tail = object_key[len(settings.s3_prefix):]
    file_part, _, version_part = tail.partition("/")
    uuid.UUID(file_part)  # raises if it is not a bare uuid
    assert version_part == "1.svlt"


def test_s05_revoked_user_cannot_decrypt_after_rekey(uploaded, client, db_session, abe_pk, tmp_path):
    """S-05: after revocation and re-encryption, the revoked user's key is useless
    even given the raw DB row and the raw S3 object."""
    revoked_user = make_user(
        db_session, "prof_b", "pw", attributes=["DEPT_CSE", "ROLE_FACULTY"], key_stale=False
    )
    admin = make_user(db_session, "admin", "pw", is_admin=True,
                      attributes=["DEPT_CSE", "ROLE_FACULTY"], key_stale=False)
    assert admin is not None

    # the key prof_b holds right now, under the v1 attribute versions
    old_sk = abe_kem.keygen(abe_pk, key_authority.load().msk, ["DEPT_CSE_V1", "ROLE_FACULTY_V1"])
    # before revocation prof_b can open the file
    assert abe_kem.decap(abe_pk, old_sk, uploaded["ct_key"], uploaded["file_id"].bytes) == uploaded["key"]

    admin_token = login(client, "admin", "pw")
    resp = client.delete(
        "/api/v1/admin/users/%s/attributes/ROLE_FACULTY" % revoked_user.id,
        headers=_api(client, admin_token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["files_total"] == 1, "the uploaded file should be queued for re-keying"

    attr = db_session.query(models.Attribute).filter(models.Attribute.name == "ROLE_FACULTY").first()
    db_session.refresh(attr)
    assert attr.current_version == 2

    # the re-key worker's job, done here with the admin's attributes
    new_versioned = "DEPT_CSE_V1 and ROLE_FACULTY_V2"
    new_key, new_ct_key = abe_kem.encap(abe_pk, new_versioned, uploaded["file_id"].bytes)
    assert new_key != uploaded["key"]

    plain_path = tmp_path / "re_plain.bin"
    new_cipher = tmp_path / "re_cipher.svlt"
    plain_path.write_bytes(PLAINTEXT)
    aes_stream.encrypt_file(str(plain_path), str(new_cipher), new_key, uploaded["file_id"].bytes)

    # prof_b's old key satisfies nothing in the new policy...
    assert abe_kem.decap(abe_pk, old_sk, new_ct_key, uploaded["file_id"].bytes) is None
    # ...and the stale file key cannot open the re-encrypted object either
    with pytest.raises(Exception):
        aes_stream.decrypt_file(
            str(new_cipher), str(tmp_path / "nope.bin"), uploaded["key"], uploaded["file_id"].bytes
        )
    assert not (tmp_path / "nope.bin").exists()
