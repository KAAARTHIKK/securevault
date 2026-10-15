"""End-to-end round trip against REAL AWS S3 (doc 08 Phase 2 item 8).

Only this script is allowed to touch real AWS (doc 08 global rule 6). Requires:
  - backend/.env configured with real AWS credentials and STORAGE_BACKEND=s3
    (see documentation/04_AWS_S3_Setup.md)
  - the backend running and reachable (e.g. docker compose up)
  - backend/scripts/init_ka.py and backend/scripts/seed_demo.py already run

Usage: python backend/scripts/e2e.py
"""
import base64
import hashlib
import os
import sys
import tempfile
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import requests  # noqa: E402

from crypto import abe_kem, aes_stream, policy  # noqa: E402

BASE_URL = os.environ.get("SECUREVAULT_API", "http://localhost:8000/api/v1")
USERNAME = os.environ.get("SECUREVAULT_E2E_USER", "prof_a")
PASSWORD = os.environ.get("SECUREVAULT_E2E_PASSWORD", "prof-a-pass")


def _get(session, path, **kw):
    resp = session.get(BASE_URL + path, **kw)
    resp.raise_for_status()
    return resp.json()


def _post(session, path, **kw):
    resp = session.post(BASE_URL + path, **kw)
    resp.raise_for_status()
    return resp.json()


def main() -> None:
    session = requests.Session()

    print("1. Logging in as %s..." % USERNAME)
    login = _post(session, "/auth/login", json={"username": USERNAME, "password": PASSWORD})
    session.headers["Authorization"] = "Bearer %s" % login["access_token"]

    print("2. Issuing a fresh ABE secret key...")
    issue = _post(session, "/keys/issue")
    sk = abe_kem.deserialize_sk(base64.b64decode(issue["sk"]))

    print("3. Fetching ABE public params...")
    params = _get(session, "/keys/public-params")
    pk = abe_kem.deserialize_pk(base64.b64decode(params["pk"]))

    print("4. Fetching current attribute versions...")
    attrs = _get(session, "/attributes")
    versions = {a["name"]: a["current_version"] for a in attrs}
    known = set(versions)

    logical_policy = "DEPT_CSE and ROLE_FACULTY"
    versioned_policy = policy.to_versioned(logical_policy, known, versions)
    print("   policy: %s -> %s" % (logical_policy, versioned_policy))

    plaintext = os.urandom(256 * 1024)
    original_sha256 = hashlib.sha256(plaintext).hexdigest()

    file_id = uuid.uuid4()
    key, ct_key = abe_kem.encap(pk, versioned_policy, file_id.bytes)

    with tempfile.TemporaryDirectory() as tmp:
        plain_path = Path(tmp) / "plain.bin"
        cipher_path = Path(tmp) / "cipher.svlt"
        decrypted_path = Path(tmp) / "decrypted.bin"
        plain_path.write_bytes(plaintext)

        print("5. Encrypting locally (AES-256-GCM, chunked)...")
        aes_stream.encrypt_file(str(plain_path), str(cipher_path), key, file_id.bytes)
        ciphertext = cipher_path.read_bytes()
        ciphertext_sha256 = hashlib.sha256(ciphertext).hexdigest()
        enc_filename, name_nonce = aes_stream.encrypt_filename("e2e_test.bin", key, file_id.bytes)

        print("6. POST /files/init...")
        init_resp = _post(session, "/files/init", json={"ciphertext_size": len(ciphertext), "wrap_mode": "ABE"})

        print("7. PUT ciphertext to real S3...")
        put_resp = requests.put(
            init_resp["upload_url"], data=ciphertext, headers={"Content-Type": "application/octet-stream"}
        )
        put_resp.raise_for_status()

        print("8. POST /files/{id}/complete...")
        _post(
            session, "/files/%s/complete" % init_resp["file_id"],
            json={
                "policy_logical": logical_policy,
                "policy_versioned": versioned_policy,
                "ct_key": base64.b64encode(ct_key).decode("ascii"),
                "enc_filename": base64.b64encode(enc_filename).decode("ascii"),
                "name_nonce": base64.b64encode(name_nonce).decode("ascii"),
                "plaintext_size": len(plaintext),
                "ciphertext_sha256": ciphertext_sha256,
            },
        )

        print("9. GET /files/{id} for the download URL...")
        detail = _get(session, "/files/%s" % init_resp["file_id"])

        print("10. Downloading ciphertext from real S3...")
        dl_resp = requests.get(detail["download_url"])
        dl_resp.raise_for_status()
        downloaded = dl_resp.content
        assert hashlib.sha256(downloaded).hexdigest() == ciphertext_sha256, "ciphertext hash mismatch after download"
        downloaded_path = Path(tmp) / "downloaded.svlt"
        downloaded_path.write_bytes(downloaded)

        print("11. Unwrapping the file key via ABE decap...")
        recovered_key = abe_kem.decap(pk, sk, base64.b64decode(detail["ct_key"]), file_id.bytes)
        assert recovered_key == key, "ABE decap did not recover the original file key"

        print("12. Decrypting downloaded ciphertext...")
        aes_stream.decrypt_file(str(downloaded_path), str(decrypted_path), recovered_key, file_id.bytes)
        decrypted = decrypted_path.read_bytes()

    final_sha256 = hashlib.sha256(decrypted).hexdigest()
    assert final_sha256 == original_sha256, "round-trip hash mismatch!"

    session.post(BASE_URL + "/files/%s/access-result" % init_resp["file_id"], json={"result": "OK"})

    print("\nE2E round trip OK.")
    print("  original sha256:  %s" % original_sha256)
    print("  decrypted sha256: %s" % final_sha256)


if __name__ == "__main__":
    main()
