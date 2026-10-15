"""Typed REST client for the SecureVault backend (doc 05 Section 2).

Nothing in this module ever touches a file key, a plaintext byte, or an ABE
secret key beyond carrying the base64 the server already issued over TLS --
all crypto lives in crypto/ and is driven from client/vault.py.
"""
import os
from typing import Any, Dict, List, Optional

import requests

DEFAULT_BASE_URL = os.environ.get("SECUREVAULT_API", "http://localhost:8000/api/v1")
S3_TIMEOUT = 300


class ApiError(Exception):
    """An error response from the backend, carrying doc 05's error code."""

    def __init__(self, status_code: int, code: str, message: str):
        super().__init__("%s (%d): %s" % (code, status_code, message))
        self.status_code = status_code
        self.code = code
        self.message = message


class KeyStaleError(ApiError):
    """409 KEY_STALE -- attribute versions moved; the caller must re-issue its key."""


def _raise_for_status(resp: requests.Response) -> None:
    if resp.status_code < 400:
        return
    code, message = "HTTP_%d" % resp.status_code, resp.text
    try:
        payload = resp.json()
        if isinstance(payload, dict) and isinstance(payload.get("detail"), dict):
            err = payload["detail"].get("error", {})
            code = err.get("code", code)
            message = err.get("message", message)
        elif isinstance(payload, dict) and payload.get("detail"):
            message = str(payload["detail"])
    except ValueError:
        pass
    if resp.status_code == 409 and code == "KEY_STALE":
        raise KeyStaleError(resp.status_code, code, message)
    raise ApiError(resp.status_code, code, message)


class SecureVaultApi:
    def __init__(self, base_url: str = DEFAULT_BASE_URL, verify: Any = True):
        self.base_url = base_url.rstrip("/")
        self._session = requests.Session()
        self._session.verify = verify
        self._verify = verify
        self._stale_handler = None
        self._handling_stale = False

    # ---- plumbing -------------------------------------------------------

    def set_key_stale_handler(self, handler) -> None:
        """Install the callback that answers a 409 KEY_STALE (doc 08 Phase 3 item 1).

        client.vault.login() installs one that re-issues the ABE key and
        rewrites the local keystore, so a revoke elsewhere does not surface as
        an error the user has to resolve by hand.
        """
        self._stale_handler = handler

    def _request(self, method: str, path: str, **kw) -> Any:
        try:
            return self._send(method, path, **kw)
        except KeyStaleError:
            # re-issue once, then retry; a second 409 is a real failure
            if self._stale_handler is None or self._handling_stale:
                raise
            self._handling_stale = True
            try:
                if not self._stale_handler():
                    raise
            finally:
                self._handling_stale = False
            return self._send(method, path, **kw)

    def _send(self, method: str, path: str, **kw) -> Any:
        resp = self._session.request(method, self.base_url + path, timeout=60, **kw)
        _raise_for_status(resp)
        if resp.status_code == 204 or not resp.content:
            return None
        return resp.json()

    def set_token(self, token: Optional[str]) -> None:
        if token:
            self._session.headers["Authorization"] = "Bearer %s" % token
        else:
            self._session.headers.pop("Authorization", None)

    # ---- auth -----------------------------------------------------------

    def login(self, username: str, password: str) -> Dict[str, Any]:
        data = self._request("POST", "/auth/login", json={"username": username, "password": password})
        self.set_token(data["access_token"])
        return data

    def me(self) -> Dict[str, Any]:
        return self._request("GET", "/auth/me")

    # ---- key authority --------------------------------------------------

    def public_params(self) -> Dict[str, Any]:
        return self._request("GET", "/keys/public-params")

    def issue_key(self) -> Dict[str, Any]:
        return self._request("POST", "/keys/issue")

    def register_ecc_public_key(self, public_key_b64: str) -> None:
        self._request("PUT", "/keys/ecc", json={"public_key": public_key_b64})

    def ecc_recipients(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/keys/ecc/recipients")

    def attributes(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/attributes")

    # ---- files ----------------------------------------------------------

    def files_init(self, ciphertext_size: int, wrap_mode: str) -> Dict[str, Any]:
        return self._request(
            "POST", "/files/init",
            json={"ciphertext_size": ciphertext_size, "wrap_mode": wrap_mode},
        )

    def files_complete(self, file_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("POST", "/files/%s/complete" % file_id, json=body)

    def files_list(self, mine: bool = False) -> List[Dict[str, Any]]:
        return self._request("GET", "/files", params={"mine": str(mine).lower()})

    def file_detail(self, file_id: str) -> Dict[str, Any]:
        return self._request("GET", "/files/%s" % file_id)

    def file_delete(self, file_id: str) -> None:
        self._request("DELETE", "/files/%s" % file_id)

    def access_result(self, file_id: str, result: str) -> None:
        self._request("POST", "/files/%s/access-result" % file_id, json={"result": result})

    # ---- admin ----------------------------------------------------------

    def admin_users(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/admin/users")

    def admin_create_user(self, username: str, password: str, attributes: List[str],
                          is_admin: bool = False) -> Dict[str, Any]:
        return self._request("POST", "/admin/users", json={
            "username": username, "password": password,
            "attributes": attributes, "is_admin": is_admin,
        })

    def admin_grant(self, user_id: str, attribute: str) -> None:
        self._request("POST", "/admin/users/%s/attributes" % user_id, json={"attribute": attribute})

    def admin_revoke(self, user_id: str, attribute: str) -> Dict[str, Any]:
        return self._request("DELETE", "/admin/users/%s/attributes/%s" % (user_id, attribute))

    def rekey_jobs(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/admin/rekey-jobs")

    def rekey_job_files(self, job_id: int) -> List[Dict[str, Any]]:
        return self._request("GET", "/admin/rekey-jobs/%d/files" % job_id)

    def rekey_file_init(self, job_id: int, file_id: str) -> Dict[str, Any]:
        return self._request("POST", "/admin/rekey-jobs/%d/files/%s/init" % (job_id, file_id))

    def rekey_file_commit(self, job_id: int, file_id: str, body: Dict[str, Any]) -> None:
        self._request("POST", "/admin/rekey-jobs/%d/files/%s/commit" % (job_id, file_id), json=body)

    def audit(self, limit: int = 100, action: Optional[str] = None) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"limit": limit}
        if action:
            params["action"] = action
        return self._request("GET", "/admin/audit", params=params)

    # ---- S3 via pre-signed URLs (the backend never proxies bytes) -------

    def s3_put_file(self, upload_url: str, path: str) -> None:
        with open(path, "rb") as fh:
            resp = requests.put(
                upload_url, data=fh,
                headers={"Content-Type": "application/octet-stream"},
                timeout=S3_TIMEOUT,
            )
        resp.raise_for_status()

    def s3_get_file(self, download_url: str, path: str, progress=None) -> int:
        written = 0
        with requests.get(download_url, stream=True, timeout=S3_TIMEOUT) as resp:
            resp.raise_for_status()
            total = int(resp.headers.get("Content-Length") or 0)
            with open(path, "wb") as fh:
                for block in resp.iter_content(chunk_size=1024 * 1024):
                    fh.write(block)
                    written += len(block)
                    if progress and total:
                        progress(min(1.0, written / float(total)))
        return written
