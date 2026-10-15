"""Client-side crypto glue: keystore, upload, download, re-key (doc 02 Section 4.2-4.4).

This is the only place where a file key K exists. Nothing here is ever sent to
the backend except ABE/ECC ciphertexts of K and the AES ciphertext of the file,
and no key or plaintext is ever logged.
"""
import base64
import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from crypto import abe_kem, aes_stream, ecc_wrap, keystore, policy

from .api import SecureVaultApi

KEYSTORE_DIR = Path(os.environ.get("SECUREVAULT_HOME", Path.home() / ".securevault"))
KEYSTORE_FORMAT = 1
Progress = Optional[Callable[[float], None]]


class AccessDenied(Exception):
    """The policy is not satisfied by this user's attributes, or they are not a recipient."""


class IntegrityError(Exception):
    """The ciphertext was tampered with, reordered, truncated, or swapped."""


# ---------------------------------------------------------------- keystore

def keystore_path(username):
    return KEYSTORE_DIR / ("%s.key.enc" % username)


def save_keys(username, password, sk_b64, versioned_attributes, ecc_private):
    """scrypt + AES-GCM the user's ABE secret key to ~/.securevault/<user>.key.enc."""
    KEYSTORE_DIR.mkdir(parents=True, exist_ok=True)
    blob = json.dumps({
        "format": KEYSTORE_FORMAT,
        "sk": sk_b64,
        "versioned_attributes": list(versioned_attributes),
        "ecc_priv": base64.b64encode(ecc_private).decode("ascii") if ecc_private else None,
    }).encode("utf-8")
    path = keystore_path(username)
    keystore.save(str(path), blob, password)
    try:
        os.chmod(str(path), 0o600)
    except OSError:
        pass  # best effort; Windows has no POSIX mode


def load_keys(username, password):
    """Raises ValueError/InvalidTag on a wrong password, FileNotFoundError if absent."""
    data = json.loads(keystore.load(str(keystore_path(username)), password).decode("utf-8"))
    if data.get("format") != KEYSTORE_FORMAT:
        raise ValueError("unsupported keystore format")
    return data


# ------------------------------------------------------------------- vault

class Vault:
    """A logged-in identity plus its unlocked key material."""

    def __init__(self, api, user, pk, sk, versioned_attributes, ecc_private=None):
        self.api = api
        self.user = user
        self.pk = pk
        self.sk = sk
        self.versioned_attributes = list(versioned_attributes)
        self.ecc_private = ecc_private
        # only used to rewrite the keystore after an automatic re-issue
        self._keystore_password = None

    def refresh_key(self, keystore_password=None):
        """Re-issue the ABE key for the current attribute versions, in place.

        Installed as the api's KEY_STALE handler, so a revoke elsewhere is
        absorbed transparently: POST /keys/issue, swap SK, rewrite the keystore.
        """
        issue = self.api.issue_key()
        self.sk = abe_kem.deserialize_sk(base64.b64decode(issue["sk"]))
        self.versioned_attributes = list(issue["versioned_attributes"])
        try:
            self.user = self.api.me()
        except Exception:
            self.user["key_stale"] = False
        password = keystore_password or self._keystore_password
        if password:
            save_keys(self.username, password, issue["sk"], self.versioned_attributes, self.ecc_private)
        return True

    @property
    def user_id(self):
        return uuid.UUID(self.user["id"])

    @property
    def username(self):
        return self.user["username"]

    # ---- policy helpers ---------------------------------------------

    def attribute_versions(self):
        attrs = self.api.attributes()
        versions = {a["name"]: a["current_version"] for a in attrs}
        return set(versions), versions

    def to_versioned(self, logical_policy):
        known, versions = self.attribute_versions()
        return policy.to_versioned(logical_policy, known, versions)

    # ---- upload (doc 02 Section 4.2) --------------------------------

    def upload(self, source_path, filename, logical_policy, wrap_mode="ABE",
               recipients=None, progress=None, work_dir=None):
        """Encrypt locally, PUT to the S3 pre-signed URL, then commit metadata.

        /files/init is called first because the chunk AAD and the KEM's HKDF
        salt are bound to the *backend's* file_id; the ciphertext size is
        predicted from the plaintext size so init can run before encrypting.
        """
        if wrap_mode not in ("ABE", "ECC"):
            raise ValueError("wrap_mode must be ABE or ECC")

        plaintext_size = os.path.getsize(source_path)
        ciphertext_size = aes_stream.ciphertext_size_for(plaintext_size)
        versioned_policy = self.to_versioned(logical_policy)

        init = self.api.files_init(ciphertext_size, wrap_mode)
        file_id = uuid.UUID(init["file_id"])
        if progress:
            progress(0.1)

        ct_key_b64 = None
        recipient_rows = None

        if wrap_mode == "ABE":
            key, ct_key = abe_kem.encap(self.pk, versioned_policy, file_id.bytes)
            ct_key_b64 = base64.b64encode(ct_key).decode("ascii")
        else:
            if not recipients:
                raise ValueError("ECC mode needs at least one recipient")
            key = os.urandom(aes_stream.KEY_SIZE)
            recipient_rows = []
            for r in recipients:
                rid = uuid.UUID(r["user_id"])
                eph_public, nonce, wrapped = ecc_wrap.wrap_key(
                    key, base64.b64decode(r["public_key"]), file_id.bytes, rid.bytes,
                )
                recipient_rows.append({
                    "user_id": str(rid),
                    "eph_public": base64.b64encode(eph_public).decode("ascii"),
                    "nonce": base64.b64encode(nonce).decode("ascii"),
                    "wrapped_key": base64.b64encode(wrapped).decode("ascii"),
                })
        if progress:
            progress(0.25)

        work = Path(work_dir) if work_dir else KEYSTORE_DIR / "tmp"
        work.mkdir(parents=True, exist_ok=True)
        cipher_path = work / ("%s.svlt" % file_id)
        try:
            aes_stream.encrypt_file(source_path, str(cipher_path), key, file_id.bytes)
            actual = cipher_path.stat().st_size
            if actual != ciphertext_size:
                raise RuntimeError("predicted ciphertext size %d != actual %d" % (ciphertext_size, actual))
            enc_filename, name_nonce = aes_stream.encrypt_filename(filename, key, file_id.bytes)
            ciphertext_sha256 = sha256_file(str(cipher_path))
            if progress:
                progress(0.5)

            self.api.s3_put_file(init["upload_url"], str(cipher_path))
            if progress:
                progress(0.85)
        finally:
            shred(cipher_path)
            del key

        detail = self.api.files_complete(str(file_id), {
            "policy_logical": logical_policy,
            "policy_versioned": versioned_policy,
            "ct_key": ct_key_b64,
            "enc_filename": base64.b64encode(enc_filename).decode("ascii"),
            "name_nonce": base64.b64encode(name_nonce).decode("ascii"),
            "plaintext_size": plaintext_size,
            "ciphertext_sha256": ciphertext_sha256,
            "recipients": recipient_rows,
        })
        if progress:
            progress(1.0)
        return detail

    # ---- download (doc 02 Section 4.3) ------------------------------

    def recover_key(self, detail):
        """Unwrap K for this file, or None if this user is not authorized.

        ABE decap returns None both for "policy not satisfied" (BSW07's False)
        and for any exception -- the two paths never diverge.
        """
        file_id = uuid.UUID(detail["id"])
        if detail["wrap_mode"] == "ABE":
            if not detail.get("ct_key"):
                return None
            return abe_kem.decap(self.pk, self.sk, base64.b64decode(detail["ct_key"]), file_id.bytes)
        recipient = detail.get("recipient")
        if not recipient or not self.ecc_private:
            return None
        return ecc_wrap.unwrap_key(
            base64.b64decode(recipient["eph_public"]),
            base64.b64decode(recipient["nonce"]),
            base64.b64decode(recipient["wrapped_key"]),
            self.ecc_private,
            file_id.bytes,
            self.user_id.bytes,
        )

    def download(self, file_id, dest_dir, progress=None):
        """Returns (written_path, original_filename).

        Raises AccessDenied if the policy is unsatisfied, IntegrityError if the
        ciphertext fails its hash or any chunk's GCM tag. Either outcome is
        reported to /access-result for the audit log.
        """
        detail = self.api.file_detail(file_id)
        fid = uuid.UUID(detail["id"])

        key = self.recover_key(detail)
        if key is None:
            self._report(file_id, "DENIED")
            raise AccessDenied("Access denied by policy")
        if progress:
            progress(0.15)

        work = KEYSTORE_DIR / "tmp"
        work.mkdir(parents=True, exist_ok=True)
        cipher_path = work / ("%s.dl.svlt" % fid)
        dest_path = None
        try:
            self.api.s3_get_file(
                detail["download_url"], str(cipher_path),
                progress=(lambda f: progress(0.15 + 0.55 * f)) if progress else None,
            )
            if sha256_file(str(cipher_path)) != detail["ciphertext_sha256"]:
                raise IntegrityError("Ciphertext hash does not match the recorded sha256")

            filename = aes_stream.decrypt_filename(
                base64.b64decode(detail["enc_filename"]),
                base64.b64decode(detail["name_nonce"]),
                key, fid.bytes,
            )
            dest_path = Path(dest_dir) / safe_name(filename)
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            aes_stream.decrypt_file(str(cipher_path), str(dest_path), key, fid.bytes)
        except IntegrityError:
            self._report(file_id, "DENIED")
            raise
        except Exception as exc:
            self._report(file_id, "DENIED")
            raise IntegrityError(
                "Decryption failed: integrity check did not pass (%s)" % type(exc).__name__
            )
        finally:
            shred(cipher_path)
            del key

        if progress:
            progress(1.0)
        self._report(file_id, "OK")
        return str(dest_path), filename

    def _report(self, file_id, result):
        try:
            self.api.access_result(file_id, result)
        except Exception:
            pass  # an audit write must never break the user's operation

    # ---- re-key one file (doc 02 Section 4.4, admin only) -----------

    def rekey_file(self, job_id, item, progress=None):
        """Decrypt with the admin's all-attributes key and re-encrypt under the
        current attribute versions. Returns the new versioned policy."""
        file_id = uuid.UUID(item["file_id"])
        old_key = None
        if item.get("ct_key"):
            old_key = abe_kem.decap(self.pk, self.sk, base64.b64decode(item["ct_key"]), file_id.bytes)
        if old_key is None:
            raise AccessDenied("The admin key cannot decrypt file %s" % file_id)

        logical = policy.to_logical(item["policy_versioned"])
        new_versioned = self.to_versioned(logical)
        new_key, new_ct_key = abe_kem.encap(self.pk, new_versioned, file_id.bytes)

        work = KEYSTORE_DIR / "tmp"
        work.mkdir(parents=True, exist_ok=True)
        old_cipher = work / ("%s.rekey.old" % file_id)
        plain = work / ("%s.rekey.plain" % file_id)
        new_cipher = work / ("%s.rekey.new" % file_id)
        try:
            self.api.s3_get_file(item["download_url"], str(old_cipher))
            if progress:
                progress(0.3)
            aes_stream.decrypt_file(str(old_cipher), str(plain), old_key, file_id.bytes)

            filename = None
            if item.get("enc_filename") and item.get("name_nonce"):
                filename = aes_stream.decrypt_filename(
                    base64.b64decode(item["enc_filename"]),
                    base64.b64decode(item["name_nonce"]),
                    old_key, file_id.bytes,
                )
            if filename is None:
                filename = "file-%s" % file_id

            aes_stream.encrypt_file(str(plain), str(new_cipher), new_key, file_id.bytes)
            enc_filename, name_nonce = aes_stream.encrypt_filename(filename, new_key, file_id.bytes)
            ciphertext_sha256 = sha256_file(str(new_cipher))
            ciphertext_size = new_cipher.stat().st_size
            if progress:
                progress(0.6)

            init = self.api.rekey_file_init(job_id, str(file_id))
            self.api.s3_put_file(init["upload_url"], str(new_cipher))
            if progress:
                progress(0.85)
            self.api.rekey_file_commit(job_id, str(file_id), {
                "policy_versioned": new_versioned,
                "ct_key": base64.b64encode(new_ct_key).decode("ascii"),
                "enc_filename": base64.b64encode(enc_filename).decode("ascii"),
                "name_nonce": base64.b64encode(name_nonce).decode("ascii"),
                "ciphertext_sha256": ciphertext_sha256,
                "ciphertext_size": ciphertext_size,
            })
        finally:
            for p in (old_cipher, plain, new_cipher):
                shred(p)
            del old_key, new_key
        if progress:
            progress(1.0)
        return new_versioned


# --------------------------------------------------------------- helpers

def sha256_file(path, block=1024 * 1024):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(block)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def shred(path):
    """Remove a temporary plaintext/ciphertext scratch file if it exists."""
    try:
        if path.exists():
            path.unlink()
    except OSError:
        pass


def safe_name(filename):
    """Never let a decrypted filename escape the download directory."""
    name = os.path.basename(filename.replace("\\", "/")).strip()
    if not name or name in (".", ".."):
        return "download.bin"
    return name


def login(api, username, password, keystore_password=None, force_reissue=False):
    """Login, fetch PK, issue or unlock the ABE secret key, and return a Vault.

    A stale key (or a missing keystore) triggers POST /keys/issue and a fresh
    local keystore write; otherwise the stored key is unlocked locally.
    """
    ks_password = keystore_password or password
    login_resp = api.login(username, password)
    me = api.me()
    pk = abe_kem.deserialize_pk(base64.b64decode(api.public_params()["pk"]))

    stored = None
    if not force_reissue and not login_resp.get("key_stale") and not me.get("key_stale"):
        try:
            stored = load_keys(username, ks_password)
        except FileNotFoundError:
            stored = None

    ecc_private = None
    if stored is not None:
        sk_b64 = stored["sk"]
        versioned = stored.get("versioned_attributes", [])
        if stored.get("ecc_priv"):
            ecc_private = base64.b64decode(stored["ecc_priv"])
    else:
        issue = api.issue_key()
        sk_b64 = issue["sk"]
        versioned = issue["versioned_attributes"]
        try:
            old = load_keys(username, ks_password)
            ecc_private = base64.b64decode(old["ecc_priv"]) if old.get("ecc_priv") else None
        except Exception:
            ecc_private = None
        if ecc_private is None:
            ecc_private, ecc_public = ecc_wrap.generate_keypair()
            api.register_ecc_public_key(base64.b64encode(ecc_public).decode("ascii"))
        save_keys(username, ks_password, sk_b64, versioned, ecc_private)

    sk = abe_kem.deserialize_sk(base64.b64decode(sk_b64))
    vault = Vault(api, me, pk, sk, versioned, ecc_private)
    vault._keystore_password = ks_password
    api.set_key_stale_handler(vault.refresh_key)
    return vault
