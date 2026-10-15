# 03: Cryptographic Design

## 1. Primitives

| Purpose | Primitive | Library |
|---|---|---|
| Bulk file encryption | AES-256-GCM (96-bit nonce, 128-bit tag) | `cryptography.hazmat.primitives.ciphers.aead.AESGCM` |
| Key derivation | HKDF-SHA256 | `cryptography` |
| Policy-based key encapsulation | CP-ABE, Bethencourt–Sahai–Waters 2007 (`CPabe_BSW07`), pairing group `SS512` | `charm-crypto` |
| Fallback key wrap | X25519 ECDH + HKDF + AES-GCM | `cryptography` |
| Password-based key store | scrypt (N=2^15, r=8, p=1) + AES-GCM | `cryptography` |
| Password hashing (server) | bcrypt | `passlib[bcrypt]` |
| Ciphertext fingerprint | SHA-256 | `hashlib` |

## 2. Hybrid scheme: CP-ABE as a KEM

CP-ABE encrypts **group elements** (in GT), not arbitrary bytes. We therefore use it as a **Key Encapsulation Mechanism**:

```
Encrypt(file, policy):
  R    ← random element of GT
  K    ← HKDF-SHA256(ikm = serialize(R), salt = file_id, info = b"securevault-file-key-v1", len = 32)
  CT_K ← CPabe_BSW07.encrypt(PK, R, versioned_policy)
  blob ← AESGCM_stream(K, file, file_id)
  store blob in S3; store CT_K + metadata in DB

Decrypt(file_id, SK):
  R    ← CPabe_BSW07.decrypt(PK, SK, CT_K)     # fails if attributes don't satisfy the policy
  K    ← HKDF-SHA256(serialize(R), salt=file_id, info=...)
  file ← AESGCM_stream_decrypt(K, blob, file_id)
```

**Why hybrid?** ABE costs pairing operations that scale linearly with policy size, which is milliseconds to hundreds of milliseconds. AES-GCM runs at hundreds of MB/s. ABE is applied once to a short value, and AES handles the bulk data. The benchmarks in doc 07 should show this clearly.

**Serialization:** use `charm.core.engine.util.objectToBytes / bytesToObject` with the pairing group to store CT_K, PK, and SK as bytes (base64 in JSON transport).

> charm-crypto checks: when `decrypt` fails because attributes don't satisfy the policy, BSW07 returns `False` instead of raising. Always check for that explicitly, and treat any exception as "access denied" too.

## 3. Attributes and policy format
- **Logical attributes** (seen by users): `DEPT_CSE`, `ROLE_FACULTY`, `YEAR_4`, …
- **Versioned attributes** (used in crypto): `DEPT_CSE_V1`, `ROLE_FACULTY_V3`, …
  - Use uppercase letters, digits, and underscores only. charm's policy parser handles these reliably. Avoid `:` and spaces.
- **Logical policy** (stored for display): `(DEPT_CSE and ROLE_FACULTY) or ROLE_HOD`
- **Versioned policy** (actually encrypted under): `(DEPT_CSE_V1 and ROLE_FACULTY_V3) or ROLE_HOD_V1`
  - The client rewrites the policy using the current versions from `GET /attributes`.
- **User key attributes:** the user's logical attributes, each suffixed with the *current* version at issuance.

## 4. File ciphertext format (chunked AES-GCM)

Single-shot GCM on a large file needs the whole file in memory. Chunking bounds memory use and detects truncation and reordering.

```
Header (32 bytes):
  magic         4  b"SVLT"
  format_ver    1  0x01
  reserved      3  0x000000
  chunk_size    4  uint32 BE (default 65536)
  nonce_prefix  8  random
  total_chunks  8  uint64 BE
  reserved      4

Then for i = 0 … n-1:
  ciphertext_i || tag_i(16)

nonce_i = nonce_prefix (8) || uint32_BE(i) (4)      → 12-byte nonce, never reused under K
AAD_i   = header || file_id (16 bytes, UUID) || uint32_BE(i) || final_flag (1 byte: 1 if last chunk)
```

- **Reordering** is caught because the chunk index is in both the nonce and the AAD.
- **Truncation** is caught because the last chunk must carry `final_flag=1`, and `total_chunks` is in the authenticated header.
- **Blob swapping** between files is caught because `file_id` is in the AAD.
- **Nonce reuse** cannot happen because K is fresh for every file version.

**Filename privacy:** the original filename is encrypted with K (separate nonce, AAD = `file_id || b"name"`) and stored as `enc_filename`. S3 object keys are random UUIDs.

## 5. Key lifecycle

| Key | Created | Stored | Lifetime |
|---|---|---|---|
| PK (ABE public params) | KA `setup()` once | DB / `pk.bin`, public | System lifetime |
| MSK (ABE master secret) | KA `setup()` once | `msk.enc`, AES-GCM under scrypt(`KA_PASSPHRASE`) | System lifetime; never leaves backend |
| SK_user (ABE secret key) | `/keys/issue` | Client: `~/.securevault/<user>.key.enc` (scrypt(password) + AES-GCM) | Until an attribute version changes |
| K (file key) | Per upload or re-key | Never stored; derived from R | One file version |
| ECC keypair (fallback) | Client on first login | Private key encrypted locally; public key in DB | User lifetime |
| JWT | Login | Client memory | 30 minutes |

## 6. Fallback: ECC per-recipient wrapping
Used if `charm-crypto` can't be installed, and as a comparison baseline in the report.

```
for each recipient u:
  eph       ← X25519 ephemeral keypair
  shared    ← ECDH(eph.priv, u.pub)
  KEK       ← HKDF(shared, salt=file_id, info=b"securevault-ecc-wrap-v1")
  wrapped_u ← AESGCM(KEK).encrypt(nonce, K, aad=file_id||u.id)
  store (file_id, u.id, eph.pub, nonce, wrapped_u)
```

Here K is 32 random bytes directly. The trade-off: the sender must know every recipient at upload time, and new users who later match a policy get nothing. That is exactly the problem ABE solves, and it makes a good report point.

## 7. Revocation design (versioned attributes)

**The problem:** a CP-ABE secret key embeds its attributes permanently. Removing `ROLE_FACULTY` from a user in the database does not stop their old key from decrypting anything encrypted under `ROLE_FACULTY`.

**The fix:** every attribute has a version number.
1. The admin revokes `ROLE_FACULTY` from user U. The attribute version goes from `v3` to `v4`.
2. All *other* holders of `ROLE_FACULTY` are flagged `key_stale = true`. Their next request gets a 409, and the client re-fetches its SK with `ROLE_FACULTY_V4`.
3. A `rekey_job` lists every file whose versioned policy contains `ROLE_FACULTY_V3`.
4. The **re-key worker** runs on the admin's machine with an admin SK holding all attributes. For each file it decrypts, generates a fresh R′ and K′, re-encrypts under the policy with `_V4`, uploads a new object, updates metadata, and deletes the old object.
5. U's old key holds `ROLE_FACULTY_V3`, so it no longer satisfies any current policy.

**Limits (state honestly in the report):**
- U keeps any plaintext they already downloaded. No system can prevent this.
- Until the re-key job finishes, U could still decrypt *not-yet-re-keyed* files if they can obtain the blobs. The backend also refuses metadata and URLs to users whose key is revoked, as a defense-in-depth layer.
- S3 **versioning must stay disabled** on the bucket (or old versions must be purged). Otherwise old ciphertext lingers.
- The admin key is powerful. It lives only on the admin machine, encrypted at rest.

## 8. Threat model

| Adversary | Capability | Mitigation | Result |
|---|---|---|---|
| Curious cloud / S3 insider | Reads all objects | Client-side AES-256-GCM | Learns ciphertext and sizes only |
| Leaked IAM keys / public bucket | Downloads bucket | Same as above, plus Block Public Access | Same |
| DB dump attacker | Reads all metadata | Holds only CT_K, no SK | Cannot derive K |
| Unauthorized user (wrong attributes) | Valid login, obtains blob + CT_K | CP-ABE policy | Decrypt returns `False` |
| Colluding users (e.g. one has `DEPT_CSE`, another `ROLE_FACULTY`) | Pool their keys | BSW07 per-user randomization makes it **collusion-resistant** | Cannot combine to satisfy the AND |
| Tampering attacker | Modifies, reorders, or truncates blob | GCM tags + AAD + SHA-256 | Detected; decryption aborts |
| Network MITM | Intercepts traffic | TLS; pre-signed URLs are HTTPS | Mitigated |
| Revoked user | Holds old SK | Versioned attributes + re-encryption | Locked out of re-keyed files |
| **Out of scope** | Compromised client, malicious KA | — | Documented limitation |
