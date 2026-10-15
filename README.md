# SecureVault

Zero-trust encrypted cloud storage with attribute-based access control.

Files are encrypted **on the client** with chunked AES-256-GCM before they ever
leave the machine. The AES file key is never stored anywhere: it is derived from
a random group element that is sealed with **CP-ABE (BSW07)** under a policy such
as `DEPT_CSE and ROLE_FACULTY`, so a file is decryptable only by a user whose
attributes satisfy that policy. Ciphertext lives in AWS S3, reached only through
short-lived pre-signed URLs. Both S3 and the backend are treated as untrusted
for confidentiality — a full database dump plus every stored object yields no
plaintext and no file key.

The authoritative design is in [`documentation/`](documentation/) (docs 01–08);
[`documentation/09_Report.md`](documentation/09_Report.md) is the write-up.

## How it fits together

```
 Streamlit client  ──encrypt/decrypt here──┐
   crypto/ (AES-GCM, CP-ABE KEM, X25519)   │
        │  JWT over TLS                    │  pre-signed PUT/GET
        ▼                                  ▼
 FastAPI backend ── PostgreSQL        AWS S3 (ciphertext only)
   = Key Authority: runs ABE setup()/keygen(), issues per-user
     secret keys, stores metadata. Never sees K or plaintext.
```

- **Hybrid, not pure ABE.** ABE encrypts a random `GT` element `R`; `K = HKDF(R)`
  is the AES-256-GCM key. Pairing cost is paid once per file on 32 bytes while
  AES moves the bulk bytes (benchmark E4).
- **Versioned attributes.** Users and policies are written in logical attributes
  (`ROLE_FACULTY`); everything is encrypted under versioned ones
  (`ROLE_FACULTY_V3`). Revocation bumps the version, so old keys silently stop
  satisfying new policies — there is no revocation list.
- **Re-encryption is a client job.** After a revoke, the backend queues a
  `rekey_job`; `client/rekey_worker.py` (run by an admin) decrypts and
  re-encrypts the affected files. The backend holds MSK but no attribute key, so
  it *cannot* do this itself.

## Quick start

```bash
cp backend/.env.example backend/.env     # then fill in real values
python -c "import secrets; print(secrets.token_hex(32))"   # JWT_SECRET, KA_PASSPHRASE

docker-compose up --build                # postgres + backend (:8000) + client (:8501)

docker-compose exec backend python backend/scripts/init_ka.py    # ABE setup(): pk.bin, msk.enc
docker-compose exec backend python backend/scripts/seed_demo.py  # demo attributes and users
```

Open the client at <http://localhost:8501> and sign in. The ABE runtime image
(`abe-runtime/Dockerfile`: Python 3.8 + PBC 0.5.14 + charm-crypto) is used for
the backend *and* the client, because both import `crypto/`.

`.env` placeholders from `.env.example` are rejected at startup. Set
`SECUREVAULT_DEV=1` to relax that for local work and tests.

### Seeded demo users

| User | Password | Attributes |
|---|---|---|
| `admin` | `admin-pass` | every attribute (needed to run the re-key worker) |
| `prof_a` | `prof-a-pass` | `DEPT_CSE`, `ROLE_FACULTY` |
| `prof_b` | `prof-b-pass` | `DEPT_CSE`, `ROLE_FACULTY` |
| `hod` | `hod-pass` | `DEPT_CSE`, `ROLE_HOD`, `ROLE_FACULTY` |
| `student_s` | `student-s-pass` | `DEPT_CSE`, `ROLE_STUDENT`, `YEAR_4` |

Demo passwords only — change them anywhere real.

## Commands

```bash
# crypto core tests (C-01..C-12)
pytest crypto/ --cov=crypto

# backend tests (B-01..B-07) and leakage tests (S-01..S-03, S-05), on moto
pytest backend/ --cov=backend

# full round trip against REAL S3 (the only script allowed to touch AWS)
python backend/scripts/e2e.py
python backend/scripts/s04_public_access_check.py     # S-04: bucket must be private

# client
streamlit run client/app.py
python -m client.rekey_worker --list
python -m client.rekey_worker --job 3                 # admin re-encryption after a revoke

# benchmarks E1-E5 -> benchmarks/results.csv + benchmarks/plots/*.png
python benchmarks/bench.py
python benchmarks/bench.py --only E1,E5 --no-abe      # without the ABE runtime

# HTTPS for the demo (the ABE secret key travels over this connection)
python scripts/gen_self_signed_cert.py
uvicorn backend.app.main:app --host 0.0.0.0 --port 8443 \
    --ssl-keyfile certs/server.key --ssl-certfile certs/server.crt
```

## Using the client

**Sign in** fetches the ABE public parameters, then either issues a fresh secret
key (first login, or after a revoke marked the key stale) or unlocks the one
cached at `~/.securevault/<user>.key.enc`. That file is scrypt + AES-GCM
protected by your keystore password and never leaves the machine. If an
attribute is revoked while you are signed in, the backend answers `409
KEY_STALE`; the client absorbs that automatically — it re-issues the key,
rewrites the keystore, and retries the request once. **Re-fetch ABE key** in the
sidebar does the same thing on demand.

**Upload** picks a file, builds a policy (attributes within a row are ANDed, rows
are ORed), and chooses `ABE` or the `ECC` fallback. Encryption, the pre-signed
PUT and the metadata commit all happen from this page.

**Files** lists what the server knows. Filenames are themselves encrypted, so a
name appears only once your key decrypts it. Policy denial surfaces as a red
*"Access denied by policy"* box: ABE decapsulation returned no key, so nothing
was decrypted locally. A tampered object fails its SHA-256 or a chunk's GCM tag
and reports an integrity failure instead, writing no plaintext.

**Admin** (admins only) grants and revokes attributes, shows re-key job progress
with a **Run re-key now** button, and renders the audit log.

## Repository layout

| Path | What it is |
|---|---|
| `crypto/` | shared package: `aes_stream`, `abe_kem`, `ecc_wrap`, `keystore`, `policy` |
| `backend/app/` | FastAPI app, Key Authority, S3 storage, audit, routes |
| `client/` | Streamlit UI, typed REST client, crypto glue (`vault.py`), re-key worker |
| `benchmarks/` | E1–E5 measurements, CSV and plots |
| `abe-runtime/` | Python 3.8 + PBC + charm-crypto image |
| `documentation/` | design docs 01–08 and the report (09) |

## Security notes

- A file key `K`, an ABE secret key, and plaintext exist only in the client
  process. Tests S-01–S-03 and S-05 scan every database column, the server logs,
  the API responses and the stored S3 object to prove it.
- Object keys are `objects/<uuid>/<version>.svlt` and carry no filename.
- Login is rate-limited per `(username, client IP)`; failures are audited as
  `LOGIN_FAILED`.
- A secret-scrubbing logging filter sits on every log handler, so a traceback or
  an access-log line cannot print a pre-signed URL signature, a bearer token, or
  a base64/hex key even by accident.
- Pre-signed URLs are short-lived (`PRESIGN_TTL_SECONDS`, 300 s by default) and
  the backend never proxies file bytes.
- `pk.bin`, `msk.enc`, `*.key.enc`, `.env` and `certs/` are gitignored. No
  secret is committed.

**Known limits** (detail in [the report](documentation/09_Report.md)): the Key
Authority holds MSK and could mint any key — a single-authority trust
assumption; a revoked user keeps whatever plaintext they already downloaded, and
there is a window until the re-key job finishes; pairing-based ABE is not
post-quantum.
