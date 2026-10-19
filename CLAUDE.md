# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Current state

Phases 0 through 5 of `documentation/08_Claude_Code_Build_Prompt.md` are built:
the crypto core, the backend/Key Authority, the Streamlit client and re-key
worker, the E1-E5 benchmarks, the leakage tests, the hardening pass, and
`documentation/09_Report.md`. Treat docs 01-07 as the authoritative design and
doc 08 as the phase plan that produced the code; `README.md` is the operator
view (setup, commands, demo users).

All of it has been run, not just written: the full suite passes inside
`abe-runtime`, the report's benchmark tables are filled from a real 10-rep run,
and `e2e.py` plus the doc 07 Section 3 demo (steps 1-8, including revoke and
re-key) pass against a real S3 bucket in `ap-south-1`. Run the backend tests
against a separate database (`DATABASE_URL=...securevault_test`): the test
session drops every table and regenerates `pk.bin`/`msk.enc` on teardown.

The admin's issued key deliberately holds every version of its attributes
(`ROLE_FACULTY_V1`, `_V2`, ...). A revoke marks the admin stale too, and the
re-key worker must decrypt files still under the old version -- a current-only
admin key locks it out of exactly those files. Do not "simplify" this away.

If asked to change behaviour, keep the doc 08 global rules below intact -- they
are the point of the project, not style preferences.

## What SecureVault is

A zero-trust encrypted cloud storage system. Files are encrypted **client-side** with AES-256-GCM before upload; the AES file key is itself protected with Ciphertext-Policy Attribute-Based Encryption (CP-ABE, BSW07), so a file is decryptable only by users whose attributes satisfy its access policy (e.g. `DEPT_CSE AND ROLE_FACULTY`). Ciphertext lives in AWS S3, which — like the backend — is treated as untrusted for confidentiality. See `documentation/02_System_Architecture.md` for the full component/trust-boundary diagram.

## Non-negotiable global rules (from doc 08)

These apply to every line of code written in this repo:

1. **Never** let plaintext file content, the file key (K/R), or an ABE secret key reach the backend, S3, or any log line.
2. Crypto primitives come only from `cryptography` and `charm-crypto` — never hand-roll a primitive. Randomness only via `os.urandom`/`secrets`.
3. Python 3.8 compatibility everywhere (hard constraint from `charm-crypto`'s native build).
4. Secrets only via `.env` (never committed); always ship a matching `.env.example`.
   `backend/app/logging_filter.py` scrubs key material from log records as a
   backstop -- do not remove it or raise `MIN_BLOB_LENGTH` above 40 (base64 of a
   32-byte key is 44 characters).
5. Tests use `moto` for S3; only `scripts/e2e.py` is allowed to touch a real AWS account.
6. ABE `decrypt`/`decap` returning `False` (BSW07's "policy not satisfied" signal) and any exception during decrypt must both be treated as "access denied" (`None`) — never let one path raise while the other silently returns.

## Architecture (why the pieces are shaped this way)

The design only makes sense once you connect three documents: **02** (who talks to whom), **03** (the crypto that makes the trust boundaries real), and **05** (how that crypto's outputs are persisted). Key points that span files:

- **CP-ABE is used as a KEM, not to encrypt files directly** (doc 03 §2): ABE encrypts a random GT element `R`; `K = HKDF(R)` becomes the actual AES-256-GCM key for the file. ABE cost (pairing ops) is paid once per file on a 32-byte value; AES handles the bulk bytes. This hybrid split is the core performance argument for the whole project (see benchmark E4 in doc 07).
- **Attributes are versioned, logical vs. versioned policy are different strings** (doc 03 §3, §7): users and policies deal in logical attributes (`ROLE_FACULTY`); everything actually encrypted under uses versioned attributes (`ROLE_FACULTY_V3`). Revocation works by bumping an attribute's version — old secret keys silently stop satisfying any policy written against the new version. There is no key revocation list; re-encryption (the rekey worker, doc 02 §4.4) is how already-encrypted files catch up to the new version.
- **The backend is a Key Authority but must never see file keys** (doc 02 §2-3): it runs ABE `setup()`/`keygen()` once and issues per-user secret keys over TLS, but `encap`/`decap` only ever happen on the client. A DB dump yields ABE ciphertexts of `R`, never `K` or plaintext.
- **S3 is accessed only via short-lived pre-signed URLs** (doc 02, doc 04 §5): the backend never proxies file bytes. `storage.py` must implement the `Storage` protocol (`presign_put`, `presign_get`, `head`, `delete`) so S3 and `moto` are interchangeable — this is why tests never need real AWS.
- **The chunked AES-GCM file format binds reordering/truncation/swap detection into the AAD** (doc 03 §4): nonce = `nonce_prefix || chunk_index`, AAD = `header || file_id || chunk_index || final_flag`. Any change to this layout breaks every security test in doc 07 §1.1 — treat it as a fixed wire format, not an implementation detail to refactor.
- **`crypto/` is a shared package imported by both `backend/` and `client/`** (doc 06 §1) — it must stay dependency-light and Python-3.8-clean since it runs inside the same `abe-runtime` image/venv on both sides.
- **Revocation is multi-step and asynchronous** (doc 03 §7, doc 02 §4.4): revoke attribute -> bump version -> flag other holders `key_stale` (they get `409 KEY_STALE` until they re-fetch) -> enqueue a `rekey_job` -> an admin-privileged `rekey_worker.py` CLI (not the backend) decrypts-and-re-encrypts affected files with the admin's all-attributes key. The backend itself never holds enough ABE attributes to do this work.

## Commands

```bash
# Local environment: postgres + backend (:8000) + Streamlit client (:8501)
docker-compose up --build
docker-compose exec backend python backend/scripts/init_ka.py    # ABE setup() -> pk.bin, msk.enc
docker-compose exec backend python backend/scripts/seed_demo.py  # demo attributes/users

# Tests (SECUREVAULT_DEV=1 relaxes the .env placeholder checks; conftest sets it)
pytest crypto/ --cov=crypto                    # C-01..C-12
pytest backend/ --cov=backend                  # B-01..B-07 and S-01..S-03, S-05, on moto
pytest crypto/tests/test_aes_stream.py::test_c01_round_trip   # a single test

# Real AWS -- these two scripts only
python backend/scripts/e2e.py
python backend/scripts/s04_public_access_check.py

# Client
streamlit run client/app.py
python -m client.rekey_worker --list
python -m client.rekey_worker --job 3          # admin re-encryption after a revoke

# Benchmarks -> benchmarks/results.csv + benchmarks/plots/
python benchmarks/bench.py
python benchmarks/bench.py --only E1,E5 --no-abe   # works without charm-crypto

# HTTPS for the demo
python scripts/gen_self_signed_cert.py
```

Without charm-crypto installed, only the non-ABE crypto tests run
(`test_aes_stream`, `test_ecc_wrap`, `test_keystore`, `test_policy`) -- anything
importing `crypto.abe_kem` needs the `abe-runtime` image.

## Client-side invariants (Phase 3)

- `client/vault.py` is the only module that ever holds a file key. `client/api.py`
  carries base64 the server already issued and nothing more; the Streamlit pages
  do no crypto of their own.
- **Order matters on upload:** `POST /files/init` comes *first*, because the chunk
  AAD and the KEM's HKDF salt are bound to the backend's `file_id`. Since init
  needs `ciphertext_size`, it is predicted with `aes_stream.ciphertext_size_for()`
  rather than measured after encrypting. Do not reorder these.
- `409 KEY_STALE` is handled automatically: `client/api.py` re-issues the key via
  the handler `client/vault.login()` installs, rewrites the keystore, and retries
  once. Keep that one-shot guard -- a retry loop on a persistent 409 would hammer
  `/keys/issue`.
- Denial and tampering are distinct paths: `AccessDenied` (decap returned `None`)
  renders the red "Access denied by policy" box, `IntegrityError` (bad sha256 or
  GCM tag) renders an integrity failure. Both report to `/access-result`, and
  neither leaves partial plaintext behind.
- Two additive API endpoints exist beyond doc 05's table -- `GET
  /keys/ecc/recipients`, and `enc_filename`/`name_nonce` on the rekey job file
  list -- both public data, both needed by the client. Doc 09 Section 4 records why.

## Key documents to consult while coding

| Doing this | Read this doc section |
|---|---|
| Changing the file ciphertext format | `03_Cryptographic_Design.md` §4 (fixed wire format) |
| Adding/changing a DB table or API route | `05_Database_and_API_Spec.md` (schema and endpoints are specified exactly) |
| Touching S3 access | `04_AWS_S3_Setup.md` §5 (`Storage` protocol contract) |
| Implementing revocation/rekey | `03_Cryptographic_Design.md` §7 and `02_System_Architecture.md` §4.4 |
| Writing a new test | `07_Testing_Benchmarks_and_Demo.md` §1 (test IDs are pre-specified, implement them, don't invent parallel ones) |
| Working on the client or re-key worker | `02_System_Architecture.md` Section 4.2-4.4, and the invariants above |
| Writing the report or reading results | `09_Report.md` (threat model, limitations, benchmark tables) |
