# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Current state

This repository currently contains **only specs** (`documentation/`) — no code, no `docker-compose.yml`, no `crypto/`/`backend/`/`client/` directories, not even a git repo yet. Before writing any code, read `documentation/01` through `documentation/07` (they are the authoritative design) and `documentation/08_Claude_Code_Build_Prompt.md` (the phase-gated execution plan this project is meant to be built against).

If asked to start or continue implementation, follow `documentation/08_Claude_Code_Build_Prompt.md` literally: build phase by phase (0 → 4), stop at every **STOP** point described there, and wait for explicit confirmation before continuing to the next phase. Do not skip phases or build ahead.

## What SecureVault is

A zero-trust encrypted cloud storage system. Files are encrypted **client-side** with AES-256-GCM before upload; the AES file key is itself protected with Ciphertext-Policy Attribute-Based Encryption (CP-ABE, BSW07), so a file is decryptable only by users whose attributes satisfy its access policy (e.g. `DEPT_CSE AND ROLE_FACULTY`). Ciphertext lives in AWS S3, which — like the backend — is treated as untrusted for confidentiality. See `documentation/02_System_Architecture.md` for the full component/trust-boundary diagram.

## Non-negotiable global rules (from doc 08)

These apply to every line of code written in this repo:

1. **Never** let plaintext file content, the file key (K/R), or an ABE secret key reach the backend, S3, or any log line.
2. Crypto primitives come only from `cryptography` and `charm-crypto` — never hand-roll a primitive. Randomness only via `os.urandom`/`secrets`.
3. Python 3.8 compatibility everywhere (hard constraint from `charm-crypto`'s native build).
4. Secrets only via `.env` (never committed); always ship a matching `.env.example`.
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

## Commands (once the repo is scaffolded per doc 06 §1)

There is no code yet, so none of these exist until the corresponding phase is built. Once they do:

```bash
# Local environment
docker-compose up                              # postgres + backend (ABE runtime image)

# Crypto core tests (Phase 1)
pytest crypto/ --cov=crypto                    # run doc 07 tests C-01..C-12
pytest crypto/tests/test_aes_stream.py::test_name   # single test

# Backend (Phase 2)
python backend/scripts/init_ka.py              # ABE setup() -> pk.bin, msk.enc
python backend/scripts/seed_demo.py            # creates demo attributes/users
pytest backend/tests/ --cov=backend            # doc 07 tests B-01..B-07 (moto)
python backend/scripts/e2e.py                   # full round trip against REAL S3 only

# Client (Phase 3)
streamlit run client/app.py
python -m client.rekey_worker --job <id>       # admin re-encryption after revocation

# Benchmarks (Phase 4)
python benchmarks/bench.py                      # E1-E5, writes CSV + PNGs to benchmarks/plots/
```

## Key documents to consult while coding

| Doing this | Read this doc section |
|---|---|
| Changing the file ciphertext format | `03_Cryptographic_Design.md` §4 (fixed wire format) |
| Adding/changing a DB table or API route | `05_Database_and_API_Spec.md` (schema and endpoints are specified exactly) |
| Touching S3 access | `04_AWS_S3_Setup.md` §5 (`Storage` protocol contract) |
| Implementing revocation/rekey | `03_Cryptographic_Design.md` §7 and `02_System_Architecture.md` §4.4 |
| Writing a new test | `07_Testing_Benchmarks_and_Demo.md` §1 (test IDs are pre-specified, implement them, don't invent parallel ones) |
