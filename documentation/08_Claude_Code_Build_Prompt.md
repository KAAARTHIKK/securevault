# 08: Claude Code Build Prompt (SecureVault)

> Paste this whole file into Claude Code in VS Code, from the repo root, with `docs/01–07` copied into `docs/`. Claude must stop at every **STOP** and wait for my "continue".

---

You are building **SecureVault**, a zero-trust encrypted cloud storage system. The authoritative specs are in `docs/`:
- `01_Project_Overview_and_Requirements.md`: requirements (FR/NFR)
- `02_System_Architecture.md`: components and flows
- `03_Cryptographic_Design.md`: **follow exactly**: KEM construction, file format, AAD, versioned attributes
- `04_AWS_S3_Setup.md`: S3 config and storage contract
- `05_Database_and_API_Spec.md`: schema and endpoints
- `06_Implementation_Plan.md`: repo layout and phases
- `07_Testing_Benchmarks_and_Demo.md`: tests and demo

## Global rules
1. Read all docs first. If any doc is ambiguous or contradictory, list the issues and ask before coding.
2. **Never** send plaintext, file keys (K/R), or ABE secret keys to the backend, S3, or logs.
3. Only use `cryptography` and `charm-crypto` for crypto. Never hand-roll primitives. Use `os.urandom`/`secrets` for randomness.
4. Python 3.8 compatibility everywhere (charm constraint). Type hints, docstrings, `ruff` clean.
5. Secrets only via `.env`, never committed. Provide `.env.example`.
6. Tests use **moto** for S3. Only `scripts/e2e.py` touches real S3.
7. Small, focused git commits per sub-step with conventional messages. **Do not add Co-Authored-By lines.**
8. At each STOP: print a summary of files created, test results, and anything I must do manually (e.g., AWS steps). Then wait.

---

## Phase 0: Environment & ABE proof
1. Create the repo layout from doc 06 §1 (empty modules are fine).
2. `abe-runtime/Dockerfile`: python:3.8-slim-bullseye, build deps, PBC 0.5.14 from source, charm-crypto from source, then `pip install -r requirements.txt`.
3. `docker-compose.yml`: `db` (postgres:15, volume, healthcheck) and `backend` (built from abe-runtime, mounts repo, `uvicorn app.main:app --reload`).
4. `scripts/abe_smoke.py`: BSW07 on SS512, encrypt a random GT element under `(DEPT_CSE_V1 and ROLE_FACULTY_V1)`, decrypt with a matching and a non-matching key, print OK/DENIED.

**STOP 0:** Show the build command, the smoke-test output, and `docker compose ps`. If the charm build fails, show the error and propose fixes. Do not switch to ECC-only without my approval.

---

## Phase 1: Crypto core (`crypto/`)
Implement per doc 03:
- `aes_stream.py`: streaming chunked AES-256-GCM with the exact header, nonce, and AAD layout; filename encryption helper.
- `abe_kem.py`: `setup`, `keygen`, `encap(pk, versioned_policy, file_id) -> (K, ct_bytes)`, `decap(pk, sk, ct_bytes, file_id) -> Optional[bytes]`, `serialize`/`deserialize` for pk, sk, and ct. HKDF derivation as specified. Treat a `False` return or any exception from decrypt as `None`.
- `ecc_wrap.py`, `keystore.py` (scrypt N=2^15, r=8, p=1 + AES-GCM; versioned file format), `policy.py` (tokenizer + validator + logical→versioned rewrite).
- Tests C-01 … C-12 from doc 07.

**STOP 1:** Show the `pytest crypto/ --cov=crypto` summary.

---

## Phase 2: Backend
1. SQLAlchemy models + Alembic migration exactly per doc 05 §1.
2. `config.py` (pydantic-settings), `auth.py` (bcrypt, JWT HS256, `get_current_user`, `require_admin`).
3. `key_authority.py` + `scripts/init_ka.py` (setup → `pk.bin`, `msk.enc` encrypted with `KA_PASSPHRASE` via the keystore format).
4. `storage.py`: `Storage` protocol, `S3Storage` (boto3, s3v4, presign put/get with `ContentType=application/octet-stream`, head, delete), selected by `STORAGE_BACKEND`.
5. Routes per doc 05 §2, including the stale-key guard (409 `KEY_STALE`), revocation logic, rekey-job endpoints, and the audit log.
6. `scripts/seed_demo.py` (attributes + five users from doc 07 §3).
7. Tests B-01 … B-07 with moto.
8. `scripts/e2e.py`: login → issue key → encrypt → init → PUT to the real S3 URL → complete → download → decrypt → compare hashes.

**STOP 2:** Show test results. Tell me the exact AWS steps from doc 04 I must complete before running `e2e.py`. Wait for me to run it and report back.

---

## Phase 3: Client
1. `client/api.py`: typed wrapper over every endpoint; auto-handle 409 by re-issuing the key and updating the keystore.
2. Streamlit `app.py` + pages: Login, Upload (policy builder with OR-of-AND rows using multiselects; ABE/ECC toggle; progress), Files (list; download; red "Access denied by policy"; reports access-result), Admin (users, grant/revoke, rekey jobs with progress, audit table).
3. `client/rekey_worker.py` CLI per doc 02 §4.4, using the admin key.
4. Temp files: decrypted output goes to a user-chosen path; delete any temp ciphertext after use.

**STOP 3:** Give me the run commands. I will run demo steps 1–5 manually and report.

---

## Phase 4: Revocation, benchmarks, hardening
1. Verify the full revocation path (demo steps 7–8). Add test S-05.
2. Security tests S-01 … S-04.
3. `benchmarks/bench.py`: experiments E1–E5 (10 runs each, mean ± std), CSV output + matplotlib PNGs in `benchmarks/plots/`.
4. Hardening: login rate limit, self-signed HTTPS option, a secret-scrubbing logging filter, startup check that refuses to run if `.env` values are defaults.
5. Root `README.md`: prerequisites, setup, AWS steps link, run commands, demo script.

**STOP 4:** Show all test results, list the plots, and confirm each Definition-of-Done item from doc 06 §5 with evidence.
