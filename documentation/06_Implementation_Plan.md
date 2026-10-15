# 06: Implementation Plan

## 1. Repository layout
```
securevault/
├── docker-compose.yml           # postgres + backend
├── abe-runtime/
│   └── Dockerfile               # python:3.8 + GMP + PBC + charm-crypto
├── crypto/                      # shared package, installed in client and backend
│   ├── __init__.py
│   ├── aes_stream.py            # chunked AES-GCM (doc 03 §4)
│   ├── abe_kem.py               # BSW07 setup/keygen/encap/decap + serialization
│   ├── ecc_wrap.py              # X25519 fallback
│   ├── keystore.py              # scrypt + AES-GCM local key files
│   ├── policy.py                # logical → versioned policy rewrite, validation
│   └── tests/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py            # pydantic-settings from .env
│   │   ├── db.py  models.py  schemas.py
│   │   ├── auth.py              # bcrypt, JWT, deps
│   │   ├── key_authority.py     # loads msk.enc, keygen
│   │   ├── storage.py           # S3 + moto implementations
│   │   ├── audit.py
│   │   └── routes/ (auth.py keys.py files.py admin.py)
│   ├── alembic/
│   ├── scripts/ (init_ka.py seed_demo.py)
│   ├── tests/
│   └── .env.example
├── client/
│   ├── app.py                   # Streamlit entry
│   ├── api.py                   # typed REST client
│   ├── pages/ (1_Upload.py 2_Files.py 3_Admin.py)
│   └── rekey_worker.py          # admin CLI
├── benchmarks/ (bench.py plots/)
└── docs/                        # these documents + report
```

## 2. Environment
- **ABE runtime:** a Docker image built from `python:3.8-slim-bullseye`. It installs `build-essential libgmp-dev flex bison libssl-dev`, builds **PBC 0.5.14** from source, then installs `charm-crypto` from the GitHub source (`./configure.sh && make && make install`).
- Use this image (or a Python 3.8 venv with the same libraries) for **both** the backend and the client, since both import `crypto/`.
- Pin everything in `requirements.txt`: `cryptography`, `fastapi`, `uvicorn`, `sqlalchemy`, `psycopg2-binary`, `alembic`, `python-jose`, `passlib[bcrypt]`, `boto3`, `moto`, `streamlit`, `requests`, `pytest`, `matplotlib`.
- **Risk:** if the charm build fails after one focused day, set `WRAP_MODE=ECC` and continue. Phases 2–4 work in both modes.

## 3. Phases (each ends in a STOP point)

### Phase 0: Environment & proof of ABE (days 1–2)
- Build `abe-runtime`. Run a script: `setup → keygen(['DEPT_CSE_V1','ROLE_FACULTY_V1']) → encrypt R under '(DEPT_CSE_V1 and ROLE_FACULTY_V1)' → decrypt`, then decrypt with the wrong attributes.
- `docker-compose up` brings Postgres up.
- **STOP:** ABE hello-world prints OK for the right key and DENIED for the wrong key. Postgres is reachable.

### Phase 1: Crypto core (days 3–6)
- `aes_stream.py`: `encrypt_file(in_path, out_path, key, file_id)` and `decrypt_file(...)`, streaming in 64 KB chunks, with the header and AAD exactly as in doc 03.
- `abe_kem.py`: `setup()`, `keygen(pk, msk, attrs)`, `encap(pk, policy) -> (K, ct_bytes)`, `decap(pk, sk, ct_bytes) -> K | None`, `serialize/deserialize`.
- `ecc_wrap.py`, `keystore.py`, `policy.py` (with a grammar validator that allows only known attributes, `and`, `or`, and parentheses).
- Tests: round trip at 0 B, 1 B, 64 KB exactly, 10 MB; tamper one byte, swap chunks, truncate the last chunk, swap file_id; wrong-attribute decap gives `None`; **collusion test** (two users each holding half the AND each fail individually).
- **STOP:** `pytest crypto/` is green with at least 90% coverage of `crypto/`.

### Phase 2: Backend (days 7–11)
- Models + Alembic migration (doc 05).
- `scripts/init_ka.py`: runs `setup()`, writes `pk.bin` and `msk.enc`.
- `scripts/seed_demo.py`: creates attributes and users `admin`, `prof_a`, `prof_b`, `hod`, `student_s`.
- Routes: auth, keys, files, admin. Stale-key guard middleware. Audit writes.
- `storage.py` with S3 + moto. All tests use moto.
- **STOP:** `pytest backend/` is green, and an end-to-end script (`scripts/e2e.py`) uploads and downloads against **real S3** using the crypto package.

### Phase 3: Client (days 12–16)
- Streamlit: login → auto key fetch / stale handling → keystore unlock.
- **Upload page:** file picker, policy builder (rows of attribute multiselects joined by AND, rows joined by OR), mode toggle ABE/ECC, progress bar.
- **Files page:** table with owner, policy, and size; a Download button; denial shown as a red "Access denied by policy" box.
- **Admin page:** users, grant/revoke attributes, rekey-job progress, audit table.
- `rekey_worker.py` CLI: `python -m client.rekey_worker --job 3`.
- **STOP:** All five seeded users behave per the demo script on real S3.

### Phase 4: Revocation, benchmarks, hardening (days 17–21)
- Full revocation flow with stale keys and re-encryption. Verify that the revoked user is denied after the job.
- `benchmarks/bench.py`:
  - AES encrypt/decrypt time at 1, 10, 50, 100 MB
  - ABE encap/decap time against number of policy attributes (1–10) and keygen time against number of user attributes
  - ECC wrap time against number of recipients (1–50), compared with a single ABE encap
  - Plots saved as PNGs
- Hardening: rate-limit login (simple in-memory), HTTPS with a self-signed cert, `.env` checks, no secrets in logs.
- **STOP:** Doc 07's demo script runs cleanly end to end, and the plots exist.

### Phase 5: Report & presentation (days 22–25)
- Architecture diagram, threat model table, benchmark analysis, limitations, future work.

## 4. Timeline summary
| Week | Phases |
|---|---|
| 1 | 0, 1 |
| 2 | 2 |
| 3 | 3 |
| 4 | 4, 5 |

## 5. Definition of done
- [ ] No plaintext, K, or SK in any server log, DB column, or S3 object (verified by grep tests in doc 07)
- [ ] All test suites green
- [ ] Demo script passes on real S3 in `ap-south-1`
- [ ] Benchmarks plotted and explained
- [ ] README with setup steps; `.env.example`; no committed secrets
