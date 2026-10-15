# 09: Report — SecureVault

Zero-trust encrypted cloud storage with CP-ABE access control.

This document is the Phase 5 deliverable from doc 06: architecture, threat model,
benchmark analysis, limitations and future work. Docs 01–08 remain the
authoritative design; this one explains and evaluates what was built.

> **Numbers:** the benchmark tables below are filled from `benchmarks/results.csv`
> after running `python benchmarks/bench.py` inside the `abe-runtime` container.
> Cells marked `___` are waiting on that run on the machine you are reporting
> from — record the CPU, RAM and Python version alongside them, because pairing
> timings are hardware-sensitive and are not transferable between machines.

---

## 1. Problem and goal

Mainstream cloud storage protects data *from other tenants*, not *from the
provider*. S3 server-side encryption leaves AWS holding the keys, so AWS — or
anyone with stolen IAM credentials — can read the objects. Sharing is expressed
as per-user ACLs, which do not scale to statements like "any CSE faculty member".

SecureVault targets both problems at once:

1. **Confidentiality against the infrastructure.** Encrypt on the client, with
   keys the server never sees. A full DB dump plus every S3 object must yield no
   plaintext.
2. **Access control by attributes, not identities.** The data owner states a
   *policy* (`DEPT_CSE and ROLE_FACULTY`) at upload time, and the cryptography
   itself enforces it at decryption time — no server-side permission check to
   bypass or misconfigure.

## 2. Architecture

```
┌────────────────────────── trusted (client machine) ──────────────────────────┐
│  Streamlit client (client/)                                                  │
│    crypto/aes_stream  chunked AES-256-GCM over the file                      │
│    crypto/abe_kem     CP-ABE BSW07 used as a KEM over a 32-byte key          │
│    crypto/ecc_wrap    X25519 per-recipient fallback                          │
│    crypto/keystore    scrypt + AES-GCM at ~/.securevault/<user>.key.enc      │
│    K, plaintext and SK exist ONLY here                                       │
└───────────┬──────────────────────────────────────────────┬───────────────────┘
            │ JWT over TLS                                │ pre-signed PUT/GET
            │ (metadata, CT_K, ABE secret key issuance)    │ (ciphertext bytes)
┌───────────▼──────────────────────────────┐   ┌───────────▼───────────────────┐
│ FastAPI backend (backend/) = Key Authority│   │ AWS S3                        │
│  setup()/keygen(), issues per-user SK     │   │  objects/<uuid>/<ver>.svlt    │
│  metadata, policies, CT_K, audit log      │   │  ciphertext only, no filename │
│  presigns S3 URLs; never proxies bytes    │   │  untrusted for confidentiality│
│  untrusted for confidentiality            │   └───────────────────────────────┘
└───────────┬───────────────────────────────┘
            │
      PostgreSQL (users, attributes, files, rekey_jobs, audit_log)
```

Two trust boundaries matter. Everything left of the first is trusted; the
backend, the database and S3 all sit on the untrusted side for
*confidentiality*, while the backend remains trusted for *availability* and
*integrity of metadata* (it could delete rows or refuse service, but not read
files).

### 2.1 The hybrid KEM construction

CP-ABE operates on group elements and costs pairing operations, so it is never
used on file bytes. Per file:

```
R           <- random element of GT
CT_K        <- ABE.encrypt(PK, R, versioned_policy)     # stored in the DB
K           <- HKDF-SHA256(serialize(R), salt=file_id, info="securevault-file-key-v1")
ciphertext  <- AES-256-GCM-stream(file, K)              # stored in S3
```

Decryption reverses it: `R = ABE.decrypt(PK, SK, CT_K)` succeeds only if the
user's attributes satisfy the policy, then the same HKDF rederives `K`. ABE cost
is therefore a per-file constant, independent of file size — the claim measured
as E4.

The HKDF salt is the file's UUID, so the same `R` under two files would still
give different AES keys, and `K` is domain-separated from anything else derived
from `R`.

### 2.2 The file format

Fixed wire format (doc 03 §4), 32-byte header then `ciphertext_i || tag_i`:

```
nonce_i = nonce_prefix(8) || uint32_BE(i)
aad_i   = header || file_id(16) || uint32_BE(i) || final_flag(1)
```

Binding the chunk index into both the nonce and the AAD makes chunk **reordering**
detectable; the final flag plus `total_chunks` in the header makes **truncation**
detectable; `file_id` in the AAD makes **blob swapping** between files
detectable. Decryption writes to `<out>.part` and only renames on success, so a
failed decrypt leaves no partial plaintext. Tests C-01–C-05 cover each case.

Filenames are themselves encrypted (`AAD = file_id || "name"`), and object keys
are `objects/<uuid>/<version>.svlt`, so the S3 listing leaks neither names nor
extensions (S-03).

### 2.3 Versioned attributes and revocation

Users and policies are written in **logical** attributes; everything is
encrypted under **versioned** ones:

| Layer | Example |
|---|---|
| user-facing / stored for display | `DEPT_CSE and ROLE_FACULTY` |
| actually encrypted under | `DEPT_CSE_V1 and ROLE_FACULTY_V3` |

Revoking `ROLE_FACULTY` from a user runs five steps
(`DELETE /admin/users/{id}/attributes/{name}`):

1. drop the user↔attribute row;
2. bump `attributes.current_version` (v3 → v4);
3. mark every *remaining* holder `key_stale` — they get `409 KEY_STALE` on file
   operations until they re-fetch a key minted for `_V4`;
4. create a `rekey_job` listing the active files whose versioned policy mentions
   `ROLE_FACULTY_V3`, and flag those files `rekeying`;
5. write a `REVOKE` audit row.

There is no revocation list to consult and no key to "turn off": the revoked
user's key is for `_V3`, and every new policy names `_V4`, so it satisfies
nothing. Already-encrypted files catch up through re-encryption, performed by
`client/rekey_worker.py` under the **admin's** all-attributes key — the backend
holds MSK but no attribute key, and so is structurally unable to read the files
it is coordinating.

## 3. Threat model

| # | Adversary / scenario | Capability assumed | Outcome | Mechanism |
|---|---|---|---|---|
| T1 | Cloud provider or stolen IAM credentials | Reads every S3 object | No plaintext | Client-side AES-256-GCM; S3 never sees `K` (S-02) |
| T2 | Database dump (SQL injection, stolen backup, insider DBA) | Reads every column | No plaintext, no `K` | Only `CT_K` is stored — an ABE ciphertext of `R` (S-01) |
| T3 | Compromised backend process | Full code execution server-side | Reads future metadata and *could mint keys*; cannot read existing files without attributes | `encap`/`decap` only run client-side; see L1 |
| T4 | Unauthorized user with a valid account | Authenticates, requests any file | `GET /files/{id}` succeeds, decryption does not | ABE `decrypt` returns `False` → `decap` returns `None` → "Access denied by policy" (C-07) |
| T5 | Two users colluding to pool partial attributes | Both keys, both halves of an AND | Both fail | BSW07 randomizes each key with a per-user secret; components do not combine (C-08) |
| T6 | Revoked user | Old `_V3` key, raw DB row, raw S3 object | Denied after re-key | Version bump + re-encryption (S-05) |
| T7 | Active network attacker on the object store | Flips, reorders, truncates, or swaps ciphertext | Detected, no plaintext written | SHA-256 check then per-chunk GCM tag over the AAD (C-02–C-05) |
| T8 | Passive network observer | Sees traffic | Sees ciphertext only | TLS; `scripts/gen_self_signed_cert.py` for the demo |
| T9 | Password guessing against the API | Repeated `/auth/login` | Throttled, audited | In-memory per-(user, IP) limiter → `429 RATE_LIMITED`, `LOGIN_FAILED` rows |
| T10 | Anonymous internet user hitting the bucket | Knows bucket and key names | Denied | Public-access block, no public ACL, pre-signed URLs only (S-04) |
| T11 | Stolen client machine | Has `~/.securevault/<user>.key.enc` | Needs the keystore password | scrypt (N=2¹⁵, r=8, p=1) + AES-GCM (C-10) |
| T12 | Leaky logs | Reads application logs | Nothing useful | No key or plaintext logged deliberately, plus a secret-scrubbing `logging.Filter` on every handler that redacts pre-signed signatures, bearer tokens and base64/hex key blobs (S-01, `test_logging_filter.py`) |

**Explicitly out of scope:** a compromised *client* (it legitimately holds `K`
and `SK`); traffic analysis of file sizes and access times, which the design does
not hide; and anything a user does with plaintext after a successful decrypt.

## 4. Implementation summary

| Component | Files | Notes |
|---|---|---|
| Crypto core | `crypto/` (5 modules, ~440 lines) | Only `cryptography` and `charm-crypto`; no hand-rolled primitive; randomness from `os.urandom` |
| Backend | `backend/app/` (13 modules) | FastAPI, SQLAlchemy, Alembic, bcrypt + JWT (HS256), `Storage` protocol so S3 and moto are interchangeable |
| Client | `client/` (7 modules) | Streamlit UI, typed REST client, `vault.py` holding every crypto call, admin re-key worker CLI |
| Tests | `crypto/tests/`, `backend/tests/` | C-01–C-12, B-01–B-07, S-01–S-03, S-05, plus rate-limit, log-scrubbing and size-prediction tests |
| Benchmarks | `benchmarks/bench.py` | E1–E5, mean ± std over 10 repetitions, CSV + PNG output |

Two deviations from the doc 05 API table were needed to make Phase 3 work, both
additive and both public-data-only:

- `GET /keys/ecc/recipients` — ECC wrapping needs each recipient's X25519
  *public* key, and nothing else exposed it.
- `GET /admin/rekey-jobs/{id}/files` now also returns `enc_filename` and
  `name_nonce`, because the worker re-encrypts the filename under the new file
  key and must first recover it with the old one.

The client absorbs `409 KEY_STALE` itself (doc 08 Phase 3 item 1): `client/api.py`
installs a handler that calls `POST /keys/issue`, swaps the secret key in place,
rewrites the local keystore and retries the failed request exactly once, so a
revoke elsewhere does not surface as an error the user must resolve by hand. A
second consecutive 409 propagates rather than looping.

One ordering correction was made to the upload flow: `POST /files/init` is called
**before** encryption, because the chunk AAD and the KEM's HKDF salt are bound to
the backend's `file_id`. Since `/files/init` itself needs `ciphertext_size`, the
size is computed from the plaintext size with `aes_stream.ciphertext_size_for()`
rather than measured after encrypting (test:
`test_ciphertext_size_prediction_matches_reality`).

## 5. Benchmark analysis

Repeat each measurement 10×, report mean ± std. Record the machine:

> CPU `___`, RAM `___`, OS `___`, Python 3.8 in `abe-runtime`, pairing group SS512.

### E1 — AES-256-GCM streaming vs file size

| Size | Encrypt (ms) | Decrypt (ms) | Throughput (MB/s) |
|---|---|---|---|
| 1 MB | `___` | `___` | `___` |
| 10 MB | `___` | `___` | `___` |
| 50 MB | `___` | `___` | `___` |
| 100 MB | `___` | `___` | `___` |

Expected shape: **linear in size**, with throughput roughly flat — the 64 KB
chunking bounds memory without hurting throughput, since AES-NI dominates.

### E2 — ABE encap/decap vs policy size

| Attributes in policy | Encap (ms) | Decap (ms) | `CT_K` size (bytes) |
|---|---|---|---|
| 1 … 10 | `___` | `___` | `___` |

Expected shape: **linear in the number of attributes**, since BSW07 does work per
leaf of the policy tree. Decap is typically the more expensive side (pairings per
satisfied leaf). Absolute values are in the milliseconds — three to four orders
of magnitude above AES on the same 32 bytes, which is exactly why the design
never puts file bytes through ABE.

### E3 — ABE keygen vs user attributes

| Attributes in key | Keygen (ms) | `SK` size (bytes) |
|---|---|---|
| 1 … 10 | `___` | `___` |

Expected shape: linear. This cost is paid by the Key Authority once per issuance
(and again for every stale-key re-fetch after a revoke), not per file.

### E4 — hybrid vs pure-ABE (the design argument)

| Size | Hybrid round trip (ms) | AES share of total |
|---|---|---|
| 1 MB | `___` | `___` |
| 100 MB | `___` | `___` |

Expected: total ≈ `AES(size) + constant`, where the constant is one encap plus
one decap measured independently as `abe_constant_overhead`. The AES share should
rise toward ~100% as the file grows, i.e. ABE cost **amortizes away**. A pure-ABE
design would instead scale pairing work with file size and be unusable at 100 MB.

### E5 — ECC vs ABE sharing (the key report graph)

| Recipients | ECC wrap time (ms) | ECC metadata (bytes) | ABE encap (ms) | ABE metadata (bytes) |
|---|---|---|---|---|
| 1 | `___` | 108 | `___` | `___` |
| 10 | `___` | 1 080 | `___` (same) | `___` (same) |
| 50 | `___` | 5 400 | `___` (same) | `___` (same) |

This is the graph that answers "why ABE at all?". ECC wrapping is *faster per
operation* but both its cost and its stored metadata grow **linearly with the
number of authorized users**, and the uploader must know every recipient at
upload time. ABE pays one constant cost and stores one constant-size `CT_K`,
whatever the audience size — and a user who gains `ROLE_FACULTY` next month can
read an existing file without it being re-wrapped. The ECC figures above are the
measured metadata growth (108 bytes per recipient: 32-byte ephemeral public key +
12-byte nonce + 48-byte wrapped key + row overhead); `ecc_wrap_all_recipients`
grows with the same slope.

Plots land in `benchmarks/plots/`: `e1_aes.png`, `e2_abe_policy.png`,
`e3_abe_keygen.png`, `e4_hybrid.png`, `e5_ecc_vs_abe_time.png`,
`e5_ecc_vs_abe_metadata.png`.

## 6. Verification status

| Test group | IDs | Where |
|---|---|---|
| Crypto unit | C-01…C-12 | `crypto/tests/` |
| Backend API | B-01…B-07 | `backend/tests/` (moto) |
| Leakage | S-01, S-02, S-03, S-05 | `backend/tests/test_security.py` (moto) |
| Bucket exposure | S-04 | `backend/scripts/s04_public_access_check.py` (real AWS) |
| End to end | doc 07 §1.4 | `backend/scripts/e2e.py` (real AWS) |
| Hardening | rate limiting, `.env` checks | `backend/tests/test_auth.py`, `backend/app/config.py` |
| Hardening | log scrubbing | `backend/tests/test_logging_filter.py` (8 tests) |

S-01 is the broadest: it uploads a file carrying a marker string, then scans
every column of every table, the captured log records, and the API response body
for the marker, the raw file key, and its hex/base64/base64url encodings.

## 7. Limitations

- **L1 — Single-authority trust.** The Key Authority holds MSK and can mint a key
  for any attribute set, so a compromised backend *can* eventually read anything.
  This is inherent to single-authority CP-ABE, not a bug in the implementation,
  and it is the single most important caveat in the whole design.
- **L2 — Revocation is eventual, not instant.** Between the version bump and the
  re-key job completing, the old ciphertext is still decryptable by the revoked
  key. And nothing can claw back plaintext the user already downloaded.
- **L3 — Re-encryption cost.** Re-keying rewrites whole objects; revoking a
  widely-used attribute means re-encrypting every file that mentions it. Cost
  grows with corpus size, not with the number of revoked users.
- **L4 — Not post-quantum.** Pairing-based assumptions fall to a quantum
  adversary. So does X25519 in the fallback mode.
- **L5 — Python client, not a browser.** There is no maintained browser CP-ABE
  implementation; moving encryption server-side would destroy the zero-trust
  property, so the client is a desktop Streamlit app.
- **L6 — Metadata is not hidden.** Policies, file sizes, ownership and access
  times are visible to the backend. Filenames and contents are not.
- **L7 — Availability still depends on the backend.** It cannot read files, but
  it can refuse to presign, or delete rows.
- **L8 — The ECC fallback does not scale** (E5) and requires naming recipients at
  upload time. It exists so Phases 2–4 could proceed if the charm build failed.
- **L9 — Rate limiting is process-local.** Fine for one backend process; a
  multi-replica deployment needs shared state (Redis).

## 8. Future work

1. **Multi-authority ABE** (e.g. Lewko–Waters) to remove L1: no single party can
   mint a satisfying key.
2. **Proxy / server-aided re-encryption** so re-keying does not require an admin
   to hold every attribute and pull whole objects through a client.
3. **Outsourced decryption** (Green–Hohenberger–Waters) to move pairing work off
   weak clients without revealing `K`.
4. **Post-quantum wrapping**: a hybrid KEM (X25519 + ML-KEM) for the fallback
   mode, pending practical lattice-based ABE.
5. **Searchable encryption** over the encrypted filename index, so users can find
   files without the server learning names.
6. **Append-only / signed audit log** (hash chain) so a compromised backend
   cannot silently rewrite history.
7. **Key rotation for the KA** and attribute-level key escrow policies.
8. **Chunk-level re-encryption** to make L3 cheaper for large files.

## 9. Conclusion

SecureVault demonstrates that attribute-based access control and a genuinely
untrusted cloud can coexist: the provider stores only high-entropy bytes, the
backend stores only an ABE ciphertext of a key it cannot open, and "who may
read this" is a statement enforced by pairing arithmetic rather than by a
permission check that can be misconfigured. The hybrid KEM makes it practical —
ABE cost is a per-file constant (E4) while AES moves the data (E1) — and
versioned attributes make revocation possible without a revocation list (S-05).
The honest cost is the single-authority trust assumption (L1) and eventual
rather than instant revocation (L2), both of which have known research answers
listed above.
