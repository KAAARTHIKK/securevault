# 07: Testing, Benchmarks & Demo

## 1. Test plan

### 1.1 Crypto unit tests (`crypto/tests`)
| ID | Test | Expected |
|---|---|---|
| C-01 | AES round trip at 0 B, 1 B, 65 535 B, 65 536 B, 65 537 B, 10 MB | Identical output |
| C-02 | Flip 1 byte in any chunk | `InvalidTag`, no partial output kept |
| C-03 | Swap chunks 1 and 2 | Fails |
| C-04 | Drop the final chunk | Fails (final-flag / total_chunks check) |
| C-05 | Decrypt blob A under file_id B | Fails |
| C-06 | ABE decap with satisfying attributes | Returns the same K |
| C-07 | ABE decap with non-satisfying attributes | Returns `None` |
| C-08 | Collusion: user1 {DEPT_CSE_V1}, user2 {ROLE_FACULTY_V1}, policy AND | Both fail; mixing key components fails |
| C-09 | Old version key (`ROLE_FACULTY_V3`) against a `_V4` policy | Fails |
| C-10 | Keystore: wrong password | Fails cleanly |
| C-11 | Policy validator rejects unknown attributes and injection-like strings | Raises `ValueError` |
| C-12 | ECC wrap/unwrap; a non-recipient cannot unwrap | Pass / fail as expected |

### 1.2 Backend tests (`backend/tests`, moto + test DB)
| ID | Test |
|---|---|
| B-01 | Login OK / wrong password returns 401 / JWT expiry |
| B-02 | Non-admin calling `/admin/*` gets 403 |
| B-03 | `/files/init` returns a pre-signed URL that expires; PUT after expiry fails |
| B-04 | `/complete` with a wrong size gets 422 `SIZE_MISMATCH` |
| B-05 | Revoke: version bumps, holders go stale (409), job lists correct files |
| B-06 | Delete removes the S3 object |
| B-07 | Audit rows written for every action |

### 1.3 Security / leakage tests
| ID | Test |
|---|---|
| S-01 | After an E2E upload, scan all DB columns and server logs for the plaintext marker string and for hex/base64 of K. Expect **no match** |
| S-02 | Download the S3 object with the AWS CLI. Entropy is close to 8 bits/byte; plaintext marker absent |
| S-03 | Object keys contain no filenames |
| S-04 | Bucket public-access check: an anonymous GET is denied |
| S-05 | Revoked user, after the re-key job, cannot decrypt even with a raw DB row and the S3 object |

### 1.4 End-to-end (real S3)
`scripts/e2e.py` runs the demo script below non-interactively and asserts every outcome.

## 2. Benchmarks (`benchmarks/bench.py`)
Run each measurement 10 times and report the mean ± std. Record CPU and RAM in the report.

| Experiment | X-axis | Y-axis | Expected shape |
|---|---|---|---|
| E1 AES-GCM | File size 1–100 MB | Encrypt/decrypt time | Linear, steep throughput |
| E2 ABE encap/decap | Policy attributes 1–10 | Time (ms) | Roughly linear in policy size |
| E3 ABE keygen | User attributes 1–10 | Time (ms) | Linear |
| E4 Hybrid vs pure-ABE argument | File size | Total time | Hybrid ≈ AES + constant ABE cost |
| E5 ECC vs ABE sharing | Recipients 1–50 | Wrap time + metadata size | ECC grows linearly; ABE stays constant per file |

**E5 is the key report graph.** It shows *why* ABE: cost and metadata don't grow with the number of authorized users.

## 3. Demo script (about 5 minutes)

**Seed users:**
| User | Attributes |
|---|---|
| `admin` | ROLE_ADMIN (+ admin key holding all attributes for re-key) |
| `prof_a` | DEPT_CSE, ROLE_FACULTY |
| `prof_b` | DEPT_CSE, ROLE_FACULTY |
| `hod` | DEPT_CSE, ROLE_HOD, ROLE_FACULTY |
| `student_s` | DEPT_CSE, ROLE_STUDENT, YEAR_4 |

1. **prof_a** uploads `endsem_qp.pdf` with policy `DEPT_CSE AND ROLE_FACULTY`.
2. Open the **AWS S3 console**. The object is `objects/<uuid>/1.svlt`, with no filename. Download it and open it in a hex viewer: random bytes.
3. Open the DB row: policy and ct_key visible, but nothing usable.
4. **prof_b** downloads it, and it opens correctly.
5. **student_s** tries, and the cryptography itself returns *"Access denied by policy"*. Show the audit log entry DOWNLOAD_DENIED.
6. **Tamper:** flip a byte of the S3 object with the CLI, then download as prof_b. Integrity failure is detected.
7. **Revoke:** admin removes ROLE_FACULTY from prof_b and runs the re-key worker. The progress bar completes, and the S3 object key changes to `2.svlt`.
8. **prof_b** tries again and is denied. **prof_a** auto-refreshes their key and still has access.
9. Show the benchmark plots (E2 and E5).

## 4. Likely viva questions

**Why not just use S3 server-side encryption?**
AWS holds those keys, so AWS (or anyone holding stolen IAM credentials) can read the data. Here the cloud only ever sees ciphertext.

**Why hybrid, not pure ABE?**
ABE works on group elements and is slow with pairing operations. AES handles the bulk data, and ABE protects only a 32-byte key. See E4.

**What's CP-ABE vs KP-ABE?**
In CP-ABE, the policy is in the ciphertext and attributes are in the key, so the data owner decides who can read. In KP-ABE it's the reverse.

**Is it collusion-resistant?**
Yes. BSW07 randomizes each user's key with a per-user secret, so components from different keys can't be combined. Test C-08 shows this.

**How does revocation work, and what are its limits?**
Versioned attributes plus re-encryption. A revoked user keeps whatever plaintext they already downloaded, and there's a window until the re-key job completes.

**Can the Key Authority read everything?**
In principle yes, since it can mint any key. This is the single-authority trust assumption. Multi-authority ABE is the future-work fix.

**Why GCM chunking with AAD?**
It bounds memory and detects reordering, truncation, and blob swapping.

**Why a Python client instead of a web app?**
There's no maintained browser CP-ABE library, and moving encryption to the server would break the zero-trust property.

**Is it post-quantum secure?**
No. Pairing-based assumptions break under a quantum computer. That is listed as future work.
