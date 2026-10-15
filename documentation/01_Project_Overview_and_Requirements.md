# 01: Project Overview & Requirements

## 1. Problem statement
Organizations increasingly keep sensitive files on public cloud storage. Server-side encryption, such as S3 default encryption, protects data on disk, but the cloud provider still holds the keys. Anyone with sufficient cloud privileges can read the data: a malicious insider, leaked IAM credentials, or a misconfigured bucket. Role-based access checks done in application code fail completely once the server is compromised.

**Goal:** Build a system where the cloud and the application server are **untrusted for confidentiality**. Data is encrypted before it leaves the user's machine, and access control is enforced **cryptographically** through attribute-based policies.

## 2. Objectives
1. Encrypt every file on the client with **AES-256-GCM** before upload, providing confidentiality and integrity.
2. Protect each file's AES key with **CP-ABE**, so a file is decryptable only by users whose attributes satisfy its policy, such as `(DEPT_CSE and ROLE_FACULTY)`.
3. Store only ciphertext in **AWS S3**, accessed through short-lived **pre-signed URLs**. Clients never hold AWS credentials.
4. Provide **attribute revocation** using versioned attributes and re-encryption.
5. Provide a fallback **ECC (X25519) per-recipient** key-wrapping mode.
6. Measure and justify the **hybrid design** with benchmarks.

## 3. Scope

### In scope
- Single-organization deployment (a college department)
- One key authority (KA) that issues ABE user keys
- Local desktop client (Streamlit) plus a REST backend plus S3
- Upload, list, download, delete, policy-based sharing, revocation, audit log
- Benchmarks and a security test suite

### Out of scope (future work)
- Multi-authority ABE (no single trusted KA)
- Post-quantum ABE
- Mobile or browser clients (no maintained JS/WASM CP-ABE library exists)
- Real-time collaborative editing
- Protection against a compromised client device

## 4. Stakeholders & users

| Role | Example attributes | Capabilities |
|---|---|---|
| **Admin / Key Authority operator** | `ROLE_ADMIN` | Create users, assign and revoke attributes, run re-key jobs, view audit log |
| **Faculty** | `DEPT_CSE`, `ROLE_FACULTY` | Upload with policies, download permitted files |
| **HOD** | `DEPT_CSE`, `ROLE_HOD`, `ROLE_FACULTY` | Same as faculty, plus broader policies |
| **Student** | `DEPT_CSE`, `ROLE_STUDENT`, `YEAR_4` | Upload and download files whose policy they satisfy |

**Attribute universe (demo):** `DEPT_CSE`, `DEPT_ECE`, `DEPT_MECH`, `ROLE_ADMIN`, `ROLE_HOD`, `ROLE_FACULTY`, `ROLE_STUDENT`, `YEAR_1` … `YEAR_4`

## 5. Functional requirements

| ID | Requirement |
|---|---|
| FR-01 | The admin can create users and assign them attributes from the attribute universe. |
| FR-02 | Users log in with username and password and receive a JWT with a 30-minute lifetime. |
| FR-03 | On first login, or after a key-version change, the client obtains the user's ABE secret key from the KA and stores it locally, encrypted under a password-derived key. |
| FR-04 | The user selects a file and builds an access policy (AND/OR of attributes) in the client UI. |
| FR-05 | The client encrypts the file with a fresh random AES-256 key, using chunked AES-GCM. |
| FR-06 | The client wraps the file key under the policy with CP-ABE (or, in ECC mode, once per recipient). |
| FR-07 | The client requests a pre-signed PUT URL and uploads the ciphertext directly to S3. |
| FR-08 | The client registers file metadata (policy, wrapped key, hash, sizes) with the backend. Original filenames are encrypted. |
| FR-09 | Users can list all files in the organization and see the policy and owner, but not the content. |
| FR-10 | Download fetches the metadata and a pre-signed GET URL, then the client unwraps the key and decrypts locally. If the policy isn't satisfied, the user sees a clear "Access denied by policy" result. |
| FR-11 | The owner or admin can delete a file. This removes both the S3 object and the metadata. |
| FR-12 | The admin can revoke an attribute from a user. This bumps the attribute's version, reissues keys to remaining holders, and queues re-encryption of affected files. |
| FR-13 | An admin re-key worker re-encrypts affected files with new keys and updated versioned policies. |
| FR-14 | Every key issuance, upload, download, delete, and revocation is written to an audit log (events only, never keys). |
| FR-15 | A benchmark script measures AES vs ABE timings against file size and policy size. |

## 6. Non-functional requirements

| ID | Category | Requirement |
|---|---|---|
| NFR-01 | Security | No plaintext file content, file key, or ABE secret key ever reaches the backend or S3. |
| NFR-02 | Security | All transport uses HTTPS. S3 pre-signed URLs expire in at most 5 minutes. |
| NFR-03 | Security | Passwords are hashed with bcrypt. Local key stores use scrypt (N=2^15) + AES-GCM. |
| NFR-04 | Security | The S3 bucket has Block Public Access enabled and SSE-S3 as defense in depth. |
| NFR-05 | Integrity | Any modification, reordering, or truncation of ciphertext is detected (GCM tags + AAD). |
| NFR-06 | Performance | A 10 MB file encrypts in under 1 s on a typical laptop. ABE wrap/unwrap takes under 500 ms for policies with up to 6 attributes. |
| NFR-07 | Cost | Stays within the AWS Free plan credits; there are no paid dependencies. |
| NFR-08 | Portability | Backend and ABE runtime are reproducible through Docker. |
| NFR-09 | Maintainability | Storage access sits behind an interface, so S3 can be swapped for MinIO or moto in tests. |
| NFR-10 | Usability | Policy builder uses dropdowns. The user never types raw policy syntax. |

## 7. Assumptions & constraints
- The Key Authority (backend + master key) is **trusted for key issuance** but **not for data access**. It never receives ciphertext keys from clients. (A malicious KA *could* mint itself a key; this is the inherent limitation of single-authority ABE and is documented as such.)
- The client device is trusted while the user is logged in.
- `charm-crypto` requires Python ≤ 3.9 and native libraries (GMP, PBC), so it runs in a pinned Docker image or a Python 3.8 virtual environment.

## 8. Success criteria
- The full demo script (doc 07) runs without errors.
- A user with the wrong attributes cannot decrypt, even with direct access to the S3 object and the database row.
- Tampering is detected 100% of the time in the test suite.
- After revocation, the revoked user cannot decrypt re-encrypted files with their old key.
- The benchmark graphs are included in the report.
