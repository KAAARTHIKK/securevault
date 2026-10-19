# SecureVault: Documentation Index

**SecureVault** is a zero-trust encrypted cloud storage system. Files are encrypted on the client with AES-256-GCM. The file key is protected with Ciphertext-Policy Attribute-Based Encryption (CP-ABE), so only users whose attributes satisfy a file's access policy can decrypt it. Encrypted blobs are stored in **AWS S3**, which is treated as an untrusted cloud.

| # | Document | Purpose |
|---|---|---|
| 01 | [Project Overview & Requirements](01_Project_Overview_and_Requirements.md) | Problem, objectives, scope, users, functional and non-functional requirements |
| 02 | [System Architecture](02_System_Architecture.md) | Components, data flows, sequence diagrams, trust boundaries |
| 03 | [Cryptographic Design](03_Cryptographic_Design.md) | AES-GCM file format, CP-ABE KEM, key lifecycle, revocation, threat model |
| 04 | [AWS S3 Setup Guide](04_AWS_S3_Setup.md) | Account, budget, bucket, IAM least-privilege, pre-signed URLs |
| 05 | [Database & API Specification](05_Database_and_API_Spec.md) | PostgreSQL schema and REST endpoints |
| 06 | [Implementation Plan](06_Implementation_Plan.md) | Repo layout, phases with STOP points, timeline, environment |
| 07 | [Testing, Benchmarks & Demo](07_Testing_Benchmarks_and_Demo.md) | Test plan, security tests, benchmarks, demo script, viva Q&A |
| 08 | [Claude Code Build Prompt](08_Claude_Code_Build_Prompt.md) | Single consolidated, phase-gated prompt for building the system |
| 09 | [Report](09_Report.md) | Architecture, threat model table, benchmark analysis, limitations, future work |

## Tech summary
- **Client:** Python 3.8 + Streamlit (runs locally; every crypto operation happens here)
- **Backend:** FastAPI + SQLAlchemy + PostgreSQL + JWT
- **Crypto:** `cryptography` (AES-GCM, X25519, HKDF, scrypt) + `charm-crypto` (BSW07 CP-ABE)
- **Storage:** AWS S3 (ap-south-1), accessed only through pre-signed URLs
- **Dev infra:** Docker Compose (Postgres + backend + client); `moto` for offline S3 tests
- **Cost:** stays within AWS Free plan credits; everything else is open source

For setup steps, commands and the demo walkthrough, see the repository
[README](../README.md).
