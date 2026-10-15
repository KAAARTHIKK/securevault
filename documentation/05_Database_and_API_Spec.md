# 05: Database & API Specification

## 1. Database schema (PostgreSQL)

```sql
CREATE TABLE users (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username       VARCHAR(64) UNIQUE NOT NULL,
  password_hash  VARCHAR(128) NOT NULL,          -- bcrypt
  is_admin       BOOLEAN NOT NULL DEFAULT FALSE,
  key_stale      BOOLEAN NOT NULL DEFAULT TRUE,  -- must (re)fetch ABE key
  ecc_public_key BYTEA,                          -- X25519, fallback mode
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE attributes (
  id              SERIAL PRIMARY KEY,
  name            VARCHAR(64) UNIQUE NOT NULL,   -- e.g. ROLE_FACULTY
  current_version INT NOT NULL DEFAULT 1
);

CREATE TABLE user_attributes (
  user_id      UUID REFERENCES users(id) ON DELETE CASCADE,
  attribute_id INT  REFERENCES attributes(id),
  granted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, attribute_id)
);

CREATE TABLE user_keys (                          -- issuance record, not the key
  id                  SERIAL PRIMARY KEY,
  user_id             UUID REFERENCES users(id) ON DELETE CASCADE,
  versioned_attributes TEXT[] NOT NULL,           -- e.g. {DEPT_CSE_V1, ROLE_FACULTY_V3}
  issued_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked             BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE files (
  id               UUID PRIMARY KEY,
  owner_id         UUID REFERENCES users(id),
  object_key       VARCHAR(256) NOT NULL,
  version          INT NOT NULL DEFAULT 1,
  status           VARCHAR(16) NOT NULL DEFAULT 'pending', -- pending|active|rekeying|deleted
  wrap_mode        VARCHAR(8)  NOT NULL,                   -- ABE|ECC
  policy_logical   TEXT,
  policy_versioned TEXT,
  ct_key           BYTEA,                 -- serialized ABE ciphertext of R
  enc_filename     BYTEA NOT NULL,
  name_nonce       BYTEA NOT NULL,
  plaintext_size   BIGINT NOT NULL,
  ciphertext_size  BIGINT NOT NULL,
  ciphertext_sha256 CHAR(64) NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE file_recipients (                     -- ECC mode only
  file_id      UUID REFERENCES files(id) ON DELETE CASCADE,
  user_id      UUID REFERENCES users(id) ON DELETE CASCADE,
  eph_public   BYTEA NOT NULL,
  nonce        BYTEA NOT NULL,
  wrapped_key  BYTEA NOT NULL,
  PRIMARY KEY (file_id, user_id)
);

CREATE TABLE rekey_jobs (
  id            SERIAL PRIMARY KEY,
  attribute_id  INT REFERENCES attributes(id),
  old_version   INT NOT NULL,
  new_version   INT NOT NULL,
  status        VARCHAR(16) NOT NULL DEFAULT 'queued', -- queued|running|done|failed
  files_total   INT NOT NULL DEFAULT 0,
  files_done    INT NOT NULL DEFAULT 0,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE rekey_job_files (
  job_id  INT  REFERENCES rekey_jobs(id) ON DELETE CASCADE,
  file_id UUID REFERENCES files(id) ON DELETE CASCADE,
  done    BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (job_id, file_id)
);

CREATE TABLE audit_log (
  id         BIGSERIAL PRIMARY KEY,
  user_id    UUID,
  action     VARCHAR(32) NOT NULL,   -- LOGIN, KEY_ISSUE, UPLOAD, DOWNLOAD_OK, DOWNLOAD_DENIED, DELETE, REVOKE, REKEY
  file_id    UUID,
  detail     JSONB,
  ip         INET,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ON audit_log (created_at DESC);
```

Use **Alembic** for migrations.

## 2. REST API

Base URL: `/api/v1`. Auth: `Authorization: Bearer <JWT>` everywhere except login. Binary values are base64 in JSON.

### Auth
| Method | Path | Body | Response |
|---|---|---|---|
| POST | `/auth/login` | `{username, password}` | `{access_token, expires_in, key_stale, is_admin}` |
| GET | `/auth/me` | — | `{id, username, attributes:[...], is_admin, key_stale}` |

### Keys / Key Authority
| Method | Path | Notes |
|---|---|---|
| GET | `/keys/public-params` | Returns `{pk, group:"SS512", scheme:"BSW07"}` (public) |
| POST | `/keys/issue` | Generates SK for the caller's current versioned attributes. Records `user_keys`, sets `key_stale=false`, writes audit. Returns `{sk, versioned_attributes}` |
| PUT | `/keys/ecc` | `{public_key}`: registers the caller's X25519 public key |
| GET | `/attributes` | `[{name, current_version}]`, used to version policies |

**Stale-key guard:** while `key_stale=true`, every endpoint except `/keys/*`, `/auth/*`, and `/attributes` returns **409 `KEY_STALE`**. The client then re-issues its key automatically.

### Files
| Method | Path | Body | Response |
|---|---|---|---|
| POST | `/files/init` | `{ciphertext_size, wrap_mode}` | `{file_id, object_key, upload_url, expires_in}` |
| POST | `/files/{id}/complete` | `{policy_logical, policy_versioned, ct_key, enc_filename, name_nonce, plaintext_size, ciphertext_sha256, recipients?:[{user_id, eph_public, nonce, wrapped_key}]}` | `201 {file}`. The server HEADs S3 and checks the size |
| GET | `/files` | query `?mine=true` | `[{id, owner, policy_logical, wrap_mode, sizes, created_at}]` |
| GET | `/files/{id}` | — | Full metadata + `ct_key` (or the caller's recipient row) + `download_url` |
| DELETE | `/files/{id}` | — | Owner or admin only: deletes the S3 object and marks the row deleted |
| POST | `/files/{id}/access-result` | `{result: "OK" \| "DENIED"}` | Client reports the decrypt outcome for the audit log |

> Since the KA can't verify ABE decryption on the server, the download URL is issued to any authenticated non-stale user. Confidentiality comes from the crypto; the URL gate only adds defense in depth.

### Admin
| Method | Path | Body / Notes |
|---|---|---|
| POST | `/admin/users` | `{username, password, attributes:[...], is_admin}` |
| GET | `/admin/users` | List with attributes |
| POST | `/admin/users/{id}/attributes` | `{attribute}`: grant; sets `key_stale=true` for that user |
| DELETE | `/admin/users/{id}/attributes/{name}` | Revoke: bump version, mark holders stale, mark the user's key revoked, create a `rekey_job`. Returns `{job_id, files_total}` |
| GET | `/admin/rekey-jobs` | List jobs |
| GET | `/admin/rekey-jobs/{id}/files` | Pending files with metadata + download URLs |
| POST | `/admin/rekey-jobs/{id}/files/{file_id}/init` | New `object_key` + upload URL for the re-encrypted version |
| POST | `/admin/rekey-jobs/{id}/files/{file_id}/commit` | `{policy_versioned, ct_key, enc_filename, name_nonce, ciphertext_sha256, ciphertext_size}`: swap the version, delete the old object, mark done |
| GET | `/admin/audit` | `?limit=&action=`: paginated audit log |

### Error format
```json
{ "error": { "code": "KEY_STALE", "message": "Attribute versions changed; re-issue your key." } }
```
Codes: `UNAUTHORIZED` 401, `FORBIDDEN` 403, `NOT_FOUND` 404, `KEY_STALE` 409, `SIZE_MISMATCH` 422, `VALIDATION` 422.
