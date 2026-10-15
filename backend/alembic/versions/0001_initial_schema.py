"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-10-15

Schema copied verbatim from doc 05 Section 1. Postgres 13+ provides
gen_random_uuid() natively, no pgcrypto extension needed.
"""
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

SCHEMA_SQL = """
CREATE TABLE users (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username       VARCHAR(64) UNIQUE NOT NULL,
  password_hash  VARCHAR(128) NOT NULL,
  is_admin       BOOLEAN NOT NULL DEFAULT FALSE,
  key_stale      BOOLEAN NOT NULL DEFAULT TRUE,
  ecc_public_key BYTEA,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE attributes (
  id              SERIAL PRIMARY KEY,
  name            VARCHAR(64) UNIQUE NOT NULL,
  current_version INT NOT NULL DEFAULT 1
);

CREATE TABLE user_attributes (
  user_id      UUID REFERENCES users(id) ON DELETE CASCADE,
  attribute_id INT  REFERENCES attributes(id),
  granted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, attribute_id)
);

CREATE TABLE user_keys (
  id                   SERIAL PRIMARY KEY,
  user_id              UUID REFERENCES users(id) ON DELETE CASCADE,
  versioned_attributes TEXT[] NOT NULL,
  issued_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked              BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE files (
  id                UUID PRIMARY KEY,
  owner_id          UUID REFERENCES users(id),
  object_key        VARCHAR(256) NOT NULL,
  version           INT NOT NULL DEFAULT 1,
  status            VARCHAR(16) NOT NULL DEFAULT 'pending',
  wrap_mode         VARCHAR(8)  NOT NULL,
  policy_logical    TEXT,
  policy_versioned  TEXT,
  ct_key            BYTEA,
  enc_filename      BYTEA NOT NULL,
  name_nonce        BYTEA NOT NULL,
  plaintext_size    BIGINT NOT NULL,
  ciphertext_size   BIGINT NOT NULL,
  ciphertext_sha256 CHAR(64) NOT NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE file_recipients (
  file_id      UUID REFERENCES files(id) ON DELETE CASCADE,
  user_id      UUID REFERENCES users(id) ON DELETE CASCADE,
  eph_public   BYTEA NOT NULL,
  nonce        BYTEA NOT NULL,
  wrapped_key  BYTEA NOT NULL,
  PRIMARY KEY (file_id, user_id)
);

CREATE TABLE rekey_jobs (
  id           SERIAL PRIMARY KEY,
  attribute_id INT REFERENCES attributes(id),
  old_version  INT NOT NULL,
  new_version  INT NOT NULL,
  status       VARCHAR(16) NOT NULL DEFAULT 'queued',
  files_total  INT NOT NULL DEFAULT 0,
  files_done   INT NOT NULL DEFAULT 0,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
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
  action     VARCHAR(32) NOT NULL,
  file_id    UUID,
  detail     JSONB,
  ip         INET,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ON audit_log (created_at DESC);
"""

DROP_SQL = """
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS rekey_job_files;
DROP TABLE IF EXISTS rekey_jobs;
DROP TABLE IF EXISTS file_recipients;
DROP TABLE IF EXISTS files;
DROP TABLE IF EXISTS user_keys;
DROP TABLE IF EXISTS user_attributes;
DROP TABLE IF EXISTS attributes;
DROP TABLE IF EXISTS users;
"""


def upgrade() -> None:
    op.execute(SCHEMA_SQL)


def downgrade() -> None:
    op.execute(DROP_SQL)
