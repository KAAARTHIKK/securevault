"""SQLAlchemy ORM models, matching doc 05 Section 1 exactly."""
import uuid

from sqlalchemy import BigInteger, Boolean, Column, ForeignKey, Index, Integer, String, TIMESTAMP, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, BYTEA, INET, JSONB, UUID

from .db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(64), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    is_admin = Column(Boolean, nullable=False, default=False)
    key_stale = Column(Boolean, nullable=False, default=True)
    ecc_public_key = Column(BYTEA, nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())


class Attribute(Base):
    __tablename__ = "attributes"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    current_version = Column(Integer, nullable=False, default=1)


class UserAttribute(Base):
    __tablename__ = "user_attributes"

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    attribute_id = Column(Integer, ForeignKey("attributes.id"), primary_key=True)
    granted_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())


class UserKey(Base):
    __tablename__ = "user_keys"

    id = Column(Integer, primary_key=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    versioned_attributes = Column(ARRAY(Text), nullable=False)
    issued_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    revoked = Column(Boolean, nullable=False, default=False)


class File(Base):
    __tablename__ = "files"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    object_key = Column(String(256), nullable=False)
    version = Column(Integer, nullable=False, default=1)
    status = Column(String(16), nullable=False, default="pending")
    wrap_mode = Column(String(8), nullable=False)
    policy_logical = Column(Text)
    policy_versioned = Column(Text)
    ct_key = Column(BYTEA)
    enc_filename = Column(BYTEA, nullable=False)
    name_nonce = Column(BYTEA, nullable=False)
    plaintext_size = Column(BigInteger, nullable=False)
    ciphertext_size = Column(BigInteger, nullable=False)
    ciphertext_sha256 = Column(String(64), nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())


class FileRecipient(Base):
    __tablename__ = "file_recipients"

    file_id = Column(UUID(as_uuid=True), ForeignKey("files.id", ondelete="CASCADE"), primary_key=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    eph_public = Column(BYTEA, nullable=False)
    nonce = Column(BYTEA, nullable=False)
    wrapped_key = Column(BYTEA, nullable=False)


class RekeyJob(Base):
    __tablename__ = "rekey_jobs"

    id = Column(Integer, primary_key=True)
    attribute_id = Column(Integer, ForeignKey("attributes.id"))
    old_version = Column(Integer, nullable=False)
    new_version = Column(Integer, nullable=False)
    status = Column(String(16), nullable=False, default="queued")
    files_total = Column(Integer, nullable=False, default=0)
    files_done = Column(Integer, nullable=False, default=0)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())


class RekeyJobFile(Base):
    __tablename__ = "rekey_job_files"

    job_id = Column(Integer, ForeignKey("rekey_jobs.id", ondelete="CASCADE"), primary_key=True)
    file_id = Column(UUID(as_uuid=True), ForeignKey("files.id", ondelete="CASCADE"), primary_key=True)
    done = Column(Boolean, nullable=False, default=False)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(BigInteger, primary_key=True)
    user_id = Column(UUID(as_uuid=True), nullable=True)
    action = Column(String(32), nullable=False)
    file_id = Column(UUID(as_uuid=True), nullable=True)
    detail = Column(JSONB)
    ip = Column(INET)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())


Index("ix_audit_log_created_at", AuditLog.created_at.desc())
