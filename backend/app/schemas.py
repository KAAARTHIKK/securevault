"""Pydantic request/response schemas (doc 05 Section 2)."""
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    expires_in: int
    key_stale: bool
    is_admin: bool


class MeResponse(BaseModel):
    id: uuid.UUID
    username: str
    attributes: List[str]
    is_admin: bool
    key_stale: bool


class PublicParamsResponse(BaseModel):
    pk: str
    group: str
    scheme: str


class IssueKeyResponse(BaseModel):
    sk: str
    versioned_attributes: List[str]


class RegisterEccRequest(BaseModel):
    public_key: str


class AttributeResponse(BaseModel):
    name: str
    current_version: int


class FileInitRequest(BaseModel):
    ciphertext_size: int
    wrap_mode: str


class FileInitResponse(BaseModel):
    file_id: uuid.UUID
    object_key: str
    upload_url: str
    expires_in: int


class RecipientIn(BaseModel):
    user_id: uuid.UUID
    eph_public: str
    nonce: str
    wrapped_key: str


class FileCompleteRequest(BaseModel):
    policy_logical: str
    policy_versioned: str
    ct_key: Optional[str] = None
    enc_filename: str
    name_nonce: str
    plaintext_size: int
    ciphertext_sha256: str
    recipients: Optional[List[RecipientIn]] = None


class FileSummary(BaseModel):
    id: uuid.UUID
    owner_id: uuid.UUID
    policy_logical: Optional[str]
    wrap_mode: str
    plaintext_size: int
    ciphertext_size: int
    status: str
    created_at: datetime


class FileDetail(FileSummary):
    object_key: str
    version: int
    policy_versioned: Optional[str]
    ct_key: Optional[str]
    enc_filename: str
    name_nonce: str
    ciphertext_sha256: str
    download_url: Optional[str] = None
    recipient: Optional[RecipientIn] = None


class AccessResultRequest(BaseModel):
    result: str


class AdminCreateUserRequest(BaseModel):
    username: str
    password: str
    attributes: List[str] = Field(default_factory=list)
    is_admin: bool = False


class AdminUserResponse(BaseModel):
    id: uuid.UUID
    username: str
    is_admin: bool
    key_stale: bool
    attributes: List[str]


class GrantAttributeRequest(BaseModel):
    attribute: str


class RevokeAttributeResponse(BaseModel):
    job_id: Optional[int]
    files_total: int


class RekeyJobResponse(BaseModel):
    id: int
    attribute_id: int
    old_version: int
    new_version: int
    status: str
    files_total: int
    files_done: int
    created_at: datetime


class RekeyFileItem(BaseModel):
    file_id: uuid.UUID
    object_key: str
    policy_versioned: Optional[str]
    ct_key: Optional[str]
    download_url: str


class RekeyInitResponse(BaseModel):
    object_key: str
    upload_url: str
    expires_in: int


class RekeyCommitRequest(BaseModel):
    policy_versioned: str
    ct_key: str
    enc_filename: str
    name_nonce: str
    ciphertext_sha256: str
    ciphertext_size: int


class AuditLogItem(BaseModel):
    id: int
    user_id: Optional[uuid.UUID]
    action: str
    file_id: Optional[uuid.UUID]
    detail: Optional[Dict[str, Any]]
    created_at: datetime
