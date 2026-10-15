"""File routes (doc 05 Section 2, doc 02 Section 4.2-4.3)."""
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import audit, models
from ..auth import require_fresh_key
from ..codec import b64d, b64e
from ..config import get_settings
from ..db import get_db
from ..schemas import (
    AccessResultRequest,
    FileCompleteRequest,
    FileDetail,
    FileInitRequest,
    FileInitResponse,
    FileSummary,
    RecipientIn,
)
from ..storage import get_storage

router = APIRouter(prefix="/files", tags=["files"])


def _object_key(file_id: uuid.UUID, version: int) -> str:
    settings = get_settings()
    return "%s%s/%d.svlt" % (settings.s3_prefix, file_id, version)


def _to_detail(f: models.File, download_url: Optional[str], recipient: Optional[models.FileRecipient] = None) -> FileDetail:
    return FileDetail(
        id=f.id,
        owner_id=f.owner_id,
        policy_logical=f.policy_logical,
        wrap_mode=f.wrap_mode,
        plaintext_size=f.plaintext_size,
        ciphertext_size=f.ciphertext_size,
        status=f.status,
        created_at=f.created_at,
        object_key=f.object_key,
        version=f.version,
        policy_versioned=f.policy_versioned,
        ct_key=b64e(f.ct_key) if f.ct_key else None,
        enc_filename=b64e(f.enc_filename),
        name_nonce=b64e(f.name_nonce),
        ciphertext_sha256=f.ciphertext_sha256,
        download_url=download_url,
        recipient=RecipientIn(
            user_id=recipient.user_id,
            eph_public=b64e(recipient.eph_public),
            nonce=b64e(recipient.nonce),
            wrapped_key=b64e(recipient.wrapped_key),
        ) if recipient else None,
    )


@router.post("/init", response_model=FileInitResponse)
def init_upload(
    body: FileInitRequest,
    user: models.User = Depends(require_fresh_key),
    db: Session = Depends(get_db),
):
    if body.wrap_mode not in ("ABE", "ECC"):
        raise HTTPException(
            status_code=422,
            detail={"error": {"code": "VALIDATION", "message": "wrap_mode must be ABE or ECC"}},
        )
    file_id = uuid.uuid4()
    object_key = _object_key(file_id, 1)

    file_row = models.File(
        id=file_id,
        owner_id=user.id,
        object_key=object_key,
        version=1,
        status="pending",
        wrap_mode=body.wrap_mode,
        enc_filename=b"",
        name_nonce=b"",
        plaintext_size=0,
        ciphertext_size=body.ciphertext_size,
        ciphertext_sha256="0" * 64,
    )
    db.add(file_row)
    db.commit()

    settings = get_settings()
    storage = get_storage()
    upload_url = storage.presign_put(object_key, body.ciphertext_size)

    return FileInitResponse(
        file_id=file_id,
        object_key=object_key,
        upload_url=upload_url,
        expires_in=settings.presign_ttl_seconds,
    )


@router.post("/{file_id}/complete", response_model=FileDetail, status_code=status.HTTP_201_CREATED)
def complete_upload(
    file_id: uuid.UUID,
    body: FileCompleteRequest,
    user: models.User = Depends(require_fresh_key),
    db: Session = Depends(get_db),
):
    file_row = db.get(models.File, file_id)
    if file_row is None or file_row.owner_id != user.id:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "File not found."}})

    storage = get_storage()
    actual_size = storage.head(file_row.object_key)
    if actual_size is None or actual_size != file_row.ciphertext_size:
        raise HTTPException(
            status_code=422,
            detail={"error": {"code": "SIZE_MISMATCH", "message": "Uploaded object size does not match."}},
        )

    file_row.policy_logical = body.policy_logical
    file_row.policy_versioned = body.policy_versioned
    file_row.ct_key = b64d(body.ct_key) if body.ct_key else None
    file_row.enc_filename = b64d(body.enc_filename)
    file_row.name_nonce = b64d(body.name_nonce)
    file_row.plaintext_size = body.plaintext_size
    file_row.ciphertext_sha256 = body.ciphertext_sha256
    file_row.status = "active"

    if body.recipients:
        for r in body.recipients:
            db.add(models.FileRecipient(
                file_id=file_row.id,
                user_id=r.user_id,
                eph_public=b64d(r.eph_public),
                nonce=b64d(r.nonce),
                wrapped_key=b64d(r.wrapped_key),
            ))

    audit.write(db, user.id, "UPLOAD", file_id=file_row.id, detail={"policy": body.policy_logical})
    db.commit()
    return _to_detail(file_row, download_url=None)


@router.get("", response_model=List[FileSummary])
def list_files(
    mine: bool = False,
    user: models.User = Depends(require_fresh_key),
    db: Session = Depends(get_db),
):
    query = db.query(models.File).filter(models.File.status != "deleted")
    if mine:
        query = query.filter(models.File.owner_id == user.id)
    files = query.order_by(models.File.created_at.desc()).all()
    return [
        FileSummary(
            id=f.id, owner_id=f.owner_id, policy_logical=f.policy_logical, wrap_mode=f.wrap_mode,
            plaintext_size=f.plaintext_size, ciphertext_size=f.ciphertext_size, status=f.status,
            created_at=f.created_at,
        )
        for f in files
    ]


@router.get("/{file_id}", response_model=FileDetail)
def get_file(
    file_id: uuid.UUID,
    user: models.User = Depends(require_fresh_key),
    db: Session = Depends(get_db),
):
    f = db.get(models.File, file_id)
    if f is None or f.status == "deleted":
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "File not found."}})

    storage = get_storage()
    download_url = storage.presign_get(f.object_key)

    recipient = None
    if f.wrap_mode == "ECC":
        recipient = (
            db.query(models.FileRecipient)
            .filter(models.FileRecipient.file_id == f.id, models.FileRecipient.user_id == user.id)
            .first()
        )

    return _to_detail(f, download_url, recipient)


@router.delete("/{file_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_file(
    file_id: uuid.UUID,
    user: models.User = Depends(require_fresh_key),
    db: Session = Depends(get_db),
):
    f = db.get(models.File, file_id)
    if f is None or f.status == "deleted":
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "File not found."}})
    if f.owner_id != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail={"error": {"code": "FORBIDDEN", "message": "Not the owner."}})

    storage = get_storage()
    storage.delete(f.object_key)
    f.status = "deleted"
    audit.write(db, user.id, "DELETE", file_id=f.id)
    db.commit()


@router.post("/{file_id}/access-result")
def access_result(
    file_id: uuid.UUID,
    body: AccessResultRequest,
    user: models.User = Depends(require_fresh_key),
    db: Session = Depends(get_db),
):
    action = "DOWNLOAD_OK" if body.result == "OK" else "DOWNLOAD_DENIED"
    audit.write(db, user.id, action, file_id=file_id)
    db.commit()
    return {"status": "ok"}
