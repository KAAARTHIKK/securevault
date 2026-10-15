"""Admin routes (doc 05 Section 2, doc 02 Section 4.4, doc 03 Section 7)."""
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import audit, models
from ..auth import hash_password, require_fresh_admin
from ..codec import b64d, b64e
from ..config import get_settings
from ..db import get_db
from ..schemas import (
    AdminCreateUserRequest,
    AdminUserResponse,
    AuditLogItem,
    GrantAttributeRequest,
    RekeyCommitRequest,
    RekeyFileItem,
    RekeyInitResponse,
    RekeyJobResponse,
    RevokeAttributeResponse,
)
from ..storage import get_storage

router = APIRouter(prefix="/admin", tags=["admin"])


def _user_attribute_names(db: Session, user_id) -> List[str]:
    rows = (
        db.query(models.Attribute.name)
        .join(models.UserAttribute, models.UserAttribute.attribute_id == models.Attribute.id)
        .filter(models.UserAttribute.user_id == user_id)
        .all()
    )
    return [r[0] for r in rows]


def _get_or_create_attribute(db: Session, name: str) -> models.Attribute:
    attr = db.query(models.Attribute).filter(models.Attribute.name == name).first()
    if attr is None:
        attr = models.Attribute(name=name, current_version=1)
        db.add(attr)
        db.flush()
    return attr


@router.post("/users", response_model=AdminUserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    body: AdminCreateUserRequest,
    admin: models.User = Depends(require_fresh_admin),
    db: Session = Depends(get_db),
):
    if db.query(models.User).filter(models.User.username == body.username).first():
        raise HTTPException(status_code=422, detail={"error": {"code": "VALIDATION", "message": "Username taken."}})

    user = models.User(
        username=body.username,
        password_hash=hash_password(body.password),
        is_admin=body.is_admin,
        key_stale=True,
    )
    db.add(user)
    db.flush()

    for name in body.attributes:
        attr = _get_or_create_attribute(db, name)
        db.add(models.UserAttribute(user_id=user.id, attribute_id=attr.id))

    audit.write(db, admin.id, "USER_CREATE", detail={"username": body.username})
    db.commit()
    return AdminUserResponse(
        id=user.id, username=user.username, is_admin=user.is_admin,
        key_stale=user.key_stale, attributes=body.attributes,
    )


@router.get("/users", response_model=List[AdminUserResponse])
def list_users(admin: models.User = Depends(require_fresh_admin), db: Session = Depends(get_db)):
    users = db.query(models.User).order_by(models.User.username).all()
    return [
        AdminUserResponse(
            id=u.id, username=u.username, is_admin=u.is_admin, key_stale=u.key_stale,
            attributes=_user_attribute_names(db, u.id),
        )
        for u in users
    ]


@router.post("/users/{user_id}/attributes", status_code=status.HTTP_201_CREATED)
def grant_attribute(
    user_id: uuid.UUID,
    body: GrantAttributeRequest,
    admin: models.User = Depends(require_fresh_admin),
    db: Session = Depends(get_db),
):
    user = db.get(models.User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "User not found."}})

    attr = _get_or_create_attribute(db, body.attribute)
    exists = (
        db.query(models.UserAttribute)
        .filter(models.UserAttribute.user_id == user.id, models.UserAttribute.attribute_id == attr.id)
        .first()
    )
    if exists is None:
        db.add(models.UserAttribute(user_id=user.id, attribute_id=attr.id))
    user.key_stale = True
    audit.write(db, admin.id, "GRANT", detail={"user_id": str(user.id), "attribute": body.attribute})
    db.commit()
    return {"status": "ok"}


@router.delete("/users/{user_id}/attributes/{name}", response_model=RevokeAttributeResponse)
def revoke_attribute(
    user_id: uuid.UUID,
    name: str,
    admin: models.User = Depends(require_fresh_admin),
    db: Session = Depends(get_db),
):
    user = db.get(models.User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "User not found."}})

    attr = db.query(models.Attribute).filter(models.Attribute.name == name).first()
    if attr is None:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Attribute not found."}})

    link = (
        db.query(models.UserAttribute)
        .filter(models.UserAttribute.user_id == user.id, models.UserAttribute.attribute_id == attr.id)
        .first()
    )
    if link is None:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "NOT_FOUND", "message": "User does not hold this attribute."}},
        )

    old_version = attr.current_version
    new_version = old_version + 1
    old_versioned_name = "%s_V%d" % (name, old_version)

    db.delete(link)
    attr.current_version = new_version
    db.flush()

    remaining_holders = (
        db.query(models.User)
        .join(models.UserAttribute, models.UserAttribute.user_id == models.User.id)
        .filter(models.UserAttribute.attribute_id == attr.id)
        .all()
    )
    for holder in remaining_holders:
        holder.key_stale = True

    affected_files = (
        db.query(models.File)
        .filter(models.File.status == "active")
        .filter(models.File.policy_versioned.like("%" + old_versioned_name + "%"))
        .all()
    )

    job = models.RekeyJob(
        attribute_id=attr.id,
        old_version=old_version,
        new_version=new_version,
        status="queued",
        files_total=len(affected_files),
    )
    db.add(job)
    db.flush()
    for f in affected_files:
        db.add(models.RekeyJobFile(job_id=job.id, file_id=f.id))
        f.status = "rekeying"

    audit.write(db, admin.id, "REVOKE", detail={
        "user_id": str(user.id), "attribute": name, "old_version": old_version, "new_version": new_version,
    })
    db.commit()
    return RevokeAttributeResponse(job_id=job.id, files_total=job.files_total)


@router.get("/rekey-jobs", response_model=List[RekeyJobResponse])
def list_rekey_jobs(admin: models.User = Depends(require_fresh_admin), db: Session = Depends(get_db)):
    jobs = db.query(models.RekeyJob).order_by(models.RekeyJob.created_at.desc()).all()
    return [RekeyJobResponse(
        id=j.id, attribute_id=j.attribute_id, old_version=j.old_version, new_version=j.new_version,
        status=j.status, files_total=j.files_total, files_done=j.files_done, created_at=j.created_at,
    ) for j in jobs]


@router.get("/rekey-jobs/{job_id}/files", response_model=List[RekeyFileItem])
def list_rekey_job_files(
    job_id: int,
    admin: models.User = Depends(require_fresh_admin),
    db: Session = Depends(get_db),
):
    job = db.get(models.RekeyJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Job not found."}})

    storage = get_storage()
    pending = (
        db.query(models.RekeyJobFile, models.File)
        .join(models.File, models.File.id == models.RekeyJobFile.file_id)
        .filter(models.RekeyJobFile.job_id == job_id, models.RekeyJobFile.done.is_(False))
        .all()
    )
    return [
        RekeyFileItem(
            file_id=f.id, object_key=f.object_key, policy_versioned=f.policy_versioned,
            ct_key=b64e(f.ct_key) if f.ct_key else None, download_url=storage.presign_get(f.object_key),
        )
        for _, f in pending
    ]


@router.post("/rekey-jobs/{job_id}/files/{file_id}/init", response_model=RekeyInitResponse)
def rekey_file_init(
    job_id: int, file_id: uuid.UUID,
    admin: models.User = Depends(require_fresh_admin), db: Session = Depends(get_db),
):
    job = db.get(models.RekeyJob, job_id)
    f = db.get(models.File, file_id)
    if job is None or f is None:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Not found."}})

    settings = get_settings()
    new_version = f.version + 1
    object_key = "%s%s/%d.svlt" % (settings.s3_prefix, f.id, new_version)
    storage = get_storage()
    upload_url = storage.presign_put(object_key, f.ciphertext_size)
    return RekeyInitResponse(object_key=object_key, upload_url=upload_url, expires_in=settings.presign_ttl_seconds)


@router.post("/rekey-jobs/{job_id}/files/{file_id}/commit")
def rekey_file_commit(
    job_id: int, file_id: uuid.UUID, body: RekeyCommitRequest,
    admin: models.User = Depends(require_fresh_admin), db: Session = Depends(get_db),
):
    job = db.get(models.RekeyJob, job_id)
    f = db.get(models.File, file_id)
    if job is None or f is None:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Not found."}})

    settings = get_settings()
    storage = get_storage()
    new_object_key = "%s%s/%d.svlt" % (settings.s3_prefix, f.id, f.version + 1)
    actual_size = storage.head(new_object_key)
    if actual_size is None or actual_size != body.ciphertext_size:
        raise HTTPException(
            status_code=422,
            detail={"error": {"code": "SIZE_MISMATCH", "message": "Re-keyed object size mismatch."}},
        )

    old_object_key = f.object_key
    f.version += 1
    f.object_key = new_object_key
    f.policy_versioned = body.policy_versioned
    f.ct_key = b64d(body.ct_key)
    f.enc_filename = b64d(body.enc_filename)
    f.name_nonce = b64d(body.name_nonce)
    f.ciphertext_sha256 = body.ciphertext_sha256
    f.ciphertext_size = body.ciphertext_size
    f.status = "active"

    storage.delete(old_object_key)

    job_file = (
        db.query(models.RekeyJobFile)
        .filter(models.RekeyJobFile.job_id == job_id, models.RekeyJobFile.file_id == file_id)
        .first()
    )
    if job_file is not None:
        job_file.done = True
    job.files_done += 1
    if job.files_done >= job.files_total:
        job.status = "done"

    audit.write(db, admin.id, "REKEY", file_id=f.id, detail={"job_id": job_id, "new_version": f.version})
    db.commit()
    return {"status": "ok"}


@router.get("/audit", response_model=List[AuditLogItem])
def get_audit_log(
    limit: int = 100,
    action: Optional[str] = None,
    admin: models.User = Depends(require_fresh_admin),
    db: Session = Depends(get_db),
):
    query = db.query(models.AuditLog)
    if action:
        query = query.filter(models.AuditLog.action == action)
    rows = query.order_by(models.AuditLog.created_at.desc()).limit(limit).all()
    return [AuditLogItem(
        id=r.id, user_id=r.user_id, action=r.action, file_id=r.file_id, detail=r.detail, created_at=r.created_at,
    ) for r in rows]
