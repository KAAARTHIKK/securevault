"""Key Authority routes (doc 05 Section 2, doc 02 Section 4.1).

/keys/*, /auth/*, and /attributes are the only endpoints exempt from the
stale-key guard -- they use get_current_user, never require_fresh_key.
"""
from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import audit, models
from ..auth import get_current_user
from ..codec import b64d, b64e
from ..db import get_db
from ..key_authority import load as load_ka
from crypto import abe_kem
from ..schemas import (
    AttributeResponse,
    EccRecipientResponse,
    IssueKeyResponse,
    PublicParamsResponse,
    RegisterEccRequest,
)

router = APIRouter(tags=["keys"])


@router.get("/keys/public-params", response_model=PublicParamsResponse)
def public_params():
    ka = load_ka()
    return PublicParamsResponse(pk=b64e(abe_kem.serialize_pk(ka.pk)), group="SS512", scheme="BSW07")


@router.post("/keys/issue", response_model=IssueKeyResponse)
def issue_key(
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(models.Attribute.name, models.Attribute.current_version)
        .join(models.UserAttribute, models.UserAttribute.attribute_id == models.Attribute.id)
        .filter(models.UserAttribute.user_id == user.id)
        .all()
    )
    versioned_attributes = ["%s_V%d" % (name, version) for name, version in rows]

    ka = load_ka()
    sk = ka.issue_key(versioned_attributes)

    db.add(models.UserKey(user_id=user.id, versioned_attributes=versioned_attributes))
    user.key_stale = False
    audit.write(db, user.id, "KEY_ISSUE", detail={"versioned_attributes": versioned_attributes})
    db.commit()

    return IssueKeyResponse(sk=b64e(abe_kem.serialize_sk(sk)), versioned_attributes=versioned_attributes)


@router.put("/keys/ecc")
def register_ecc_key(
    body: RegisterEccRequest,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user.ecc_public_key = b64d(body.public_key)
    db.commit()
    return {"status": "ok"}


@router.get("/keys/ecc/recipients", response_model=List[EccRecipientResponse])
def list_ecc_recipients(
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Recipient directory for ECC fallback mode.

    Beyond doc 05's table, but ECC wrapping needs each recipient's X25519
    *public* key and nothing else exposes it. Public keys only -- never a
    secret key, and never a file key.
    """
    users = (
        db.query(models.User)
        .filter(models.User.ecc_public_key.isnot(None))
        .order_by(models.User.username)
        .all()
    )
    return [
        EccRecipientResponse(user_id=u.id, username=u.username, public_key=b64e(u.ecc_public_key))
        for u in users
    ]


@router.get("/attributes", response_model=List[AttributeResponse])
def list_attributes(
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    attrs = db.query(models.Attribute).order_by(models.Attribute.name).all()
    return [AttributeResponse(name=a.name, current_version=a.current_version) for a in attrs]
