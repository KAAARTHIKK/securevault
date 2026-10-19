"""Auth routes (doc 05 Section 2)."""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .. import audit, models, ratelimit
from ..auth import create_access_token, get_current_user, verify_password
from ..config import get_settings
from ..db import get_db
from ..schemas import LoginRequest, LoginResponse, MeResponse

router = APIRouter(prefix="/auth", tags=["auth"])


def _attribute_names(db: Session, user: models.User):
    rows = (
        db.query(models.Attribute.name)
        .join(models.UserAttribute, models.UserAttribute.attribute_id == models.Attribute.id)
        .filter(models.UserAttribute.user_id == user.id)
        .all()
    )
    return [r[0] for r in rows]


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    settings = get_settings()
    client_ip = request.client.host if request.client else "unknown"

    retry_after = ratelimit.check(
        body.username, client_ip, settings.login_max_attempts, settings.login_window_seconds
    )
    if retry_after:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(retry_after)},
            detail={"error": {"code": "RATE_LIMITED",
                              "message": "Too many login attempts. Try again in %d s." % retry_after}},
        )

    user = db.query(models.User).filter(models.User.username == body.username).first()
    if user is None or not verify_password(body.password, user.password_hash):
        ratelimit.record_failure(body.username, client_ip, settings.login_window_seconds)
        audit.write(db, user.id if user else None, "LOGIN_FAILED",
                    detail={"username": body.username}, ip=client_ip)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "UNAUTHORIZED", "message": "Invalid username or password."}},
        )

    ratelimit.record_success(body.username, client_ip)
    audit.write(db, user.id, "LOGIN", ip=client_ip)
    db.commit()
    return LoginResponse(
        access_token=create_access_token(str(user.id)),
        expires_in=settings.jwt_ttl_minutes * 60,
        key_stale=user.key_stale,
        is_admin=user.is_admin,
    )


@router.get("/me", response_model=MeResponse)
def me(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    return MeResponse(
        id=user.id,
        username=user.username,
        attributes=_attribute_names(db, user),
        is_admin=user.is_admin,
        key_stale=user.key_stale,
    )
