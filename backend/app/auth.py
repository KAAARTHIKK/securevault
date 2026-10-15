"""bcrypt password hashing, JWT (HS256), and FastAPI auth dependencies (doc 05)."""
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from . import models
from .config import get_settings
from .db import get_db

_pwd_context = CryptContext(schemes=["bcrypt"])
_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def hash_password(password: str) -> str:
    return _pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return _pwd_context.verify(password, password_hash)


def create_access_token(user_id: str) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_ttl_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def _api_error(code: str, message: str, status_code: int) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"error": {"code": code, "message": message}})


def get_current_user(
    token: Optional[str] = Depends(_oauth2_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    if not token:
        raise _api_error("UNAUTHORIZED", "Missing bearer token.", status.HTTP_401_UNAUTHORIZED)
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
        user_id = uuid.UUID(payload["sub"])
    except (JWTError, ValueError, KeyError):
        raise _api_error("UNAUTHORIZED", "Invalid or expired token.", status.HTTP_401_UNAUTHORIZED)
    user = db.get(models.User, user_id)
    if user is None:
        raise _api_error("UNAUTHORIZED", "User no longer exists.", status.HTTP_401_UNAUTHORIZED)
    return user


def require_admin(user: models.User = Depends(get_current_user)) -> models.User:
    if not user.is_admin:
        raise _api_error("FORBIDDEN", "Admin privileges required.", status.HTTP_403_FORBIDDEN)
    return user


def require_fresh_key(user: models.User = Depends(get_current_user)) -> models.User:
    if user.key_stale:
        raise _api_error("KEY_STALE", "Attribute versions changed; re-issue your key.", status.HTTP_409_CONFLICT)
    return user


def require_fresh_admin(user: models.User = Depends(require_admin)) -> models.User:
    if user.key_stale:
        raise _api_error("KEY_STALE", "Attribute versions changed; re-issue your key.", status.HTTP_409_CONFLICT)
    return user
