"""Audit log writer (doc 05 Section 1 audit_log table). Never write keys or plaintext."""
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from . import models


def write(
    db: Session,
    user_id,
    action: str,
    file_id=None,
    detail: Optional[Dict[str, Any]] = None,
    ip: Optional[str] = None,
) -> None:
    db.add(models.AuditLog(user_id=user_id, action=action, file_id=file_id, detail=detail, ip=ip))
    db.flush()
