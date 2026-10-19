"""Audit log writer (doc 05 Section 1 audit_log table). Never write keys or plaintext."""
import ipaddress
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from . import models


def _inet_or_none(ip: Optional[str]) -> Optional[str]:
    # audit_log.ip is INET; ASGI test clients, unix sockets and some proxies report
    # non-IP hosts ("testclient", "unknown") that would crash the INSERT.
    try:
        return str(ipaddress.ip_address(ip)) if ip else None
    except ValueError:
        return None


def write(
    db: Session,
    user_id,
    action: str,
    file_id=None,
    detail: Optional[Dict[str, Any]] = None,
    ip: Optional[str] = None,
) -> None:
    db.add(models.AuditLog(user_id=user_id, action=action, file_id=file_id, detail=detail, ip=_inet_or_none(ip)))
    db.flush()
