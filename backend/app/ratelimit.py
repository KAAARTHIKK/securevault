"""Simple in-memory login rate limiter (doc 06 Phase 4 hardening).

Deliberately process-local: one backend process, no Redis dependency, and the
window is short. It throttles password guessing per (username, client IP) and
is cleared on a successful login.
"""
import threading
import time
from typing import Dict, List, Tuple

Key = Tuple[str, str]

_attempts: Dict[Key, List[float]] = {}
_lock = threading.Lock()


def _prune(key: Key, now: float, window: int) -> List[float]:
    hits = [t for t in _attempts.get(key, []) if now - t < window]
    if hits:
        _attempts[key] = hits
    else:
        _attempts.pop(key, None)
    return hits


def check(username: str, client_ip: str, max_attempts: int, window: int) -> int:
    """Returns the seconds to wait if the caller is throttled, or 0 if allowed."""
    key = (username.lower(), client_ip)
    now = time.monotonic()
    with _lock:
        hits = _prune(key, now, window)
        if len(hits) < max_attempts:
            return 0
        return max(1, int(window - (now - min(hits))))


def record_failure(username: str, client_ip: str, window: int) -> None:
    key = (username.lower(), client_ip)
    now = time.monotonic()
    with _lock:
        hits = _prune(key, now, window)
        hits.append(now)
        _attempts[key] = hits


def record_success(username: str, client_ip: str) -> None:
    with _lock:
        _attempts.pop((username.lower(), client_ip), None)


def reset() -> None:
    """Test helper: forget every recorded attempt."""
    with _lock:
        _attempts.clear()
