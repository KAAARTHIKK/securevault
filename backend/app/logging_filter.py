"""Secret-scrubbing logging filter (doc 08 Phase 4 item 4).

Global rule 1 says no key material may reach a log line. The code never logs
secrets deliberately, but a traceback, a repr of a request, or uvicorn's access
log (which includes the query string of a pre-signed S3 URL, signature and all)
can leak one by accident. This filter is the belt to that braces: it rewrites
the message of every record passing through the handlers it is attached to.

It scrubs, in order:
  - the configured secrets themselves (JWT_SECRET, KA_PASSPHRASE, AWS keys)
  - AWS SigV4 query parameters (X-Amz-Signature, X-Amz-Credential, X-Amz-Security-Token)
  - Authorization: Bearer <jwt> headers and bare JWTs
  - long base64/hex runs, which is what a serialized key or ciphertext looks like
"""
import logging
import re
from typing import List, Pattern, Tuple

REDACTED = "[REDACTED]"
# 40 chars, not 64: base64 of a 32-byte AES key is 44 characters, and that is
# exactly the value this filter most needs to catch. Separators (., -, _, /,
# whitespace) break the run, so URLs, paths and UUIDs are not affected.
MIN_BLOB_LENGTH = 40

_PATTERNS: List[Tuple[Pattern, str]] = [
    # pre-signed URL signatures and credentials
    (re.compile(r"(X-Amz-Signature=)[A-Za-z0-9%]+", re.I), r"\1" + REDACTED),
    (re.compile(r"(X-Amz-Credential=)[^&\s\"']+", re.I), r"\1" + REDACTED),
    (re.compile(r"(X-Amz-Security-Token=)[^&\s\"']+", re.I), r"\1" + REDACTED),
    (re.compile(r"(AWS4-HMAC-SHA256\s+Credential=)[^,\s]+", re.I), r"\1" + REDACTED),
    # bearer tokens and bare JWTs
    (re.compile(r"(Bearer\s+)[A-Za-z0-9\-_.=]+", re.I), r"\1" + REDACTED),
    (re.compile(r"\beyJ[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}\b"), REDACTED),
    # json fields that carry key material
    (re.compile(r'("(?:sk|ct_key|msk|wrapped_key|eph_public|public_key|password)"\s*:\s*")[^"]+'),
     r"\1" + REDACTED),
    # anything that looks like a serialized key or ciphertext
    (re.compile(r"\b[A-Za-z0-9+/]{%d,}={0,2}\b" % MIN_BLOB_LENGTH), REDACTED),
    (re.compile(r"\b[0-9a-fA-F]{%d,}\b" % MIN_BLOB_LENGTH), REDACTED),
]


def scrub(text: str, literals=()) -> str:
    """Redact secrets from one string. Safe to call on anything."""
    if not text:
        return text
    for literal in literals:
        if literal and len(literal) >= 8 and literal in text:
            text = text.replace(literal, REDACTED)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class SecretScrubFilter(logging.Filter):
    """Rewrites each record's message in place. Never drops a record."""

    def __init__(self, literals=()):
        super().__init__()
        # keep only non-trivial values; a short or empty secret would match everywhere
        self._literals = tuple(v for v in literals if v and len(v) >= 8)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True
        cleaned = scrub(message, self._literals)
        if cleaned != message:
            record.msg = cleaned
            record.args = ()
        if record.exc_text:
            record.exc_text = scrub(record.exc_text, self._literals)
        return True


def install(literals=()) -> SecretScrubFilter:
    """Attach the filter to the root logger's handlers and to uvicorn's.

    Filters on a logger do not apply to records propagated from children, so it
    is attached to the *handlers*, which every record must pass through.
    """
    scrubber = SecretScrubFilter(literals)
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig()
    for handler in root.handlers:
        handler.addFilter(scrubber)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "fastapi", "sqlalchemy.engine"):
        logger = logging.getLogger(name)
        logger.addFilter(scrubber)
        for handler in logger.handlers:
            handler.addFilter(scrubber)
    return scrubber
