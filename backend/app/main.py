"""FastAPI app entrypoint (doc 05 Section 2).

Doc 06 Phase 4 hardening lives here too: a secret-scrubbing logging filter is
installed over every handler (pre-signed URL signatures, bearer tokens and
serialized keys are redacted even if something logs them by accident), and the
.env sanity checks run at startup.
"""
import logging

from fastapi import FastAPI

from . import logging_filter
from .config import get_settings
from .routes import admin, auth, files, keys

logger = logging.getLogger("securevault")

app = FastAPI(title="SecureVault API", version="1.0.0")

API_PREFIX = "/api/v1"
app.include_router(auth.router, prefix=API_PREFIX)
app.include_router(keys.router, prefix=API_PREFIX)
app.include_router(files.router, prefix=API_PREFIX)
app.include_router(admin.router, prefix=API_PREFIX)


@app.on_event("startup")
def _startup_checks() -> None:
    settings = get_settings()  # raises on a placeholder or malformed .env

    # belt and braces for global rule 1: scrub key material from every log line
    logging_filter.install(literals=(
        settings.jwt_secret,
        settings.ka_passphrase,
        settings.aws_access_key_id,
        settings.aws_secret_access_key,
    ))

    for note in settings.warnings():
        logger.warning(note)
    logger.info(
        "SecureVault API ready (storage=%s, bucket=%s, presign TTL=%ds)",
        settings.storage_backend, settings.s3_bucket, settings.presign_ttl_seconds,
    )


@app.get(API_PREFIX + "/health", tags=["meta"])
def health() -> dict:
    """Liveness probe. Deliberately reveals nothing about configuration."""
    return {"status": "ok"}
