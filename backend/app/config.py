"""pydantic-settings configuration, loaded from backend/.env (doc 04 Section 4).

Doc 06 Phase 4 hardening: the placeholder values shipped in .env.example must
never reach a deployment, so they are rejected here unless SECUREVAULT_DEV=1
(which the test suite sets, since it uses a throwaway database and moto).
"""
import os
from functools import lru_cache
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PLACEHOLDERS = (
    "change-me-64-random-hex-chars",
    "change-me-long-passphrase-for-msk.enc",
    "changeme",
    "change-me",
)
MIN_SECRET_LENGTH = 32


def _dev_mode() -> bool:
    return os.environ.get("SECUREVAULT_DEV", "").lower() in ("1", "true", "yes")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file="backend/.env", extra="ignore")

    database_url: str
    jwt_secret: str
    jwt_ttl_minutes: int = 30
    ka_passphrase: str
    storage_backend: str = "s3"
    aws_region: str = "ap-south-1"
    s3_bucket: str
    s3_prefix: str = "objects/"
    aws_access_key_id: str
    aws_secret_access_key: str
    presign_ttl_seconds: int = 300

    # login throttling (doc 06 Phase 4)
    login_max_attempts: int = 5
    login_window_seconds: int = 60

    @field_validator("jwt_secret", "ka_passphrase")
    @classmethod
    def _secret_must_be_real(cls, value: str) -> str:
        if _dev_mode():
            return value
        if value.strip().lower() in PLACEHOLDERS:
            raise ValueError(
                "placeholder secret from .env.example is still in use -- generate a real one "
                "(python -c \"import secrets;print(secrets.token_hex(32))\")"
            )
        if len(value) < MIN_SECRET_LENGTH:
            raise ValueError("secret must be at least %d characters" % MIN_SECRET_LENGTH)
        return value

    @field_validator("aws_access_key_id", "aws_secret_access_key")
    @classmethod
    def _credential_must_be_real(cls, value: str) -> str:
        if _dev_mode():
            return value
        if value.strip().lower() in PLACEHOLDERS:
            raise ValueError("placeholder AWS credential from .env.example is still in use")
        return value

    @field_validator("storage_backend")
    @classmethod
    def _known_backend(cls, value: str) -> str:
        if value not in ("s3", "moto"):
            raise ValueError("STORAGE_BACKEND must be 's3' or 'moto', got %r" % value)
        return value

    @field_validator("s3_prefix")
    @classmethod
    def _prefix_ends_with_slash(cls, value: str) -> str:
        if value and not value.endswith("/"):
            raise ValueError("S3_PREFIX must end with '/'")
        return value

    @field_validator("presign_ttl_seconds")
    @classmethod
    def _short_lived_presign(cls, value: int) -> int:
        if not 30 <= value <= 3600:
            raise ValueError("PRESIGN_TTL_SECONDS must be between 30 and 3600")
        return value

    def warnings(self) -> List[str]:
        """Non-fatal things worth printing at startup."""
        notes = []
        if _dev_mode():
            notes.append("SECUREVAULT_DEV is set: .env placeholder checks are relaxed.")
        if self.jwt_ttl_minutes > 60:
            notes.append("JWT_TTL_MINUTES is %d; a shorter token life is safer." % self.jwt_ttl_minutes)
        if self.storage_backend == "moto":
            notes.append("STORAGE_BACKEND=moto: no real S3 is being used.")
        return notes


@lru_cache()
def get_settings() -> Settings:
    return Settings()
