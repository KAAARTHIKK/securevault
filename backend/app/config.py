"""pydantic-settings configuration, loaded from backend/.env (doc 04 Section 4)."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


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


@lru_cache()
def get_settings() -> Settings:
    return Settings()
