"""Storage protocol and S3 implementation (doc 04 Section 5)."""
from typing import Optional

try:
    from typing import Protocol
except ImportError:  # Python 3.7 fallback, unused on our 3.8 target
    from typing_extensions import Protocol

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

from .config import get_settings


class Storage(Protocol):
    def presign_put(self, object_key: str, size: int) -> str: ...
    def presign_get(self, object_key: str) -> str: ...
    def head(self, object_key: str) -> Optional[int]: ...
    def delete(self, object_key: str) -> None: ...


class S3Storage:
    def __init__(self, bucket: str, region: str, ttl_seconds: int):
        self._bucket = bucket
        self._ttl = ttl_seconds
        self._client = boto3.client(
            "s3",
            region_name=region,
            config=Config(signature_version="s3v4"),
        )

    def presign_put(self, object_key: str, size: int) -> str:
        return self._client.generate_presigned_url(
            "put_object",
            Params={"Bucket": self._bucket, "Key": object_key, "ContentType": "application/octet-stream"},
            ExpiresIn=self._ttl,
        )

    def presign_get(self, object_key: str) -> str:
        return self._client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self._bucket, "Key": object_key},
            ExpiresIn=self._ttl,
        )

    def head(self, object_key: str) -> Optional[int]:
        try:
            resp = self._client.head_object(Bucket=self._bucket, Key=object_key)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("404", "NoSuchKey"):
                return None
            raise
        return resp["ContentLength"]

    def delete(self, object_key: str) -> None:
        self._client.delete_object(Bucket=self._bucket, Key=object_key)


def get_storage() -> Storage:
    settings = get_settings()
    if settings.storage_backend not in ("s3", "moto"):
        raise ValueError("unknown STORAGE_BACKEND: %r" % settings.storage_backend)
    return S3Storage(settings.s3_bucket, settings.aws_region, settings.presign_ttl_seconds)
