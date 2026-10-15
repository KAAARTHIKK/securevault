"""Base64 helpers -- binary values are base64 in JSON transport (doc 05 Section 2)."""
import base64


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data)
