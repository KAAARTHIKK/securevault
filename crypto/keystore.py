"""Password-based local key store: scrypt(N=2^15, r=8, p=1) + AES-GCM (doc 03 Section 1, 5).

Versioned file format: magic(4) || format_ver(1) || salt(16) || nonce(12) || ciphertext+tag.
Used both for a user's ABE secret key (~/.securevault/<user>.key.enc) and the
KA's msk.enc.
"""
import os
from typing import Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"SVKS"
FORMAT_VERSION = 0x01
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1

PathLike = Union[str, os.PathLike]


def _derive(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_SIZE, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def encrypt_blob(plaintext: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive(password, salt)
    header = MAGIC + bytes([FORMAT_VERSION])
    ct = AESGCM(key).encrypt(nonce, plaintext, header)
    return header + salt + nonce + ct


def decrypt_blob(blob: bytes, password: str) -> bytes:
    min_len = len(MAGIC) + 1 + SALT_SIZE + NONCE_SIZE
    if len(blob) < min_len:
        raise ValueError("truncated keystore blob")
    header = blob[:5]
    if header[:4] != MAGIC or header[4] != FORMAT_VERSION:
        raise ValueError("bad keystore header")
    salt = blob[5:5 + SALT_SIZE]
    nonce = blob[5 + SALT_SIZE:5 + SALT_SIZE + NONCE_SIZE]
    ct = blob[5 + SALT_SIZE + NONCE_SIZE:]
    key = _derive(password, salt)
    return AESGCM(key).decrypt(nonce, ct, header)


def save(path: PathLike, plaintext: bytes, password: str) -> None:
    with open(path, "wb") as f:
        f.write(encrypt_blob(plaintext, password))


def load(path: PathLike, password: str) -> bytes:
    with open(path, "rb") as f:
        blob = f.read()
    return decrypt_blob(blob, password)
