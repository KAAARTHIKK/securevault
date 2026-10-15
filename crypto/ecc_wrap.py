"""X25519 per-recipient key wrapping, the ECC fallback mode (doc 03 Section 6).

for each recipient u:
    eph    <- X25519 ephemeral keypair
    shared <- ECDH(eph.priv, u.pub)
    KEK    <- HKDF(shared, salt=file_id, info=b"securevault-ecc-wrap-v1")
    wrapped_u <- AESGCM(KEK).encrypt(nonce, K, aad=file_id||u.id)
"""
import os
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KDF_INFO = b"securevault-ecc-wrap-v1"
NONCE_SIZE = 12
KEY_SIZE = 32


def generate_keypair() -> Tuple[bytes, bytes]:
    """Returns (private_bytes, public_bytes), both raw X25519 encodings."""
    priv = X25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def _derive_kek(shared: bytes, file_id: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=file_id, info=KDF_INFO)
    return hkdf.derive(shared)


def wrap_key(key: bytes, recipient_public: bytes, file_id: bytes,
             recipient_id: bytes) -> Tuple[bytes, bytes, bytes]:
    """Returns (eph_public, nonce, wrapped_key) to store per recipient."""
    eph_priv = X25519PrivateKey.generate()
    eph_public = eph_priv.public_key().public_bytes_raw()
    recipient_pub = X25519PublicKey.from_public_bytes(recipient_public)
    kek = _derive_kek(eph_priv.exchange(recipient_pub), file_id)
    nonce = os.urandom(NONCE_SIZE)
    wrapped = AESGCM(kek).encrypt(nonce, key, file_id + recipient_id)
    return eph_public, nonce, wrapped


def unwrap_key(eph_public: bytes, nonce: bytes, wrapped: bytes, recipient_private: bytes,
               file_id: bytes, recipient_id: bytes) -> Optional[bytes]:
    """Returns the unwrapped key, or None if this is not a valid recipient."""
    try:
        recipient_priv = X25519PrivateKey.from_private_bytes(recipient_private)
        eph_pub = X25519PublicKey.from_public_bytes(eph_public)
        kek = _derive_kek(recipient_priv.exchange(eph_pub), file_id)
        return AESGCM(kek).decrypt(nonce, wrapped, file_id + recipient_id)
    except Exception:
        return None
