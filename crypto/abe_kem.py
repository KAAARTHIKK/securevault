"""CP-ABE (BSW07, pairing group SS512) used as a KEM (doc 03 Section 2).

encap() draws a random GT element R, derives the file key K from it via HKDF,
and returns the ABE ciphertext of R. decap() reverses this. BSW07's decrypt()
signals "policy not satisfied" by returning False instead of raising; any
exception is also treated as denial, never propagated.
"""
from typing import List, Optional, Tuple

from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.core.engine.util import objectToBytes, bytesToObject
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

GROUP_PARAM = "SS512"
KDF_INFO = b"securevault-file-key-v1"
KEY_SIZE = 32


def _group() -> PairingGroup:
    return PairingGroup(GROUP_PARAM)


def _scheme(group: PairingGroup) -> CPabe_BSW07:
    return CPabe_BSW07(group)


def setup():
    group = _group()
    return _scheme(group).setup()


def keygen(pk, msk, versioned_attributes: List[str]):
    group = _group()
    return _scheme(group).keygen(pk, msk, list(versioned_attributes))


def _derive_key(r_bytes: bytes, file_id: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=file_id, info=KDF_INFO)
    return hkdf.derive(r_bytes)


def encap(pk, versioned_policy: str, file_id: bytes) -> Tuple[bytes, bytes]:
    group = _group()
    cpabe = _scheme(group)
    r = group.random(GT)
    ct = cpabe.encrypt(pk, r, versioned_policy)
    key = _derive_key(objectToBytes(r, group), file_id)
    return key, serialize_ciphertext(ct)


def decap(pk, sk, ct_bytes: bytes, file_id: bytes) -> Optional[bytes]:
    try:
        group = _group()
        cpabe = _scheme(group)
        ct = deserialize_ciphertext(ct_bytes)
        r = cpabe.decrypt(pk, sk, ct)
        if r is False or r is None:
            return None
        return _derive_key(objectToBytes(r, group), file_id)
    except Exception:
        return None


def serialize_pk(pk) -> bytes:
    return objectToBytes(pk, _group())


def deserialize_pk(data: bytes):
    return bytesToObject(data, _group())


def serialize_sk(sk) -> bytes:
    return objectToBytes(sk, _group())


def deserialize_sk(data: bytes):
    return bytesToObject(data, _group())


def serialize_ciphertext(ct) -> bytes:
    return objectToBytes(ct, _group())


def deserialize_ciphertext(data: bytes):
    return bytesToObject(data, _group())
