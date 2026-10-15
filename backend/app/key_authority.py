"""Key Authority: loads pk.bin/msk.enc and issues per-user ABE secret keys
(doc 02 Section 2-3, doc 03 Section 5). Never sees file keys or plaintext.
"""
from pathlib import Path
from typing import List

from crypto import abe_kem, keystore

from .config import get_settings

PK_FILENAME = "pk.bin"
MSK_FILENAME = "msk.enc"


class KeyAuthority:
    def __init__(self, pk, msk):
        self.pk = pk
        self.msk = msk

    def issue_key(self, versioned_attributes: List[str]):
        return abe_kem.keygen(self.pk, self.msk, versioned_attributes)


def _data_dir() -> Path:
    return Path(__file__).resolve().parent.parent  # backend/


def pk_path() -> Path:
    return _data_dir() / PK_FILENAME


def msk_path() -> Path:
    return _data_dir() / MSK_FILENAME


def setup_and_save() -> None:
    """Runs ABE setup() once; writes pk.bin (plain) and msk.enc (keystore-encrypted)."""
    pk, msk = abe_kem.setup()
    settings = get_settings()
    pk_path().write_bytes(abe_kem.serialize_pk(pk))
    keystore.save(str(msk_path()), abe_kem.serialize_msk(msk), settings.ka_passphrase)


def load() -> KeyAuthority:
    settings = get_settings()
    pk = abe_kem.deserialize_pk(pk_path().read_bytes())
    msk = abe_kem.deserialize_msk(keystore.load(str(msk_path()), settings.ka_passphrase))
    return KeyAuthority(pk, msk)
