import pytest

from crypto import keystore


def test_round_trip(tmp_path):
    path = tmp_path / "sk.enc"
    keystore.save(str(path), b"super-secret-key-material", "correct horse battery staple")
    assert keystore.load(str(path), "correct horse battery staple") == b"super-secret-key-material"


def test_c10_wrong_password_fails_cleanly(tmp_path):
    path = tmp_path / "sk.enc"
    keystore.save(str(path), b"super-secret-key-material", "correct horse battery staple")
    with pytest.raises(Exception):
        keystore.load(str(path), "wrong password")


def test_corrupted_blob_fails_cleanly(tmp_path):
    path = tmp_path / "sk.enc"
    keystore.save(str(path), b"super-secret-key-material", "pw")
    raw = bytearray(path.read_bytes())
    raw[-1] ^= 0xFF
    path.write_bytes(bytes(raw))
    with pytest.raises(Exception):
        keystore.load(str(path), "pw")
