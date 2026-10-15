import os
import uuid

import pytest
from cryptography.exceptions import InvalidTag

from crypto import aes_stream

SIZES = [0, 1, 65535, 65536, 65537, 10 * 1024 * 1024]


def _roundtrip(tmp_path, data, file_id=None, decrypt_file_id=None):
    in_path = tmp_path / "in.bin"
    out_path = tmp_path / "out.svlt"
    dec_path = tmp_path / "dec.bin"
    in_path.write_bytes(data)
    key = os.urandom(32)
    file_id = file_id or uuid.uuid4().bytes
    aes_stream.encrypt_file(str(in_path), str(out_path), key, file_id)
    aes_stream.decrypt_file(str(out_path), str(dec_path), key, decrypt_file_id or file_id)
    return dec_path


@pytest.mark.parametrize("size", SIZES)
def test_c01_round_trip(tmp_path, size):
    data = os.urandom(size)
    dec_path = _roundtrip(tmp_path, data)
    assert dec_path.read_bytes() == data


def test_c02_tamper_byte_fails_with_no_partial_output(tmp_path):
    data = os.urandom(aes_stream.DEFAULT_CHUNK_SIZE + 100)
    in_path = tmp_path / "in.bin"
    out_path = tmp_path / "out.svlt"
    dec_path = tmp_path / "dec.bin"
    in_path.write_bytes(data)
    key = os.urandom(32)
    file_id = uuid.uuid4().bytes
    aes_stream.encrypt_file(str(in_path), str(out_path), key, file_id)

    raw = bytearray(out_path.read_bytes())
    raw[aes_stream.HEADER_SIZE] ^= 0xFF
    out_path.write_bytes(bytes(raw))

    with pytest.raises(InvalidTag):
        aes_stream.decrypt_file(str(out_path), str(dec_path), key, file_id)
    assert not dec_path.exists()
    assert not (tmp_path / "dec.bin.part").exists()


def test_c03_swap_chunks_fails(tmp_path):
    chunk_size = aes_stream.DEFAULT_CHUNK_SIZE
    data = os.urandom(chunk_size * 3)
    in_path = tmp_path / "in.bin"
    out_path = tmp_path / "out.svlt"
    dec_path = tmp_path / "dec.bin"
    in_path.write_bytes(data)
    key = os.urandom(32)
    file_id = uuid.uuid4().bytes
    aes_stream.encrypt_file(str(in_path), str(out_path), key, file_id)

    raw = bytearray(out_path.read_bytes())
    chunk_len = chunk_size + aes_stream.TAG_SIZE
    start0 = aes_stream.HEADER_SIZE
    start1 = start0 + chunk_len
    start2 = start1 + chunk_len
    chunk0 = bytes(raw[start0:start1])
    chunk1 = bytes(raw[start1:start2])
    raw[start0:start1] = chunk1
    raw[start1:start2] = chunk0
    out_path.write_bytes(bytes(raw))

    with pytest.raises(Exception):
        aes_stream.decrypt_file(str(out_path), str(dec_path), key, file_id)


def test_c04_drop_final_chunk_fails(tmp_path):
    chunk_size = aes_stream.DEFAULT_CHUNK_SIZE
    final_len = 100
    data = os.urandom(chunk_size * 2 + final_len)
    in_path = tmp_path / "in.bin"
    out_path = tmp_path / "out.svlt"
    dec_path = tmp_path / "dec.bin"
    in_path.write_bytes(data)
    key = os.urandom(32)
    file_id = uuid.uuid4().bytes
    aes_stream.encrypt_file(str(in_path), str(out_path), key, file_id)

    raw = out_path.read_bytes()
    truncated = raw[: len(raw) - (final_len + aes_stream.TAG_SIZE)]
    out_path.write_bytes(truncated)

    with pytest.raises(Exception):
        aes_stream.decrypt_file(str(out_path), str(dec_path), key, file_id)


def test_c05_wrong_file_id_fails(tmp_path):
    data = os.urandom(1024)
    file_id_a = uuid.uuid4().bytes
    file_id_b = uuid.uuid4().bytes
    in_path = tmp_path / "in.bin"
    out_path = tmp_path / "out.svlt"
    dec_path = tmp_path / "dec.bin"
    in_path.write_bytes(data)
    key = os.urandom(32)
    aes_stream.encrypt_file(str(in_path), str(out_path), key, file_id_a)

    with pytest.raises(Exception):
        aes_stream.decrypt_file(str(out_path), str(dec_path), key, file_id_b)


def test_filename_encryption_round_trip():
    key = os.urandom(32)
    file_id = uuid.uuid4().bytes
    enc, nonce = aes_stream.encrypt_filename("endsem_qp.pdf", key, file_id)
    assert aes_stream.decrypt_filename(enc, nonce, key, file_id) == "endsem_qp.pdf"


def test_filename_decrypt_wrong_file_id_fails():
    key = os.urandom(32)
    file_id = uuid.uuid4().bytes
    other_file_id = uuid.uuid4().bytes
    enc, nonce = aes_stream.encrypt_filename("secret.docx", key, file_id)
    with pytest.raises(Exception):
        aes_stream.decrypt_filename(enc, nonce, key, other_file_id)


@pytest.mark.parametrize("size", [0, 1, 65535, 65536, 65537, 3 * 65536, 1024 * 1024])
def test_ciphertext_size_prediction_matches_reality(tmp_path, size):
    """The client calls /files/init (which needs the ciphertext size) before it
    can encrypt, so the prediction has to be exact."""
    key = os.urandom(32)
    file_id = os.urandom(16)
    plain = tmp_path / "p.bin"
    cipher = tmp_path / "c.svlt"
    plain.write_bytes(os.urandom(size))

    aes_stream.encrypt_file(str(plain), str(cipher), key, file_id)
    assert cipher.stat().st_size == aes_stream.ciphertext_size_for(size)


def test_total_chunks_for_counts_a_single_chunk_for_empty_input():
    assert aes_stream.total_chunks_for(0) == 1
    assert aes_stream.total_chunks_for(1) == 1
    assert aes_stream.total_chunks_for(65536) == 1
    assert aes_stream.total_chunks_for(65537) == 2
