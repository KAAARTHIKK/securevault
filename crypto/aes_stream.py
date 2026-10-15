"""Chunked AES-256-GCM file format (doc 03 Section 4).

Wire format is fixed -- any change breaks every security test in doc 07 Section 1.1:

Header (32 bytes):
    magic         4  b"SVLT"
    format_ver    1  0x01
    reserved      3  0x000000
    chunk_size    4  uint32 BE (default 65536)
    nonce_prefix  8  random
    total_chunks  8  uint64 BE
    reserved      4

Then for i = 0 .. n-1: ciphertext_i || tag_i (16 bytes)

nonce_i = nonce_prefix (8) || uint32_BE(i) (4)
aad_i   = header || file_id (16) || uint32_BE(i) || final_flag (1 byte)
"""
import os
import struct
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"SVLT"
FORMAT_VERSION = 0x01
DEFAULT_CHUNK_SIZE = 65536
HEADER_SIZE = 32
TAG_SIZE = 16
NONCE_PREFIX_SIZE = 8
FILE_ID_SIZE = 16
KEY_SIZE = 32


def _build_header(chunk_size: int, nonce_prefix: bytes, total_chunks: int) -> bytes:
    return (
        MAGIC
        + bytes([FORMAT_VERSION])
        + b"\x00\x00\x00"
        + struct.pack(">I", chunk_size)
        + nonce_prefix
        + struct.pack(">Q", total_chunks)
        + b"\x00\x00\x00\x00"
    )


def _parse_header(header: bytes) -> Tuple[int, bytes, int]:
    if len(header) != HEADER_SIZE:
        raise ValueError("truncated header")
    if header[0:4] != MAGIC:
        raise ValueError("bad magic")
    if header[4] != FORMAT_VERSION:
        raise ValueError("unsupported format version")
    chunk_size = struct.unpack(">I", header[8:12])[0]
    nonce_prefix = header[12:20]
    total_chunks = struct.unpack(">Q", header[20:28])[0]
    return chunk_size, nonce_prefix, total_chunks


def _aad(header: bytes, file_id: bytes, index: int, final: bool) -> bytes:
    return header + file_id + struct.pack(">I", index) + (b"\x01" if final else b"\x00")


def _nonce(nonce_prefix: bytes, index: int) -> bytes:
    return nonce_prefix + struct.pack(">I", index)


def _check_file_id(file_id: bytes) -> None:
    if len(file_id) != FILE_ID_SIZE:
        raise ValueError("file_id must be %d bytes" % FILE_ID_SIZE)


def total_chunks_for(plaintext_size: int, chunk_size: int = DEFAULT_CHUNK_SIZE) -> int:
    """Number of chunks the format uses for a plaintext of this size (0 B still gets 1)."""
    return max(1, -(-plaintext_size // chunk_size))


def ciphertext_size_for(plaintext_size: int, chunk_size: int = DEFAULT_CHUNK_SIZE) -> int:
    """Exact ciphertext length for a plaintext of this size.

    The client needs this *before* encrypting, because POST /files/init takes
    ciphertext_size and only then hands back the file_id that encap() and the
    chunk AAD are bound to.
    """
    return HEADER_SIZE + plaintext_size + TAG_SIZE * total_chunks_for(plaintext_size, chunk_size)


def encrypt_file(in_path: str, out_path: str, key: bytes, file_id: bytes,
                  chunk_size: int = DEFAULT_CHUNK_SIZE) -> None:
    """Stream-encrypt in_path to out_path under the format above."""
    _check_file_id(file_id)
    size = os.path.getsize(in_path)
    total_chunks = max(1, -(-size // chunk_size))
    nonce_prefix = os.urandom(NONCE_PREFIX_SIZE)
    header = _build_header(chunk_size, nonce_prefix, total_chunks)
    aesgcm = AESGCM(key)

    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        fout.write(header)
        for index in range(total_chunks):
            chunk = fin.read(chunk_size)
            final = index == total_chunks - 1
            aad = _aad(header, file_id, index, final)
            nonce = _nonce(nonce_prefix, index)
            fout.write(aesgcm.encrypt(nonce, chunk, aad))


def decrypt_file(in_path: str, out_path: str, key: bytes, file_id: bytes) -> None:
    """Stream-decrypt in_path to out_path. Raises on any tamper/reorder/truncation;
    leaves no partial output behind on failure."""
    _check_file_id(file_id)
    aesgcm = AESGCM(key)
    out_tmp = out_path + ".part"
    with open(in_path, "rb") as fin:
        header = fin.read(HEADER_SIZE)
        chunk_size, nonce_prefix, total_chunks = _parse_header(header)
        try:
            with open(out_tmp, "wb") as fout:
                for index in range(total_chunks):
                    ct = fin.read(chunk_size + TAG_SIZE)
                    final = index == total_chunks - 1
                    expected_len = chunk_size + TAG_SIZE
                    if (not final and len(ct) != expected_len) or (final and len(ct) < TAG_SIZE):
                        raise ValueError("truncated ciphertext")
                    aad = _aad(header, file_id, index, final)
                    nonce = _nonce(nonce_prefix, index)
                    fout.write(aesgcm.decrypt(nonce, ct, aad))
                if fin.read(1):
                    raise ValueError("unexpected trailing data")
        except Exception:
            if os.path.exists(out_tmp):
                os.remove(out_tmp)
            raise
    os.replace(out_tmp, out_path)


def encrypt_filename(filename: str, key: bytes, file_id: bytes) -> Tuple[bytes, bytes]:
    """Encrypt the original filename. AAD = file_id || b"name"."""
    _check_file_id(file_id)
    nonce = os.urandom(12)
    aad = file_id + b"name"
    enc = AESGCM(key).encrypt(nonce, filename.encode("utf-8"), aad)
    return enc, nonce


def decrypt_filename(enc_filename: bytes, nonce: bytes, key: bytes, file_id: bytes) -> str:
    _check_file_id(file_id)
    aad = file_id + b"name"
    return AESGCM(key).decrypt(nonce, enc_filename, aad).decode("utf-8")
