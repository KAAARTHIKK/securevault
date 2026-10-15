import os
import uuid

from crypto import ecc_wrap


def test_c12_wrap_unwrap_round_trip():
    priv, pub = ecc_wrap.generate_keypair()
    key = os.urandom(32)
    file_id = uuid.uuid4().bytes
    recipient_id = uuid.uuid4().bytes

    eph_pub, nonce, wrapped = ecc_wrap.wrap_key(key, pub, file_id, recipient_id)
    unwrapped = ecc_wrap.unwrap_key(eph_pub, nonce, wrapped, priv, file_id, recipient_id)

    assert unwrapped == key


def test_c12_non_recipient_cannot_unwrap():
    priv_a, pub_a = ecc_wrap.generate_keypair()
    priv_b, _ = ecc_wrap.generate_keypair()
    key = os.urandom(32)
    file_id = uuid.uuid4().bytes
    recipient_id = uuid.uuid4().bytes

    eph_pub, nonce, wrapped = ecc_wrap.wrap_key(key, pub_a, file_id, recipient_id)

    assert ecc_wrap.unwrap_key(eph_pub, nonce, wrapped, priv_b, file_id, recipient_id) is None
