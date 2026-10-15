import uuid

from crypto import abe_kem

POLICY = "(DEPT_CSE_V1 and ROLE_FACULTY_V1)"


def test_c06_decap_with_satisfying_attributes_returns_same_key():
    pk, msk = abe_kem.setup()
    sk = abe_kem.keygen(pk, msk, ["DEPT_CSE_V1", "ROLE_FACULTY_V1"])
    file_id = uuid.uuid4().bytes

    key, ct = abe_kem.encap(pk, POLICY, file_id)
    recovered = abe_kem.decap(pk, sk, ct, file_id)

    assert recovered == key


def test_c07_decap_with_non_satisfying_attributes_returns_none():
    pk, msk = abe_kem.setup()
    sk = abe_kem.keygen(pk, msk, ["DEPT_ECE_V1", "ROLE_STUDENT_V1"])
    file_id = uuid.uuid4().bytes

    _, ct = abe_kem.encap(pk, POLICY, file_id)

    assert abe_kem.decap(pk, sk, ct, file_id) is None


def test_c08_collusion_each_partial_key_fails_alone():
    pk, msk = abe_kem.setup()
    sk_dept_only = abe_kem.keygen(pk, msk, ["DEPT_CSE_V1"])
    sk_role_only = abe_kem.keygen(pk, msk, ["ROLE_FACULTY_V1"])
    file_id = uuid.uuid4().bytes

    _, ct = abe_kem.encap(pk, POLICY, file_id)

    assert abe_kem.decap(pk, sk_dept_only, ct, file_id) is None
    assert abe_kem.decap(pk, sk_role_only, ct, file_id) is None


def test_c09_old_version_key_denied_against_newer_policy():
    pk, msk = abe_kem.setup()
    sk_old = abe_kem.keygen(pk, msk, ["DEPT_CSE_V1", "ROLE_FACULTY_V3"])
    file_id = uuid.uuid4().bytes

    _, ct = abe_kem.encap(pk, "(DEPT_CSE_V1 and ROLE_FACULTY_V4)", file_id)

    assert abe_kem.decap(pk, sk_old, ct, file_id) is None


def test_decap_rejects_malformed_ciphertext():
    pk, msk = abe_kem.setup()
    sk = abe_kem.keygen(pk, msk, ["DEPT_CSE_V1", "ROLE_FACULTY_V1"])
    file_id = uuid.uuid4().bytes

    assert abe_kem.decap(pk, sk, b"not a real ciphertext", file_id) is None


def test_serialize_roundtrip_for_pk_sk_and_ciphertext():
    pk, msk = abe_kem.setup()
    sk = abe_kem.keygen(pk, msk, ["DEPT_CSE_V1", "ROLE_FACULTY_V1"])
    file_id = uuid.uuid4().bytes
    key, ct = abe_kem.encap(pk, POLICY, file_id)

    pk2 = abe_kem.deserialize_pk(abe_kem.serialize_pk(pk))
    sk2 = abe_kem.deserialize_sk(abe_kem.serialize_sk(sk))

    recovered = abe_kem.decap(pk2, sk2, ct, file_id)
    assert recovered == key
