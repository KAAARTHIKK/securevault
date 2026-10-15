"""Phase 0 smoke test: BSW07 CP-ABE on pairing group SS512.

Encrypts a random GT element under a policy, then decrypts it with a key
whose attributes satisfy the policy and with one that does not. Must run
inside the abe-runtime container/venv (requires charm-crypto).
"""
from charm.toolbox.pairinggroup import GT, PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07


def main():
    group = PairingGroup("SS512")
    cpabe = CPabe_BSW07(group)

    pk, msk = cpabe.setup()

    good_attrs = ["DEPT_CSE_V1", "ROLE_FACULTY_V1"]
    bad_attrs = ["DEPT_ECE_V1", "ROLE_STUDENT_V1"]

    sk_good = cpabe.keygen(pk, msk, good_attrs)
    sk_bad = cpabe.keygen(pk, msk, bad_attrs)

    policy = "(DEPT_CSE_V1 and ROLE_FACULTY_V1)"
    message = group.random(GT)

    ciphertext = cpabe.encrypt(pk, message, policy)

    decrypted_good = cpabe.decrypt(pk, sk_good, ciphertext)
    print("Matching attributes:    ", "OK" if decrypted_good == message else "DENIED")

    try:
        decrypted_bad = cpabe.decrypt(pk, sk_bad, ciphertext)
    except Exception:
        decrypted_bad = False
    print("Non-matching attributes:", "DENIED" if decrypted_bad in (False, None) else "OK (unexpected!)")


if __name__ == "__main__":
    main()
