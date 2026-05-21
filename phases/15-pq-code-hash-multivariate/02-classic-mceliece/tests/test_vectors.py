import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    apply_permutation,
    classic_mceliece_decrypt,
    classic_mceliece_encrypt,
    classic_mceliece_keygen_hamming74_with_secrets,
    gf2_identity,
    gf2_mat_mul,
    gf2_matrix_inv,
    hamming74_encode,
    hamming74_syndrome,
    hamming_weight,
    invert_permutation,
)


def _keypair(v):
    return classic_mceliece_keygen_hamming74_with_secrets(s=v["s"], perm=v["perm"])


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        if op == "gf2_matrix_inv":
            try:
                got = gf2_matrix_inv(v["a"])
            except ValueError as exc:
                assert v.get("expected_error") == str(exc), (
                    f"gf2_matrix_inv wrong error: got {exc!s}, expected {v.get('expected_error')}"
                )
                continue
        elif op == "invert_permutation":
            got = invert_permutation(v["perm"])
        elif op == "apply_permutation":
            got = apply_permutation(v["v"], v["perm"])
        elif op == "hamming74_encode":
            got = hamming74_encode(v["msg"])
        elif op == "hamming74_syndrome":
            got = hamming74_syndrome(v["word"])
        elif op == "classic_mceliece_encrypt":
            pub, _priv = _keypair(v)
            try:
                got = classic_mceliece_encrypt(pub, v["msg"], v["err"])
            except ValueError as exc:
                assert v.get("expected_error") == str(exc), (
                    f"classic_mceliece_encrypt wrong error: got {exc!s}, expected {v.get('expected_error')}"
                )
                continue
        elif op == "classic_mceliece_decrypt":
            _pub, priv = _keypair(v)
            got = classic_mceliece_decrypt(priv, v["ct"])
        else:
            raise AssertionError(f"unknown op {op}")

        assert "expected" in v, f"{op} missing expected result"
        assert got == v["expected"], f"{op} failed: got {got}, expected {v['expected']}"


def test_hamming74_is_a_code():
    for m in range(16):
        msg = [(m >> 3) & 1, (m >> 2) & 1, (m >> 1) & 1, m & 1]
        cw = hamming74_encode(msg)
        assert hamming74_syndrome(cw) == [0, 0, 0]


def test_gf2_inverse_identity():
    a = [[1, 0, 1, 1], [1, 1, 0, 1], [0, 1, 1, 1], [1, 0, 0, 1]]
    inv = gf2_matrix_inv(a)
    assert gf2_mat_mul(a, inv) == gf2_identity(4)
    assert gf2_mat_mul(inv, a) == gf2_identity(4)


def test_permutation_roundtrip():
    perm = [2, 4, 6, 0, 1, 3, 5]
    inv = invert_permutation(perm)
    v = [1, 0, 1, 0, 1, 1, 0]
    assert apply_permutation(apply_permutation(v, perm), inv) == v


def test_mceliece_roundtrip_single_error():
    s = [[1, 0, 0, 1], [1, 0, 1, 0], [0, 1, 0, 1], [1, 0, 1, 1]]
    perm = [2, 4, 6, 0, 1, 3, 5]
    pub, priv = classic_mceliece_keygen_hamming74_with_secrets(s=s, perm=perm)

    errors = [[0, 0, 0, 0, 0, 0, 0]]
    for i in range(pub.n):
        e = [0] * pub.n
        e[i] = 1
        errors.append(e)

    for m in range(16):
        msg = [(m >> 3) & 1, (m >> 2) & 1, (m >> 1) & 1, m & 1]
        for err in errors:
            ct = classic_mceliece_encrypt(pub, msg, err)
            got = classic_mceliece_decrypt(priv, ct)
            assert got == msg


def test_mceliece_fails_with_two_errors():
    s = [[1, 0, 0, 1], [1, 0, 1, 0], [0, 1, 0, 1], [1, 0, 1, 1]]
    perm = [2, 4, 6, 0, 1, 3, 5]
    pub, priv = classic_mceliece_keygen_hamming74_with_secrets(s=s, perm=perm)

    msg = [1, 1, 0, 1]
    ct = classic_mceliece_encrypt(pub, msg, [0, 0, 0, 0, 0, 0, 0])

    ct_bad = ct[:]
    ct_bad[0] ^= 1
    ct_bad[1] ^= 1
    got = classic_mceliece_decrypt(priv, ct_bad)
    assert got != msg

    try:
        classic_mceliece_encrypt(pub, msg, [1, 0, 0, 1, 0, 0, 0])
        raise AssertionError("expected ValueError for error weight > t")
    except ValueError as exc:
        assert str(exc) == "error weight exceeds decoder capability t"


if __name__ == "__main__":
    test_vectors()
    test_hamming74_is_a_code()
    test_gf2_inverse_identity()
    test_permutation_roundtrip()
    test_mceliece_roundtrip_single_error()
    test_mceliece_fails_with_two_errors()
    print("all tests pass")

