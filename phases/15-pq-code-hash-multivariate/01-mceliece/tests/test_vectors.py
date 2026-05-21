import json
import os
import sys


THIS_DIR = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as mceliece  # noqa: E402


def _load_vectors():
    path = os.path.join(THIS_DIR, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_vectors():
    data = _load_vectors()
    vectors = data["vectors"]

    for v in vectors:
        op = v["op"]
        inputs = v["inputs"]
        expected = v["expected"]

        if op == "invert_matrix_mod2":
            got = mceliece.invert_matrix_mod2(inputs["a"])
            assert got == expected
        elif op == "hamming74_encode":
            got = mceliece.hamming74_encode(inputs["message_4"])
            assert got == expected
        elif op == "hamming74_syndrome":
            got = mceliece.hamming74_syndrome(inputs["received_7"])
            assert got == expected
        elif op == "hamming74_decode_1error":
            msg, corrected, flipped = mceliece.hamming74_decode_1error(inputs["received_7"])
            assert msg == expected["message_4"]
            assert corrected == expected["corrected_7"]
            assert flipped == expected["flipped_index"]
        elif op == "mceliece_encrypt_toy":
            got = mceliece.mceliece_encrypt_toy(
                inputs["public_key"],
                inputs["message_4"],
                error_7=inputs["error_7"],
            )
            assert got == expected
        elif op == "mceliece_decrypt_toy":
            got = mceliece.mceliece_decrypt_toy(inputs["secret_key"], inputs["ciphertext_7"])
            assert got == expected
        else:
            raise AssertionError(f"unknown op: {op}")


def test_permutation_roundtrip():
    v = [1, 0, 1, 1, 0, 0, 1]
    perm = [3, 0, 1, 2, 6, 5, 4]
    inv = mceliece.invert_permutation(perm)
    assert mceliece.apply_permutation(mceliece.apply_permutation(v, perm), inv) == v


def test_g_times_h_transpose_is_zero():
    g, h = mceliece.hamming74_matrices()
    h_t = [list(col) for col in zip(*h)]
    got = mceliece.mul_mat_mat_mod2(g, h_t)
    assert got == [[0, 0, 0] for _ in range(4)]


def test_hamming74_roundtrip_for_all_messages_and_single_bit_errors():
    g, _ = mceliece.hamming74_matrices()
    for x in range(16):
        msg = [(x >> (3 - i)) & 1 for i in range(4)]
        codeword = mceliece.mul_vec_mat_mod2(msg, g)
        msg2, corrected, flipped = mceliece.hamming74_decode_1error(codeword)
        assert msg2 == msg
        assert corrected == codeword
        assert flipped is None

        for bit in range(7):
            received = codeword[:]
            received[bit] ^= 1
            msg3, corrected3, _flipped3 = mceliece.hamming74_decode_1error(received)
            assert msg3 == msg
            assert corrected3 == codeword


def test_hamming74_miscorrects_on_two_bit_errors():
    msg = [1, 0, 1, 1]
    codeword = mceliece.hamming74_encode(msg)
    received = codeword[:]
    received[0] ^= 1
    received[1] ^= 1
    msg2, _corrected2, _flipped2 = mceliece.hamming74_decode_1error(received)
    assert msg2 != msg


def test_mceliece_encrypt_decrypt_roundtrip():
    import random

    rng = random.Random(2026)
    pk, sk = mceliece.mceliece_keygen_toy(rng)
    for x in range(16):
        msg = [(x >> (3 - i)) & 1 for i in range(4)]
        ct = mceliece.mceliece_encrypt_toy(pk, msg, rng=rng)
        got = mceliece.mceliece_decrypt_toy(sk, ct)
        assert got == msg


def test_mceliece_encrypt_rejects_error_weight_above_t():
    import random

    rng = random.Random(0)
    pk, _sk = mceliece.mceliece_keygen_toy(rng)
    try:
        mceliece.mceliece_encrypt_toy(pk, [0, 0, 0, 0], error_7=[1, 1, 0, 0, 0, 0, 0])
        assert False, "expected ValueError"
    except ValueError:
        pass


if __name__ == "__main__":
    try:
        import pytest  # type: ignore

        rc = pytest.main([__file__])
        if rc != 0:
            raise SystemExit(rc)
    except ImportError:
        test_vectors()
        test_permutation_roundtrip()
        test_g_times_h_transpose_is_zero()
        test_hamming74_roundtrip_for_all_messages_and_single_bit_errors()
        test_hamming74_miscorrects_on_two_bit_errors()
        test_mceliece_encrypt_decrypt_roundtrip()
        test_mceliece_encrypt_rejects_error_weight_above_t()

    print("all tests pass")
