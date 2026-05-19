import json
import os
import sys


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as lc  # noqa: E402


def load_vectors():
    path = os.path.join(HERE, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def run_vector(v):
    op = v["op"]
    inputs = v.get("inputs", {})
    expected = v["expected"]

    if op == "hamming_weight":
        got = lc.hamming_weight(inputs["v"])
        assert got == expected
        return

    if op == "hamming_distance":
        got = lc.hamming_distance(inputs["a"], inputs["b"])
        assert got == expected
        return

    if op == "mul_vec_mat_mod2":
        got = lc.mul_vec_mat_mod2(inputs["v"], inputs["m"])
        assert got == expected
        return

    if op == "parity_check_matrix_from_systematic_g":
        got = lc.parity_check_matrix_from_systematic_g(inputs["g"])
        assert got == expected
        return

    if op == "syndrome":
        got = lc.syndrome(inputs["received"], inputs["h"])
        assert got == expected
        return

    if op == "correct_single_bit_error":
        corrected, flipped = lc.correct_single_bit_error(inputs["received"], inputs["h"])
        assert corrected == expected["corrected"]
        assert flipped == expected["flipped"]
        return

    if op == "decode_hamming74":
        message, corrected, flipped = lc.decode_hamming74(inputs["received"])
        assert message == expected["message"]
        assert corrected == expected["corrected"]
        assert flipped == expected["flipped"]
        return

    raise ValueError(f"unknown op: {op}")


def test_vectors():
    data = load_vectors()
    for v in data["vectors"]:
        run_vector(v)


def test_hamming74_all_codewords_have_zero_syndrome():
    g, h = lc.hamming74_matrices()
    for msg in lc.all_binary_vectors(4):
        c = lc.encode(msg, g)
        assert lc.is_codeword(c, h)


def test_hamming74_roundtrip_with_single_bit_error():
    g, _ = lc.hamming74_matrices()
    for msg in lc.all_binary_vectors(4):
        c = lc.encode(msg, g)
        for flip in [None] + list(range(7)):
            r = c[:]
            if flip is not None:
                r[flip] ^= 1
            msg2, corrected, _ = lc.decode_hamming74(r)
            assert msg2 == msg
            assert corrected == c


def test_rejects_non_binary_inputs():
    try:
        lc.hamming_weight([2])
        assert False, "expected ValueError"
    except ValueError:
        pass

    try:
        lc.mul_vec_mat_mod2([1, 0], [[1, 0], [0, 2]])
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_parity_check_requires_systematic_generator():
    g, _ = lc.hamming74_matrices()
    bad_g = [row[:] for row in g]
    bad_g[0][0] = 0
    try:
        lc.parity_check_matrix_from_systematic_g(bad_g)
        assert False, "expected ValueError"
    except ValueError:
        pass


if __name__ == "__main__":
    test_vectors()
    test_hamming74_all_codewords_have_zero_syndrome()
    test_hamming74_roundtrip_with_single_bit_error()
    test_rejects_non_binary_inputs()
    test_parity_check_requires_systematic_generator()
    print("all tests pass")

