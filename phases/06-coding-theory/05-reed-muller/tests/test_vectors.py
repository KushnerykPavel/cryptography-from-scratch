import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    fwht_inplace,
    hamming_distance,
    rm_encode,
    rm_generator_matrix,
    rm_monomials_upto_degree,
    rm_parameters,
    rm1_correct,
    rm1_decode_coeffs,
    rm1_encode_from_coeffs,
    xor_bits,
)


def _all_bits(length: int) -> list[list[int]]:
    out: list[list[int]] = []
    for x in range(1 << length):
        out.append([(x >> i) & 1 for i in range(length)])
    return out


def _flip_bit(v: list[int], *, index: int) -> list[int]:
    out = v[:]
    out[index] ^= 1
    return out


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        if op == "rm_parameters":
            n, k, d = rm_parameters(v["r"], v["m"])
            got = {"n": n, "k": k, "d": d}
        elif op == "rm_monomials_upto_degree":
            got = [list(t) for t in rm_monomials_upto_degree(v["r"], v["m"])]
        elif op == "rm_generator_matrix":
            got = rm_generator_matrix(v["r"], v["m"])
        elif op == "rm_encode":
            got = rm_encode(v["message"], v["r"], v["m"])
        elif op == "rm1_decode_coeffs":
            got = rm1_decode_coeffs(v["received"], m=v["m"])
        elif op == "rm1_correct":
            decoded, corrected = rm1_correct(v["received"], m=v["m"])
            got = {"decoded": decoded, "corrected": corrected}
        elif op == "hamming_distance":
            got = hamming_distance(v["a"], v["b"])
        elif op == "fwht_inplace":
            a = v["a"][:]
            fwht_inplace(a)
            got = a
        else:
            raise AssertionError(f"unknown op: {op}")

        assert got == v["expected"], f"{op} failed: got {got}, expected {v['expected']}"


def test_rm1_encode_matches_generator_matrix_exhaustive():
    m = 3
    r = 1
    n, k, _ = rm_parameters(r, m)
    assert n == 1 << m
    assert k == m + 1

    for msg in _all_bits(k):
        cw_g = rm_encode(msg, r, m)
        cw_affine = rm1_encode_from_coeffs(msg, m=m)
        assert cw_g == cw_affine


def test_rm1_decode_roundtrip_exhaustive():
    m = 3
    k = m + 1
    for msg in _all_bits(k):
        cw = rm1_encode_from_coeffs(msg, m=m)
        got = rm1_decode_coeffs(cw, m=m)
        assert got == msg


def test_rm1_single_bit_correction_exhaustive():
    m = 3
    n = 1 << m
    k = m + 1
    for msg in _all_bits(k):
        cw = rm1_encode_from_coeffs(msg, m=m)
        for i in range(n):
            received = _flip_bit(cw, index=i)
            dec, corrected = rm1_correct(received, m=m)
            assert dec == msg
            assert corrected == cw


def test_linearity_rm23():
    r, m = 2, 3
    _, k, _ = rm_parameters(r, m)
    a = [1, 0, 1, 1, 1, 0, 1]
    b = [0, 1, 0, 1, 1, 1, 0]
    assert len(a) == k
    assert len(b) == k

    cw_a = rm_encode(a, r, m)
    cw_b = rm_encode(b, r, m)
    cw_ab = rm_encode(xor_bits(a, b), r, m)
    assert cw_ab == xor_bits(cw_a, cw_b)


def test_input_validation():
    try:
        rm_parameters(2, 1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for r > m")

    try:
        rm_encode([0, 1], 1, 3)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for wrong message length")

    try:
        rm_encode([0, 1, 2, 0], 1, 3)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for non-binary message bit")

    try:
        rm1_decode_coeffs([0, 1, 0], m=3)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for wrong received length")

    try:
        fwht_inplace([1, 2, 3])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for non power-of-two length")


if __name__ == "__main__":
    test_vectors()
    test_rm1_encode_matches_generator_matrix_exhaustive()
    test_rm1_decode_roundtrip_exhaustive()
    test_rm1_single_bit_correction_exhaustive()
    test_linearity_rm23()
    test_input_validation()
    print("all tests pass")

