import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    all_error_patterns,
    build_syndrome_table,
    error_pattern,
    hamming74_parity_check_matrix,
    is_codeword,
    syndrome,
    syndrome_decode,
    syndrome_to_int,
)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    h = hamming74_parity_check_matrix()

    for v in data["vectors"]:
        op = v["op"]

        if op == "hamming74_parity_check_matrix":
            got = hamming74_parity_check_matrix()
        elif op == "syndrome":
            got = syndrome(v["received"], h)
        elif op == "syndrome_to_int":
            got = syndrome_to_int(v["syndrome"])
        elif op == "error_pattern":
            got = error_pattern(n=v["n"], ones_at=v["ones_at"])
        elif op == "build_syndrome_table_lookup":
            table = build_syndrome_table(h, max_weight=v["max_weight"])
            got = table[tuple(v["syndrome"])]
        elif op == "syndrome_decode_hamming74":
            table = build_syndrome_table(h, max_weight=v["max_weight"])
            corrected, e_hat, s = syndrome_decode(v["received"], h, table=table)
            got = {"corrected": corrected, "estimated_error": e_hat, "syndrome": s}
        else:
            raise AssertionError(f"unknown op: {op}")

        assert got == v["expected"], f"{op} failed: got {got}, expected {v['expected']}"


def test_table_single_bit_coverage():
    h = hamming74_parity_check_matrix()
    table = build_syndrome_table(h, max_weight=1)

    n = len(h[0])
    for i in range(n):
        e = error_pattern(n=n, ones_at=[i])
        s = syndrome(e, h)
        assert table[tuple(s)] == e


def test_decode_roundtrip_no_error():
    h = hamming74_parity_check_matrix()
    table = build_syndrome_table(h, max_weight=1)

    c = [0, 1, 1, 0, 0, 1, 1]
    corrected, e_hat, s = syndrome_decode(c, h, table=table)
    assert corrected == c
    assert e_hat == [0] * len(c)
    assert s == [0, 0, 0]


def test_miscorrection_demo_two_bit_error():
    h = hamming74_parity_check_matrix()
    table = build_syndrome_table(h, max_weight=1)

    c = [0, 1, 1, 0, 0, 1, 1]
    r = [0, 1, 1, 0, 1, 0, 1]  # c with flips at positions 5 and 6
    corrected, e_hat, s = syndrome_decode(r, h, table=table)

    assert s == syndrome(r, h)
    assert corrected != c
    assert is_codeword(corrected, h)
    assert e_hat == table[tuple(s)]


def test_all_error_patterns_count_and_order():
    pats = all_error_patterns(n=7, max_weight=2)
    assert len(pats) == 29
    assert pats[0] == [0, 0, 0, 0, 0, 0, 0]
    assert pats[1] == [1, 0, 0, 0, 0, 0, 0]
    assert pats[7] == [0, 0, 0, 0, 0, 0, 1]
    assert pats[8] == [1, 1, 0, 0, 0, 0, 0]


def test_input_validation():
    h = hamming74_parity_check_matrix()

    try:
        syndrome([0, 1], h)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for wrong received length")

    try:
        syndrome([0, 2, 0, 0, 0, 0, 0], h)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for non-binary received bit")

    try:
        error_pattern(n=7, ones_at=[4, 4])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for duplicate indices")

    try:
        error_pattern(n=7, ones_at=[7])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for out-of-range index")

    try:
        all_error_patterns(n=7, max_weight=8)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for max_weight > n")


if __name__ == "__main__":
    test_vectors()
    test_table_single_bit_coverage()
    test_decode_roundtrip_no_error()
    test_miscorrection_demo_two_bit_error()
    test_all_error_patterns_count_and_order()
    test_input_validation()
    print("all tests pass")

