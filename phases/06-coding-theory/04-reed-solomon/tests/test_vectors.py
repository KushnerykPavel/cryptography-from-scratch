import json
import os
import sys


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as rs  # noqa: E402


def load_vectors():
    path = os.path.join(HERE, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def run_vector(v):
    op = v["op"]
    inputs = v.get("inputs", {})
    expected = v["expected"]

    if op == "gf_mul":
        got = rs.gf_mul(inputs["x"], inputs["y"])
        assert got == expected
        return

    if op == "gf_div":
        got = rs.gf_div(inputs["x"], inputs["y"])
        assert got == expected
        return

    if op == "poly_mul":
        got = rs.poly_mul(inputs["p"], inputs["q"])
        assert got == expected
        return

    if op == "rs_generator_poly":
        got = rs.rs_generator_poly(inputs["nsym"])
        assert got == expected
        return

    if op == "rs_encode_msg":
        got = rs.rs_encode_msg(inputs["msg"], inputs["nsym"])
        assert got == expected
        return

    if op == "rs_calc_syndromes":
        got = rs.rs_calc_syndromes(inputs["codeword"], inputs["nsym"])
        assert got == expected
        return

    if op == "rs_decode":
        msg, corrected, err_pos = rs.rs_decode(inputs["codeword"], inputs["nsym"])
        assert msg == expected["message"]
        assert corrected == expected["corrected"]
        assert err_pos == expected["err_pos"]
        return

    raise ValueError(f"unknown op: {op}")


def test_vectors():
    data = load_vectors()
    for v in data["vectors"]:
        run_vector(v)


def test_gf_mul_matches_no_lut_for_sample():
    for x in range(256):
        y = (x * 73 + 19) % 256
        assert rs.gf_mul(x, y) == rs.gf_mul_no_lut(x, y)


def test_gf_div_inverse_property_for_sample():
    for x in range(1, 256):
        y = (x * 91 + 7) % 255 + 1
        got = rs.gf_div(rs.gf_mul(x, y), y)
        assert got == x


def test_generator_poly_has_expected_roots():
    nsym = 8
    g = rs.rs_generator_poly(nsym)
    for i in range(nsym):
        assert rs.poly_eval(g, rs.gf_pow(rs.GENERATOR, i)) == 0


def test_encode_has_zero_syndromes_for_sample_messages():
    nsym = 8
    for n in range(1, 33):
        msg = [(n * 37 + i * 11) % 256 for i in range(n)]
        codeword = rs.rs_encode_msg(msg, nsym)
        synd = rs.rs_calc_syndromes(codeword, nsym)
        assert max(synd) == 0


def test_roundtrip_with_up_to_t_errors():
    nsym = 8
    t = nsym // 2
    msg = list(b"reed-solomon")
    codeword = rs.rs_encode_msg(msg, nsym)

    patterns = [
        [],
        [(0, 1)],
        [(1, 255), (4, 17)],
        [(1, 255), (4, 17), (7, 66)],
        [(1, 255), (4, 17), (7, 66), (len(codeword) - 2, 153)],
    ]
    for pat in patterns:
        assert len(pat) <= t
        received = codeword[:]
        for idx, val in pat:
            received[idx] ^= val
        decoded, corrected, _ = rs.rs_decode(received, nsym)
        assert decoded == msg
        assert corrected == codeword


def test_rejects_too_many_errors():
    nsym = 8
    msg = list(b"reed-solomon")
    codeword = rs.rs_encode_msg(msg, nsym)
    received = codeword[:]
    for idx, val in [(0, 1), (2, 2), (3, 3), (5, 4), (6, 5)]:
        received[idx] ^= val
    try:
        rs.rs_decode(received, nsym)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_rejects_non_bytes():
    try:
        rs.rs_encode_msg([256], 8)
        assert False, "expected ValueError"
    except ValueError:
        pass


if __name__ == "__main__":
    test_vectors()
    test_gf_mul_matches_no_lut_for_sample()
    test_gf_div_inverse_property_for_sample()
    test_generator_poly_has_expected_roots()
    test_encode_has_zero_syndromes_for_sample_messages()
    test_roundtrip_with_up_to_t_errors()
    test_rejects_too_many_errors()
    test_rejects_non_bytes()
    print("all tests pass")

