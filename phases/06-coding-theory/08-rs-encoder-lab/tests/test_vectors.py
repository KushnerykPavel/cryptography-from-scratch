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

    if op == "gf_pow":
        got = rs.gf_pow(inputs["x"], inputs["power"])
        assert got == expected
        return

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
        got = rs.rs_generator_poly(inputs["nsym"], first_root=inputs.get("first_root", 0))
        assert got == expected
        return

    if op == "rs_encode_msg":
        got = rs.rs_encode_msg(inputs["msg"], inputs["nsym"], first_root=inputs.get("first_root", 0))
        assert got == expected
        return

    if op == "rs_calc_syndromes":
        got = rs.rs_calc_syndromes(
            inputs["codeword"], inputs["nsym"], first_root=inputs.get("first_root", 0)
        )
        assert got == expected
        return

    if op == "gsm_edge_rs85w73_encode":
        got = rs.gsm_edge_rs85w73_encode(inputs["data73"])
        assert got == expected
        return

    if op == "gsm_edge_rs85w73_syndromes":
        got = rs.gsm_edge_rs85w73_syndromes(inputs["code85"])
        assert got == expected
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


def test_gsm_edge_generator_poly_matches_spec_and_roots():
    g = rs.rs_generator_poly(rs.GSM_EDGE_RS255W243_NSYM, first_root=rs.GSM_EDGE_RS255W243_FIRST_ROOT)
    assert g == rs.GSM_EDGE_RS255W243_GENERATOR_POLY_12
    assert g == list(reversed(g)), "GSM/EDGE generator polynomial should be self-reciprocal"
    for i in range(rs.GSM_EDGE_RS255W243_NSYM):
        root = rs.gf_pow(rs.GENERATOR, rs.GSM_EDGE_RS255W243_FIRST_ROOT + i)
        assert rs.poly_eval(g, root) == 0


def test_encode_has_zero_syndromes_for_sample_messages():
    nsym = 12
    first_root = rs.GSM_EDGE_RS255W243_FIRST_ROOT
    for n in range(1, 33):
        msg = [(n * 37 + i * 11) % 256 for i in range(n)]
        codeword = rs.rs_encode_msg(msg, nsym, first_root=first_root)
        synd = rs.rs_calc_syndromes(codeword, nsym, first_root=first_root)
        assert max(synd) == 0


def test_shortened_rs85w73_is_systematic_and_valid():
    for seed in range(1, 6):
        data73 = [(seed * 29 + i * 17) % 256 for i in range(rs.GSM_EDGE_RS85W73_K)]
        code85 = rs.gsm_edge_rs85w73_encode(data73)
        assert len(code85) == rs.GSM_EDGE_RS85W73_N
        assert code85[: rs.GSM_EDGE_RS85W73_K] == data73
        synd = rs.gsm_edge_rs85w73_syndromes(code85)
        assert max(synd) == 0


def test_syndromes_detect_corruption():
    data73 = [(7 * 29 + i * 17) % 256 for i in range(rs.GSM_EDGE_RS85W73_K)]
    code85 = rs.gsm_edge_rs85w73_encode(data73)

    corrupted = code85[:]
    corrupted[0] ^= 0x01
    corrupted[17] ^= 0xFF
    synd = rs.gsm_edge_rs85w73_syndromes(corrupted)
    assert max(synd) != 0


def test_rejects_non_bytes():
    try:
        rs.gsm_edge_rs85w73_encode([256] * rs.GSM_EDGE_RS85W73_K)
        assert False, "expected ValueError"
    except ValueError:
        pass


if __name__ == "__main__":
    test_vectors()
    test_gf_mul_matches_no_lut_for_sample()
    test_gf_div_inverse_property_for_sample()
    test_gsm_edge_generator_poly_matches_spec_and_roots()
    test_encode_has_zero_syndromes_for_sample_messages()
    test_shortened_rs85w73_is_systematic_and_valid()
    test_syndromes_detect_corruption()
    test_rejects_non_bytes()
    print("all tests pass")

