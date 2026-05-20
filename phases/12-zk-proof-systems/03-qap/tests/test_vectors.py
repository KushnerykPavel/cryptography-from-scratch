import json
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
CODE_DIR = HERE.parent / "code"
sys.path.insert(0, str(CODE_DIR))

import main as qap  # noqa: E402


def _load_vectors():
    with (HERE / "vectors.json").open("r", encoding="utf-8") as f:
        return json.load(f)


def _run_vector(vec):
    op = vec["op"]
    p = vec["p"]

    if op == "field_inv":
        got = qap.field_inv(vec["a"], p)
        assert got == vec["expected"]
        return

    if op == "poly_mul":
        got = qap.poly_mul(vec["a"], vec["b"], p)
        assert got == vec["expected"]
        return

    if op == "lagrange_interpolate":
        got = qap.lagrange_interpolate(vec["xs"], vec["ys"], p)
        assert got == vec["expected"]
        return

    if op == "target_polynomial":
        got = qap.target_polynomial(vec["xs"], p)
        assert got == vec["expected"]
        return

    if op == "r1cs_to_qap":
        A_polys, B_polys, C_polys, t = qap.r1cs_to_qap(vec["A"], vec["B"], vec["C"], vec["xs"], p)
        exp = vec["expected"]
        assert A_polys == exp["A_polys"]
        assert B_polys == exp["B_polys"]
        assert C_polys == exp["C_polys"]
        assert t == exp["t"]
        return

    if op == "qap_p_poly":
        got = qap.qap_p_poly(vec["A_polys"], vec["B_polys"], vec["C_polys"], vec["witness"], p)
        assert got == vec["expected"]
        return

    if op == "poly_divmod":
        q, r = qap.poly_divmod(vec["numer"], vec["denom"], p)
        assert q == vec["expected"]["q"]
        assert r == vec["expected"]["r"]
        return

    raise ValueError(f"unknown op: {op}")


def test_vectors():
    data = _load_vectors()
    assert "vectors" in data
    for i, vec in enumerate(data["vectors"]):
        try:
            _run_vector(vec)
        except Exception as e:
            raise AssertionError(f"vector #{i} failed (op={vec.get('op')}): {e}") from e


def test_lagrange_roundtrip_points():
    p = 101
    xs = [1, 2, 5]
    ys = [7, 11, 42]
    poly = qap.lagrange_interpolate(xs, ys, p)
    for x, y in zip(xs, ys):
        assert qap.poly_eval(poly, x, p) == y % p


def test_qap_divisibility_valid_and_invalid_witness():
    p = 101
    xs = [1, 2]

    A, B, C = qap.example_r1cs_for_z_eq_x_mul_y_plus_x()
    A_polys, B_polys, C_polys, t = qap.r1cs_to_qap(A, B, C, xs, p)

    witness_good = [1, 3, 4, 12, 15]
    P_good = qap.qap_p_poly(A_polys, B_polys, C_polys, witness_good, p)
    _, r_good = qap.poly_divmod(P_good, t, p)
    assert r_good == [0]

    witness_bad = [1, 3, 4, 12, 16]
    P_bad = qap.qap_p_poly(A_polys, B_polys, C_polys, witness_bad, p)
    _, r_bad = qap.poly_divmod(P_bad, t, p)
    assert r_bad != [0]


def test_error_rejection():
    p = 101

    try:
        qap.field_inv(0, p)
        assert False, "expected ZeroDivisionError"
    except ZeroDivisionError:
        pass

    try:
        qap.poly_divmod([1], [0], p)
        assert False, "expected ZeroDivisionError"
    except ZeroDivisionError:
        pass

    try:
        qap.lagrange_interpolate([1, 1], [0, 1], p)
        assert False, "expected ValueError"
    except ValueError:
        pass


def _run_all_tests():
    test_vectors()
    test_lagrange_roundtrip_points()
    test_qap_divisibility_valid_and_invalid_witness()
    test_error_rejection()


if __name__ == "__main__":
    _run_all_tests()
    print("all tests pass")

