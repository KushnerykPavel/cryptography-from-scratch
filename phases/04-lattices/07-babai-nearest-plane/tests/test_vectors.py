import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    babai_after_lll,
    babai_nearest_plane,
    columns_to_rows,
    cvp_bruteforce,
    det_int_square,
    iter_coeffs,
    lattice_vector,
    norm2,
    vec_sub,
)


def _basis(v):
    return tuple(tuple(b) for b in v)


def _vec(v):
    return tuple(v)


def _babai_to_json(res):
    return {
        "coeffs": list(res.coeffs),
        "vector": list(res.vector),
        "residual": [int(x) for x in res.residual],
        "dist2": int(res.dist2),
    }


def _cvp_to_json(res):
    return {"coeffs": list(res.coeffs), "vector": list(res.vector), "dist2": res.dist2}


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "babai_nearest_plane":
                got = _babai_to_json(babai_nearest_plane(_basis(v["basis"]), _vec(v["target"])))
            elif op == "babai_after_lll":
                reduced_basis, res = babai_after_lll(_basis(v["basis"]), _vec(v["target"]))
                got = {"reduced_basis": [list(col) for col in reduced_basis], "result": _babai_to_json(res)}
            elif op == "babai_vs_cvp":
                B = _basis(v["basis"])
                t = _vec(v["target"])
                bb = babai_nearest_plane(B, t)
                cvp = cvp_bruteforce(B, t, coeff_bound=v["coeff_bound"])
                got = {"babai": {"coeffs": list(bb.coeffs), "vector": list(bb.vector), "dist2": int(bb.dist2)}, "cvp": _cvp_to_json(cvp)}
            else:
                raise AssertionError(f"unknown op {op}")
        except ValueError as exc:
            assert v.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {v.get('expected_error')}"
            )
            continue

        assert got == v["expected"], f"{op} failed: got {got}, expected {v['expected']}"


def test_babai_outputs_lattice_vector_roundtrip():
    B = ((4, 1), (1, 3))
    t = (2, 5)
    res = babai_nearest_plane(B, t)
    assert lattice_vector(B, res.coeffs) == res.vector
    assert int(res.dist2) == norm2(vec_sub(res.vector, t))


def test_babai_identity_basis_is_exact_on_integer_targets():
    B = ((1, 0, 0), (0, 1, 0), (0, 0, 1))
    for t in [(0, 0, 0), (3, -2, 5), (-7, 1, 0)]:
        res = babai_nearest_plane(B, t)
        assert res.vector == t
        assert res.coeffs == t
        assert int(res.dist2) == 0


def test_iter_coeffs_count():
    assert sum(1 for _ in iter_coeffs(1, 0)) == 1
    assert sum(1 for _ in iter_coeffs(2, 1)) == 9
    assert sum(1 for _ in iter_coeffs(3, 2)) == 125


def test_cvp_bruteforce_monotone_in_bound():
    B = ((7, 1), (1, 1))
    t = (6, 2)
    best1 = cvp_bruteforce(B, t, coeff_bound=2)
    best2 = cvp_bruteforce(B, t, coeff_bound=3)
    assert best2.dist2 <= best1.dist2


def test_lll_preserves_determinant_magnitude():
    B = ((1, 5), (6, 21))
    det0 = abs(det_int_square(columns_to_rows(B)))
    Bred, _ = babai_after_lll(B, (10, 10))
    det1 = abs(det_int_square(columns_to_rows(Bred)))
    assert det0 == det1


def test_rejects_bad_inputs():
    try:
        babai_nearest_plane((), (1, 2))
    except ValueError as exc:
        assert str(exc) == "basis must be non-empty"
    else:
        raise AssertionError("expected ValueError")

    try:
        babai_nearest_plane(((1, 0), (0, 0)), (1, 2))
    except ValueError as exc:
        assert str(exc) == "basis must be full rank (det != 0)"
    else:
        raise AssertionError("expected ValueError")


if __name__ == "__main__":
    test_vectors()
    test_babai_outputs_lattice_vector_roundtrip()
    test_babai_identity_basis_is_exact_on_integer_targets()
    test_iter_coeffs_count()
    test_cvp_bruteforce_monotone_in_bound()
    test_lll_preserves_determinant_magnitude()
    test_rejects_bad_inputs()
    print("all tests pass")
