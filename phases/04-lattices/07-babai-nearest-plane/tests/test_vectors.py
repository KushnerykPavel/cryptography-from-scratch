import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import babai_after_lll, babai_nearest_plane, cvp_bruteforce


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


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")

