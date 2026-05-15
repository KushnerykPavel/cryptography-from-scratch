import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import bkz_reduce, det_int_square, columns_to_rows, svp_bruteforce_fixed_last


def _basis(v):
    return tuple(tuple(b) for b in v)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "bkz_reduce":
                beta = v["beta"]
                tours = v.get("tours", 3)
                coeff_bound = v.get("coeff_bound", 6)
                got = bkz_reduce(_basis(v["basis"]), beta=beta, tours=tours, coeff_bound=coeff_bound)
                got = [list(col) for col in got]
            elif op == "svp_bruteforce_fixed_last":
                res = svp_bruteforce_fixed_last(_basis(v["block_basis"]), v["coeff_bound"], last=v.get("last", 1))
                got = {"coeffs": list(res.coeffs), "vector": list(res.vector), "norm2": res.norm2}
            elif op == "det_abs":
                det = det_int_square(columns_to_rows(_basis(v["basis"])))
                got = abs(det)
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

