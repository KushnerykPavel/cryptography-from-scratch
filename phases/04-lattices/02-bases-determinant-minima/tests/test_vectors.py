import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    change_basis_unimodular,
    det_int_square,
    is_unimodular,
    lattice_determinant,
    successive_minima_sqnorm_bruteforce_2d,
)


def _basis(v):
    return tuple(tuple(x) for x in v)


def _mat(v):
    return tuple(tuple(x) for x in v)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "det_int_square":
                got = det_int_square([list(row) for row in v["A"]])
            elif op == "lattice_determinant":
                got = lattice_determinant(_basis(v["basis"]))
            elif op == "is_unimodular":
                got = is_unimodular(_mat(v["U"]))
            elif op == "change_basis_unimodular":
                got = change_basis_unimodular(_basis(v["basis"]), _mat(v["U"]))
                got = [list(got[0]), list(got[1])]
            elif op == "successive_minima_sqnorm_bruteforce_2d":
                got = list(successive_minima_sqnorm_bruteforce_2d(_basis(v["basis"]), v["coeff_bound"]))
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

