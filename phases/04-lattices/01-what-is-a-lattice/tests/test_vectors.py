import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    change_basis_unimodular_2d,
    det_2d,
    det_mat2,
    lattice_points_in_box_2d,
    shortest_vector_bruteforce_2d,
)


def _basis(v):
    b1, b2 = v
    return (tuple(b1), tuple(b2))


def _mat2(v):
    r1, r2 = v
    return (tuple(r1), tuple(r2))


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "det_2d":
                got = det_2d(_basis(v["basis"]))
            elif op == "det_mat2":
                got = det_mat2(_mat2(v["U"]))
            elif op == "change_basis_unimodular_2d":
                got = change_basis_unimodular_2d(_basis(v["basis"]), _mat2(v["U"]))
                got = [list(got[0]), list(got[1])]
            elif op == "lattice_points_in_box_2d":
                got = lattice_points_in_box_2d(
                    _basis(v["basis"]),
                    v["coeff_bound"],
                    v["x_min"],
                    v["x_max"],
                    v["y_min"],
                    v["y_max"],
                )
                got = [list(p) for p in got]
            elif op == "shortest_vector_bruteforce_2d":
                got = shortest_vector_bruteforce_2d(_basis(v["basis"]), v["coeff_bound"])
                got_norm2 = got[0] * got[0] + got[1] * got[1]
                expected_norm2 = v.get("expected_norm2")
                if expected_norm2 is None:
                    raise AssertionError("missing expected_norm2 for shortest_vector_bruteforce_2d")
                assert got_norm2 == expected_norm2, (
                    f"{op} wrong norm^2: got {got_norm2}, expected {expected_norm2}"
                )
                continue
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

