import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import candidate_count, cvp_bruteforce, lattice_vector, svp_bruteforce


def _basis(v):
    return tuple(tuple(x) for x in v)


def _vec(v):
    return tuple(int(x) for x in v)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "candidate_count":
                got = candidate_count(v["coeff_bound"], v["n"])
            elif op == "lattice_vector":
                got = list(lattice_vector(_basis(v["basis"]), _vec(v["z"])))
            elif op == "svp_bruteforce":
                res = svp_bruteforce(_basis(v["basis"]), v["coeff_bound"])
                got = {
                    "coeffs": list(res.coeffs),
                    "vector": list(res.vector),
                    "norm2": res.norm2,
                }
            elif op == "cvp_bruteforce":
                res = cvp_bruteforce(_basis(v["basis"]), _vec(v["target"]), v["coeff_bound"])
                got = {
                    "coeffs": list(res.coeffs),
                    "vector": list(res.vector),
                    "dist2": res.dist2,
                }
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

