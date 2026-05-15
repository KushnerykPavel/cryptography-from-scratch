import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    cyclotomic_poly,
    cyclotomic_poly_z,
    cyclotomic_roots,
    divisors,
    euler_phi,
    find_primitive_nth_root,
    is_primitive_nth_root,
    multiplicative_order,
    nth_roots_of_unity,
    primitive_nth_roots,
    primitive_root,
)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "divisors":
                got = divisors(v["n"])
            elif op == "euler_phi":
                got = euler_phi(v["n"])
            elif op == "multiplicative_order":
                got = multiplicative_order(v["a"], v["p"])
            elif op == "is_primitive_nth_root":
                got = is_primitive_nth_root(v["a"], v["n"], v["p"])
            elif op == "nth_roots_of_unity":
                got = nth_roots_of_unity(v["n"], v["p"])
            elif op == "primitive_nth_roots":
                got = primitive_nth_roots(v["n"], v["p"])
            elif op == "primitive_root":
                got = primitive_root(v["p"])
            elif op == "find_primitive_nth_root":
                got = find_primitive_nth_root(v["n"], v["p"])
            elif op == "cyclotomic_poly_z":
                got = cyclotomic_poly_z(v["n"])
            elif op == "cyclotomic_poly":
                got = cyclotomic_poly(v["n"], v["p"])
            elif op == "cyclotomic_roots":
                got = cyclotomic_roots(v["n"], v["p"])
            else:
                raise AssertionError(f"unknown op {op}")
        except ValueError as exc:
            assert v.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {v.get('expected_error')}"
            )
            continue

        assert got == v["expected"], (
            f"{op} failed: got {got}, expected {v['expected']}"
        )


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
