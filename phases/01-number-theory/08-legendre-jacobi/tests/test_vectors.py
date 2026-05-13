import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    find_pseudosquares,
    is_quadratic_residue_bruteforce,
    jacobi_symbol,
    jacobi_symbol_by_factorization,
    legendre_symbol,
    solovay_strassen_primality_test,
    solovay_strassen_witness,
)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "legendre_symbol":
                got = legendre_symbol(v["a"], v["p"])
            elif op == "jacobi_symbol":
                got = jacobi_symbol(v["a"], v["n"])
            elif op == "jacobi_symbol_by_factorization":
                got = jacobi_symbol_by_factorization(v["a"], v["n"])
            elif op == "is_quadratic_residue_bruteforce":
                got = is_quadratic_residue_bruteforce(v["a"], v["n"])
            elif op == "find_pseudosquares":
                got = find_pseudosquares(v["n"])
            elif op == "solovay_strassen_witness":
                got = solovay_strassen_witness(v["a"], v["n"])
            elif op == "solovay_strassen_primality_test":
                got = solovay_strassen_primality_test(v["n"], v["bases"])
            else:
                raise AssertionError(f"unknown op {op}")
        except ValueError as exc:
            assert v.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {v.get('expected_error')}"
            )
            continue

        expected = v["expected"]
        assert got == expected, f"{op} failed: got {got}, expected {expected}"


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
