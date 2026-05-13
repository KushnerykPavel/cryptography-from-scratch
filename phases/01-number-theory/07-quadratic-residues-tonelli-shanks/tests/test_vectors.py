import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    all_square_roots_prime,
    find_quadratic_non_residue,
    is_quadratic_residue_prime,
    legendre_symbol,
    recover_factor_from_roots,
    sqrt_mod_prime_3mod4,
    sqrt_mod_semiprime_via_crt,
    tonelli_shanks,
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
            elif op == "is_quadratic_residue_prime":
                got = is_quadratic_residue_prime(v["a"], v["p"])
            elif op == "find_quadratic_non_residue":
                got = find_quadratic_non_residue(v["p"])
            elif op == "sqrt_mod_prime_3mod4":
                got = sqrt_mod_prime_3mod4(v["a"], v["p"])
            elif op == "tonelli_shanks":
                got = tonelli_shanks(v["a"], v["p"])
            elif op == "all_square_roots_prime":
                got = all_square_roots_prime(v["a"], v["p"])
            elif op == "sqrt_mod_semiprime_via_crt":
                got = sqrt_mod_semiprime_via_crt(v["a"], v["p"], v["q"])
            elif op == "recover_factor_from_roots":
                got = recover_factor_from_roots(v["n"], v["r"], v["s"])
            else:
                raise AssertionError(f"unknown op {op}")
        except ValueError as exc:
            assert v.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {v.get('expected_error')}"
            )
            continue

        expected = v["expected"]
        if isinstance(expected, list):
            expected = tuple(expected)
        assert got == expected, f"{op} failed: got {got}, expected {expected}"


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
