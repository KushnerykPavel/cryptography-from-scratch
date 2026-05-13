import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    aks_congruence_holds,
    aks_order_threshold,
    aks_primality_test,
    aks_target_polynomial,
    aks_witness_limit,
    certificate_route,
    euler_totient,
    find_smallest_r,
    integer_nth_root,
    is_perfect_power,
    multiplicative_order_mod,
    poly_mul_mod,
    poly_pow_mod,
    smallest_factor_up_to,
)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for vector in data["vectors"]:
        op = vector["op"]

        try:
            if op == "integer_nth_root":
                got = integer_nth_root(vector["value"], vector["degree"])
            elif op == "is_perfect_power":
                got = is_perfect_power(vector["n"])
            elif op == "euler_totient":
                got = euler_totient(vector["n"])
            elif op == "multiplicative_order_mod":
                got = multiplicative_order_mod(vector["n"], vector["r"])
            elif op == "aks_order_threshold":
                got = aks_order_threshold(vector["n"])
            elif op == "find_smallest_r":
                got = find_smallest_r(vector["n"])
            elif op == "smallest_factor_up_to":
                got = smallest_factor_up_to(vector["n"], vector["limit"])
            elif op == "poly_mul_mod":
                got = poly_mul_mod(vector["left"], vector["right"], vector["modulus"], vector["r"])
            elif op == "poly_pow_mod":
                got = poly_pow_mod(vector["base"], vector["exponent"], vector["modulus"], vector["r"])
            elif op == "aks_target_polynomial":
                got = aks_target_polynomial(vector["n"], vector["r"], vector["a"])
            elif op == "aks_congruence_holds":
                got = aks_congruence_holds(vector["n"], vector["r"], vector["a"])
            elif op == "aks_witness_limit":
                got = aks_witness_limit(vector["n"], vector["r"])
            elif op == "aks_primality_test":
                got = aks_primality_test(vector["n"])
            elif op == "certificate_route":
                got = certificate_route(vector["n"])
            else:
                raise AssertionError(f"unknown op {op}")
        except ValueError as exc:
            assert vector.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {vector.get('expected_error')}"
            )
            continue

        assert got == vector["expected"], f"{op} failed: got {got}, expected {vector['expected']}"


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
