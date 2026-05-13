import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    carmichael_lambda,
    carmichael_prime_power,
    euler_totient,
    factor_semiprime_from_phi,
    is_carmichael_korselt,
    prime_factorization,
    reduce_exponent_lambda,
    rsa_private_exponent,
)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "prime_factorization":
                got = prime_factorization(v["n"])
            elif op == "euler_totient":
                got = euler_totient(v["n"])
            elif op == "carmichael_prime_power":
                got = carmichael_prime_power(v["p"], v["exponent"])
            elif op == "carmichael_lambda":
                got = carmichael_lambda(v["n"])
            elif op == "reduce_exponent_lambda":
                got = reduce_exponent_lambda(v["base"], v["exp"], v["n"])
            elif op == "rsa_private_exponent":
                got = rsa_private_exponent(v["e"], v["p"], v["q"])
            elif op == "factor_semiprime_from_phi":
                got = factor_semiprime_from_phi(v["n"], v["phi_n"])
            elif op == "is_carmichael_korselt":
                got = is_carmichael_korselt(v["n"])
            else:
                raise AssertionError(f"unknown op {op}")
        except ValueError as exc:
            assert v.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {v.get('expected_error')}"
            )
            continue

        expected = v["expected"]
        if isinstance(expected, list):
            if op == "prime_factorization":
                expected = [tuple(item) for item in expected]
            else:
                expected = tuple(expected)
        assert got == expected, f"{op} failed: got {got}, expected {expected}"


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
