import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    NoInverseError,
    NoSquareRootError,
    all_mod_sqrt,
    carmichael_lambda,
    continued_fraction,
    crt,
    extended_gcd,
    factor,
    gcd,
    is_prime,
    jacobi_symbol,
    legendre_symbol,
    mod_inverse,
    mod_pow,
    mod_sqrt,
    multiplicative_order,
    phi,
    prime_sieve,
)


ERRORS = {
    "NoInverseError": NoInverseError,
    "NoSquareRootError": NoSquareRootError,
    "ValueError": ValueError,
}


def normalize(value):
    if isinstance(value, tuple):
        return [normalize(item) for item in value]
    if isinstance(value, list):
        return [normalize(item) for item in value]
    return value


def call(vector):
    op = vector["op"]
    if op == "gcd":
        return gcd(vector["a"], vector["b"])
    if op == "extended_gcd":
        return extended_gcd(vector["a"], vector["b"])
    if op == "mod_pow":
        return mod_pow(vector["base"], vector["exponent"], vector["modulus"])
    if op == "mod_inverse":
        return mod_inverse(vector["a"], vector["modulus"])
    if op == "crt":
        return crt(vector["residues"], vector["moduli"])
    if op == "is_prime":
        return is_prime(vector["n"])
    if op == "prime_sieve":
        return prime_sieve(vector["limit"])
    if op == "factor":
        return factor(vector["n"])
    if op == "phi":
        return phi(vector["n"])
    if op == "carmichael_lambda":
        return carmichael_lambda(vector["n"])
    if op == "legendre_symbol":
        return legendre_symbol(vector["a"], vector["p"])
    if op == "jacobi_symbol":
        return jacobi_symbol(vector["a"], vector["n"])
    if op == "mod_sqrt":
        return mod_sqrt(vector["a"], vector["p"])
    if op == "all_mod_sqrt":
        return all_mod_sqrt(vector["a"], vector["p"])
    if op == "multiplicative_order":
        return multiplicative_order(vector["a"], vector["n"])
    if op == "continued_fraction":
        return continued_fraction(vector["numerator"], vector["denominator"])
    raise AssertionError(f"unknown op {op}")


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for vector in data["vectors"]:
        expected_error = vector.get("expected_error")
        if expected_error:
            try:
                call(vector)
            except ERRORS[expected_error]:
                continue
            raise AssertionError(f"{vector['op']} did not raise {expected_error}")

        got = normalize(call(vector))
        assert got == vector["expected"], (
            f"{vector['op']} failed: got {got}, expected {vector['expected']}"
        )


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
