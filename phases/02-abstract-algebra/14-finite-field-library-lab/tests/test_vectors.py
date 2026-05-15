import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    InvalidFieldError,
    NoInverseError,
    NotIrreducibleError,
    PrimeField,
    PolyField,
    aes_inverse,
    aes_mul,
    is_irreducible,
    is_prime,
)


ERRORS = {
    "InvalidFieldError": InvalidFieldError,
    "NoInverseError": NoInverseError,
    "NotIrreducibleError": NotIrreducibleError,
}


def normalize(value):
    if hasattr(value, "value"):
        return int(value)
    if hasattr(value, "coefficients"):
        return list(value.coefficients)
    if isinstance(value, tuple):
        return [normalize(v) for v in value]
    if isinstance(value, list):
        return [normalize(v) for v in value]
    if isinstance(value, dict):
        return {str(k): normalize(v) for k, v in value.items()}
    return value


def call(vector):
    op = vector["op"]

    if op == "is_prime":
        return is_prime(vector["n"])
    if op == "is_irreducible":
        return is_irreducible(vector["modulus"], vector["p"])

    if op == "fp_add":
        f = PrimeField(vector["p"])
        return f(vector["a"]) + f(vector["b"])
    if op == "fp_mul":
        f = PrimeField(vector["p"])
        return f(vector["a"]) * f(vector["b"])
    if op == "fp_div":
        f = PrimeField(vector["p"])
        return f(vector["a"]) / f(vector["b"])
    if op == "fp_pow":
        f = PrimeField(vector["p"])
        return f(vector["a"]) ** vector["exponent"]
    if op == "fp_mix":
        f1 = PrimeField(vector["p1"])
        f2 = PrimeField(vector["p2"])
        return f1(vector["a"]) + f2(vector["b"])

    if op == "fq_add":
        f = PolyField(vector["p"], vector["modulus"])
        return f(vector["a"]) + f(vector["b"])
    if op == "fq_mul":
        f = PolyField(vector["p"], vector["modulus"])
        return f(vector["a"]) * f(vector["b"])
    if op == "fq_inv":
        f = PolyField(vector["p"], vector["modulus"])
        return f(vector["a"]).inverse()
    if op == "fq_div":
        f = PolyField(vector["p"], vector["modulus"])
        return f(vector["a"]) / f(vector["b"])
    if op == "fq_pow":
        f = PolyField(vector["p"], vector["modulus"])
        return f(vector["a"]) ** vector["exponent"]
    if op == "fq_mix":
        f1 = PolyField(vector["p1"], vector["modulus1"])
        f2 = PolyField(vector["p2"], vector["modulus2"])
        return f1(vector["a"]) + f2(vector["b"])
    if op == "fq_construct":
        return PolyField(vector["p"], vector["modulus"]).degree

    if op == "aes_mul":
        return aes_mul(vector["a"], vector["b"])
    if op == "aes_inverse":
        return aes_inverse(vector["byte"])

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
        assert got == normalize(vector["expected"]), (
            f"{vector['op']} failed: got {got}, expected {vector['expected']}"
        )


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
