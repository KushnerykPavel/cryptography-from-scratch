import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    Poly,
    PolyMod,
    normalize,
    poly_add,
    poly_degree,
    poly_divmod,
    poly_eval,
    poly_extended_gcd,
    poly_gcd,
    poly_mod,
    poly_mul,
    poly_neg,
    poly_scale,
    poly_sub,
    poly_to_string,
    polynomial_ring_report,
    quotient_add,
    quotient_div,
    quotient_inverse,
    quotient_mul,
    quotient_pow,
    quotient_sub,
    zero_divisor_pair,
)


def clean(value):
    if isinstance(value, (Poly, PolyMod)):
        return clean(value.coefficients if isinstance(value, Poly) else value.value)
    if isinstance(value, tuple):
        return [clean(v) for v in value]
    if isinstance(value, list):
        return [clean(v) for v in value]
    if isinstance(value, dict):
        return {str(k): clean(v) for k, v in value.items()}
    return value


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "normalize":
                got = normalize(v["coefficients"], v["p"])
            elif op == "poly_degree":
                got = poly_degree(v["coefficients"], v["p"])
            elif op == "poly_to_string":
                got = poly_to_string(v["coefficients"], v["p"])
            elif op == "poly_add":
                got = poly_add(v["a"], v["b"], v["p"])
            elif op == "poly_neg":
                got = poly_neg(v["a"], v["p"])
            elif op == "poly_sub":
                got = poly_sub(v["a"], v["b"], v["p"])
            elif op == "poly_scale":
                got = poly_scale(v["a"], v["scalar"], v["p"])
            elif op == "poly_mul":
                got = poly_mul(v["a"], v["b"], v["p"])
            elif op == "poly_divmod":
                got = poly_divmod(v["dividend"], v["divisor"], v["p"])
            elif op == "poly_mod":
                got = poly_mod(v["poly"], v["modulus"], v["p"])
            elif op == "poly_gcd":
                got = poly_gcd(v["a"], v["b"], v["p"])
            elif op == "poly_extended_gcd":
                got = poly_extended_gcd(v["a"], v["b"], v["p"])
            elif op == "poly_eval":
                got = poly_eval(v["coefficients"], v["x"], v["p"])
            elif op == "quotient_add":
                got = quotient_add(v["a"], v["b"], v["modulus"], v["p"])
            elif op == "quotient_sub":
                got = quotient_sub(v["a"], v["b"], v["modulus"], v["p"])
            elif op == "quotient_mul":
                got = quotient_mul(v["a"], v["b"], v["modulus"], v["p"])
            elif op == "quotient_pow":
                got = quotient_pow(v["a"], v["exponent"], v["modulus"], v["p"])
            elif op == "quotient_inverse":
                got = quotient_inverse(v["a"], v["modulus"], v["p"])
            elif op == "quotient_div":
                got = quotient_div(v["a"], v["b"], v["modulus"], v["p"])
            elif op == "zero_divisor_pair":
                got = zero_divisor_pair(v["modulus"], v["p"])
            elif op == "polynomial_ring_report":
                got = polynomial_ring_report(v["modulus"], v["p"])
            elif op == "poly_expression":
                f = Poly(v["f"], v["p"])
                g = Poly(v["g"], v["p"])
                got = f + g * Poly(v["scalar"], v["p"])
            elif op == "quotient_expression":
                a = PolyMod(v["a"], v["modulus"], v["p"])
                b = PolyMod(v["b"], v["modulus"], v["p"])
                got = a * b + v["add"]
            else:
                raise AssertionError(f"unknown op {op}")
        except ValueError as exc:
            assert v.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {v.get('expected_error')}"
            )
            continue

        assert clean(got) == clean(v["expected"]), (
            f"{op} failed: got {clean(got)}, expected {clean(v['expected'])}"
        )


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
