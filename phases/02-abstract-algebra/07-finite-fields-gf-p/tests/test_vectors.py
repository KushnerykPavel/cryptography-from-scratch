import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    Fp,
    addition_table,
    field_report,
    fp_add,
    fp_div,
    fp_mul,
    fp_neg,
    fp_pow,
    fp_sub,
    generators,
    inverses,
    is_generator,
    is_prime,
    lagrange_interpolate_at,
    mod_inverse,
    multiplicative_order,
    multiplication_table,
    poly_eval,
)


def normalize(value):
    if isinstance(value, Fp):
        return value.value
    if isinstance(value, dict):
        return {str(k): normalize(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [normalize(v) for v in value]
    if isinstance(value, list):
        return [normalize(v) for v in value]
    return value


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "is_prime":
                got = is_prime(v["n"])
            elif op == "mod_inverse":
                got = mod_inverse(v["a"], v["p"])
            elif op == "fp_add":
                got = fp_add(v["a"], v["b"], v["p"])
            elif op == "fp_sub":
                got = fp_sub(v["a"], v["b"], v["p"])
            elif op == "fp_neg":
                got = fp_neg(v["a"], v["p"])
            elif op == "fp_mul":
                got = fp_mul(v["a"], v["b"], v["p"])
            elif op == "fp_div":
                got = fp_div(v["a"], v["b"], v["p"])
            elif op == "fp_pow":
                got = fp_pow(v["a"], v["exponent"], v["p"])
            elif op == "field_expression":
                a = Fp(v["a"], v["p"])
                b = Fp(v["b"], v["p"])
                c = Fp(v["c"], v["p"])
                got = (a + b) * c
            elif op == "addition_table":
                got = addition_table(v["p"])
            elif op == "multiplication_table":
                got = multiplication_table(v["p"])
            elif op == "inverses":
                got = inverses(v["p"])
            elif op == "multiplicative_order":
                got = multiplicative_order(v["a"], v["p"])
            elif op == "is_generator":
                got = is_generator(v["a"], v["p"])
            elif op == "generators":
                got = generators(v["p"])
            elif op == "poly_eval":
                got = poly_eval(v["coefficients"], v["x"], v["p"])
            elif op == "lagrange_interpolate_at":
                got = lagrange_interpolate_at(v["points"], v["x"], v["p"])
            elif op == "field_report":
                got = field_report(v["p"])
            else:
                raise AssertionError(f"unknown op {op}")
        except ValueError as exc:
            assert v.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {v.get('expected_error')}"
            )
            continue

        assert normalize(got) == normalize(v["expected"]), (
            f"{op} failed: got {normalize(got)}, expected {normalize(v['expected'])}"
        )


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
