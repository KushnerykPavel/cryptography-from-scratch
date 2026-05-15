import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    ExtensionField,
    factor_by_trial,
    field_report,
    find_irreducible,
    has_root,
    is_irreducible,
    monic_polynomials,
    poly_pow_mod,
    prime_factors,
    reducible_witness,
    roots,
)


def clean(value):
    if isinstance(value, ExtensionField):
        return list(value.value)
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
            if op == "prime_factors":
                got = prime_factors(v["n"])
            elif op == "monic_polynomials":
                got = monic_polynomials(v["degree"], v["p"])
            elif op == "roots":
                got = roots(v["poly"], v["p"])
            elif op == "has_root":
                got = has_root(v["poly"], v["p"])
            elif op == "is_irreducible":
                got = is_irreducible(v["poly"], v["p"])
            elif op == "find_irreducible":
                got = find_irreducible(v["degree"], v["p"])
            elif op == "factor_by_trial":
                got = factor_by_trial(v["poly"], v["p"])
            elif op == "reducible_witness":
                got = reducible_witness(v["poly"], v["p"])
            elif op == "poly_pow_mod":
                got = poly_pow_mod(v["base"], v["exponent"], v["modulus"], v["p"])
            elif op == "field_report":
                got = field_report(v["modulus"], v["p"])
            elif op == "extension_expression":
                a = ExtensionField(v["a"], v["modulus"], v["p"])
                b = ExtensionField(v["b"], v["modulus"], v["p"])
                if v["expression"] == "add":
                    got = a + b
                elif v["expression"] == "mul":
                    got = a * b
                elif v["expression"] == "div":
                    got = a / b
                elif v["expression"] == "pow":
                    got = b ** v["exponent"]
                elif v["expression"] == "inverse":
                    got = b.inverse()
                else:
                    raise AssertionError(f"unknown expression {v['expression']}")
            elif op == "construct_extension":
                got = ExtensionField(v["value"], v["modulus"], v["p"])
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
