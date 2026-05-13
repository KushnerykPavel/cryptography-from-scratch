import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    best_rational_approximations,
    continued_fraction,
    convergents,
    factor_over_base,
    rational_from_continued_fraction,
    smooth_cfrac_relations,
    solve_rsa_factors_from_phi,
    sqrt_cf_terms,
    sqrt_continued_fraction,
    sqrt_convergent_relations,
    wiener_attack,
)


def normalize(value):
    if hasattr(value, "__dataclass_fields__"):
        return {name: normalize(getattr(value, name)) for name in value.__dataclass_fields__}
    if isinstance(value, tuple):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        return {str(key): normalize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize(item) for item in value]
    return value


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for vector in data["vectors"]:
        op = vector["op"]

        if op == "continued_fraction":
            got = continued_fraction(vector["numerator"], vector["denominator"])
        elif op == "rational_from_continued_fraction":
            got = rational_from_continued_fraction(vector["terms"])
        elif op == "convergents":
            got = convergents(vector["terms"])
        elif op == "best_rational_approximations":
            got = best_rational_approximations(vector["numerator"], vector["denominator"])
        elif op == "sqrt_continued_fraction":
            got = sqrt_continued_fraction(vector["n"])
        elif op == "sqrt_cf_terms":
            got = sqrt_cf_terms(vector["n"], vector["count"])
        elif op == "solve_rsa_factors_from_phi":
            got = solve_rsa_factors_from_phi(vector["n"], vector["phi"])
        elif op == "wiener_attack":
            got = wiener_attack(vector["e"], vector["n"])
        elif op == "sqrt_convergent_relations":
            got = sqrt_convergent_relations(vector["n"], vector["count"])
        elif op == "factor_over_base":
            got = factor_over_base(vector["value"], vector["base"])
        elif op == "smooth_cfrac_relations":
            got = smooth_cfrac_relations(vector["n"], vector["count"], vector["base"])
        else:
            raise AssertionError(f"unknown op {op}")

        assert normalize(got) == vector["expected"], (
            f"{op} failed: got {normalize(got)}, expected {vector['expected']}"
        )


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
