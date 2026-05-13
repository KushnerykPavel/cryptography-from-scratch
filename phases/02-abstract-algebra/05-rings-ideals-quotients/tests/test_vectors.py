import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    add_mod,
    ideal_report,
    is_ideal,
    is_ring,
    mul_mod,
    principal_ideal,
    quotient_coset_reps,
    quotient_is_ring,
    residues_mod,
    ring_report,
    units,
    zero_divisors,
)


def normalize(value):
    if isinstance(value, dict):
        return {str(k): normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    return value


def z_mod_ring(n):
    elements = residues_mod(n)
    add = lambda a, b: add_mod(a, b, n)
    mul = lambda a, b: mul_mod(a, b, n)
    return elements, add, mul


def build_case(v):
    n = v["n"]
    elements, add, mul = z_mod_ring(n)
    subset = v.get("subset")
    return elements, add, mul, subset


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        elements, add, mul, subset = build_case(v)
        op = v["op"]

        try:
            if op == "is_ring":
                got = is_ring(elements, add, mul)
            elif op == "ring_report":
                got = ring_report(elements, add, mul)
            elif op == "principal_ideal":
                got = principal_ideal(v["generator"], elements, mul)
            elif op == "is_ideal":
                got = is_ideal(subset, elements, add, mul)
            elif op == "quotient_coset_reps":
                got = quotient_coset_reps(elements, subset, add, mul)
            elif op == "quotient_is_ring":
                got = quotient_is_ring(elements, subset, add, mul)
            elif op == "ideal_report":
                got = ideal_report(subset, elements, add, mul)
            elif op == "zero_divisors":
                got = zero_divisors(elements, add, mul)
            elif op == "units":
                got = units(elements, add, mul)
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
