import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    add_mod,
    field_report,
    fp2_add,
    fp2_inv,
    fp2_is_field,
    fp2_mul,
    fp2_norm,
    fp2_pow,
    fp2_report,
    fp2_trace,
    fp2_zero_divisor_pair,
    is_field,
    mul_mod,
    prime_field_elements,
    residues_mod,
)


def normalize(value):
    if isinstance(value, dict):
        return {str(k): normalize(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [normalize(v) for v in value]
    if isinstance(value, list):
        return [normalize(v) for v in value]
    return value


def z_mod_ring(n):
    elements = residues_mod(n)
    add = lambda a, b: add_mod(a, b, n)
    mul = lambda a, b: mul_mod(a, b, n)
    return elements, add, mul


def fp_ring(p):
    elements = prime_field_elements(p)
    add = lambda a, b: add_mod(a, b, p)
    mul = lambda a, b: mul_mod(a, b, p)
    return elements, add, mul


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "is_field":
                elements, add, mul = z_mod_ring(v["n"])
                got = is_field(elements, add, mul)
            elif op == "prime_field_report":
                elements, add, mul = fp_ring(v["p"])
                got = field_report(elements, add, mul)
            elif op == "fp2_is_field":
                got = fp2_is_field(v["p"], v["beta"])
            elif op == "fp2_add":
                got = fp2_add(tuple(v["x"]), tuple(v["y"]), v["p"])
            elif op == "fp2_mul":
                got = fp2_mul(tuple(v["x"]), tuple(v["y"]), v["p"], v["beta"])
            elif op == "fp2_inv":
                got = fp2_inv(tuple(v["x"]), v["p"], v["beta"])
            elif op == "fp2_pow":
                got = fp2_pow(tuple(v["x"]), v["exponent"], v["p"], v["beta"])
            elif op == "fp2_norm":
                got = fp2_norm(tuple(v["x"]), v["p"], v["beta"])
            elif op == "fp2_trace":
                got = fp2_trace(tuple(v["x"]), v["p"])
            elif op == "fp2_zero_divisor_pair":
                got = fp2_zero_divisor_pair(v["p"], v["beta"])
            elif op == "fp2_report":
                got = fp2_report(v["p"], v["beta"])
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
