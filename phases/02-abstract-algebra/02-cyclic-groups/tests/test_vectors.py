import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    add_mod,
    cyclic_group_report,
    discrete_log_bruteforce,
    element_order,
    generated_subgroup,
    generators,
    is_cyclic,
    is_prime,
    mul_mod,
    primitive_roots_mod_prime,
    repeat_operation,
    residues_mod,
    units_mod,
)


def normalize(value):
    if isinstance(value, dict):
        return {str(k): normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    return value


def add_group(n):
    elements = residues_mod(n)
    operation = lambda a, b: add_mod(a, b, n)
    identity = 0
    return elements, operation, identity


def unit_group(n):
    elements = units_mod(n)
    operation = lambda a, b: mul_mod(a, b, n)
    identity = 1
    return elements, operation, identity


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "is_prime":
                got = is_prime(v["n"])
            elif op == "repeat_operation_add_mod":
                elements, operation, identity = add_group(v["n"])
                got = repeat_operation(
                    v["element"], v["exponent"], identity, operation
                )
            elif op == "repeat_operation_mul_mod":
                elements, operation, identity = unit_group(v["n"])
                got = repeat_operation(
                    v["element"], v["exponent"], identity, operation
                )
            elif op == "element_order_add_mod":
                elements, operation, _ = add_group(v["n"])
                got = element_order(v["element"], elements, operation)
            elif op == "element_order_units_mod":
                elements, operation, _ = unit_group(v["n"])
                got = element_order(v["element"], elements, operation)
            elif op == "generated_subgroup_add_mod":
                elements, operation, _ = add_group(v["n"])
                got = generated_subgroup(v["element"], elements, operation)
            elif op == "generated_subgroup_units_mod":
                elements, operation, _ = unit_group(v["n"])
                got = generated_subgroup(v["element"], elements, operation)
            elif op == "generators_add_mod":
                elements, operation, _ = add_group(v["n"])
                got = generators(elements, operation)
            elif op == "generators_units_mod":
                elements, operation, _ = unit_group(v["n"])
                got = generators(elements, operation)
            elif op == "is_cyclic_add_mod":
                elements, operation, _ = add_group(v["n"])
                got = is_cyclic(elements, operation)
            elif op == "is_cyclic_units_mod":
                elements, operation, _ = unit_group(v["n"])
                got = is_cyclic(elements, operation)
            elif op == "primitive_roots_mod_prime":
                got = primitive_roots_mod_prime(v["p"])
            elif op == "discrete_log_bruteforce_units_mod":
                elements, operation, _ = unit_group(v["n"])
                got = discrete_log_bruteforce(
                    v["base"], v["target"], elements, operation
                )
            elif op == "cyclic_group_report_add_mod":
                elements, operation, _ = add_group(v["n"])
                got = cyclic_group_report(elements, operation)
            elif op == "cyclic_group_report_units_mod":
                elements, operation, _ = unit_group(v["n"])
                got = cyclic_group_report(elements, operation)
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
