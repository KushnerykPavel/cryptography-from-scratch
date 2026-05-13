import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    add_mod,
    cosets_partition_group,
    generated_subgroup,
    is_subgroup,
    lagrange_holds,
    lagrange_report,
    left_coset,
    left_cosets,
    mul_mod,
    possible_subgroup_orders,
    residues_mod,
    right_coset,
    right_cosets,
    subgroup_index,
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
    return elements, operation


def unit_group(n):
    elements = units_mod(n)
    operation = lambda a, b: mul_mod(a, b, n)
    return elements, operation


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "generated_subgroup_add_mod":
                elements, operation = add_group(v["n"])
                got = generated_subgroup(v["element"], elements, operation)
            elif op == "generated_subgroup_units_mod":
                elements, operation = unit_group(v["n"])
                got = generated_subgroup(v["element"], elements, operation)
            elif op == "is_subgroup_add_mod":
                elements, operation = add_group(v["n"])
                got = is_subgroup(v["subset"], elements, operation)
            elif op == "is_subgroup_units_mod":
                elements, operation = unit_group(v["n"])
                got = is_subgroup(v["subset"], elements, operation)
            elif op == "left_coset_add_mod":
                elements, operation = add_group(v["n"])
                got = left_coset(v["representative"], v["subgroup"], elements, operation)
            elif op == "right_coset_add_mod":
                elements, operation = add_group(v["n"])
                got = right_coset(v["representative"], v["subgroup"], elements, operation)
            elif op == "left_coset_units_mod":
                elements, operation = unit_group(v["n"])
                got = left_coset(v["representative"], v["subgroup"], elements, operation)
            elif op == "right_coset_units_mod":
                elements, operation = unit_group(v["n"])
                got = right_coset(v["representative"], v["subgroup"], elements, operation)
            elif op == "left_cosets_add_mod":
                elements, operation = add_group(v["n"])
                got = left_cosets(v["subgroup"], elements, operation)
            elif op == "right_cosets_add_mod":
                elements, operation = add_group(v["n"])
                got = right_cosets(v["subgroup"], elements, operation)
            elif op == "left_cosets_units_mod":
                elements, operation = unit_group(v["n"])
                got = left_cosets(v["subgroup"], elements, operation)
            elif op == "right_cosets_units_mod":
                elements, operation = unit_group(v["n"])
                got = right_cosets(v["subgroup"], elements, operation)
            elif op == "cosets_partition_group_add_mod":
                elements, operation = add_group(v["n"])
                cosets = left_cosets(v["subgroup"], elements, operation)
                got = cosets_partition_group(cosets, elements)
            elif op == "subgroup_index_add_mod":
                elements, operation = add_group(v["n"])
                got = subgroup_index(v["subgroup"], elements, operation)
            elif op == "subgroup_index_units_mod":
                elements, operation = unit_group(v["n"])
                got = subgroup_index(v["subgroup"], elements, operation)
            elif op == "lagrange_holds_add_mod":
                elements, operation = add_group(v["n"])
                got = lagrange_holds(v["subgroup"], elements, operation)
            elif op == "lagrange_holds_units_mod":
                elements, operation = unit_group(v["n"])
                got = lagrange_holds(v["subgroup"], elements, operation)
            elif op == "lagrange_report_add_mod":
                elements, operation = add_group(v["n"])
                got = lagrange_report(v["subgroup"], elements, operation)
            elif op == "lagrange_report_units_mod":
                elements, operation = unit_group(v["n"])
                got = lagrange_report(v["subgroup"], elements, operation)
            elif op == "possible_subgroup_orders_add_mod":
                elements, operation = add_group(v["n"])
                got = possible_subgroup_orders(elements, operation)
            elif op == "possible_subgroup_orders_units_mod":
                elements, operation = unit_group(v["n"])
                got = possible_subgroup_orders(elements, operation)
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
