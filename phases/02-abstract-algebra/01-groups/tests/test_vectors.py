import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    add_mod,
    cayley_table,
    element_order,
    find_identity,
    group_report,
    inverse_of,
    is_group,
    mul_mod,
    residues_mod,
    units_mod,
)


def normalize(value):
    if isinstance(value, dict):
        return {str(k): normalize(v) for k, v in value.items()}
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
            if op == "residues_mod":
                got = residues_mod(v["n"])
            elif op == "units_mod":
                got = units_mod(v["n"])
            elif op == "add_mod":
                got = add_mod(v["a"], v["b"], v["n"])
            elif op == "mul_mod":
                got = mul_mod(v["a"], v["b"], v["n"])
            elif op == "cayley_table_add_mod":
                elements = residues_mod(v["n"])
                got = cayley_table(elements, lambda a, b: add_mod(a, b, v["n"]))
            elif op == "find_identity_add_mod":
                elements = residues_mod(v["n"])
                got = find_identity(elements, lambda a, b: add_mod(a, b, v["n"]))
            elif op == "inverse_of_add_mod":
                elements = residues_mod(v["n"])
                got = inverse_of(
                    v["element"], elements, lambda a, b: add_mod(a, b, v["n"])
                )
            elif op == "element_order_add_mod":
                elements = residues_mod(v["n"])
                got = element_order(
                    v["element"], elements, lambda a, b: add_mod(a, b, v["n"])
                )
            elif op == "find_identity_units_mod":
                elements = units_mod(v["n"])
                got = find_identity(elements, lambda a, b: mul_mod(a, b, v["n"]))
            elif op == "inverse_of_units_mod":
                elements = units_mod(v["n"])
                got = inverse_of(
                    v["element"], elements, lambda a, b: mul_mod(a, b, v["n"])
                )
            elif op == "element_order_units_mod":
                elements = units_mod(v["n"])
                got = element_order(
                    v["element"], elements, lambda a, b: mul_mod(a, b, v["n"])
                )
            elif op == "group_report_add_mod":
                elements = residues_mod(v["n"])
                got = group_report(elements, lambda a, b: add_mod(a, b, v["n"]))
            elif op == "group_report_units_mod":
                elements = units_mod(v["n"])
                got = group_report(elements, lambda a, b: mul_mod(a, b, v["n"]))
            elif op == "is_group_add_mod":
                elements = residues_mod(v["n"])
                got = is_group(elements, lambda a, b: add_mod(a, b, v["n"]))
            elif op == "is_group_raw_multiplication":
                elements = v["elements"]
                got = is_group(elements, lambda a, b: a * b)
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
