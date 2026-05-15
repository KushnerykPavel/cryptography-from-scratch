import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    Curve,
    Point,
    naf_digits,
    scalar_mul,
    scalar_mul_double_and_add,
    scalar_mul_naf,
    scalar_mul_wnaf,
    wnaf_digits,
)


def parse_curve(value):
    return Curve(p=value["p"], a=value["a"], b=value["b"])


def parse_point(value):
    if value is None:
        return None
    return Point(value[0], value[1])


def point_to_json(value):
    if value is None:
        return None
    return [value.x, value.y]


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        if op in {"naf_digits", "wnaf_digits"}:
            if op == "naf_digits":
                got = naf_digits(v["k"])
            else:
                got = wnaf_digits(v["k"], v["w"])
            assert got == v["expected"], f"{op} failed: got {got}, expected {v['expected']}"
            continue

        curve = parse_curve(v["curve"])
        point = parse_point(v["point"])
        k = v["k"]

        if op == "scalar_mul_double_and_add":
            got = point_to_json(scalar_mul_double_and_add(curve, k, point))
        elif op == "scalar_mul_naf":
            got = point_to_json(scalar_mul_naf(curve, k, point))
        elif op == "scalar_mul_wnaf":
            got = point_to_json(scalar_mul_wnaf(curve, k, point, w=v.get("w", 5)))
        elif op == "scalar_mul":
            got = point_to_json(
                scalar_mul(curve, k, point, method=v.get("method", "wnaf"), w=v.get("w", 5))
            )
        else:
            raise AssertionError(f"unknown op {op}")

        assert got == v["expected"], f"{op} failed: got {got}, expected {v['expected']}"


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")

