import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    Curve,
    Point,
    is_on_curve,
    point_add,
    point_neg,
    point_order,
    scalar_mul,
    validate_curve,
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
        curve = parse_curve(v["curve"])

        try:
            if op == "validate_curve":
                validate_curve(curve)
                got = True
            elif op == "is_on_curve":
                got = is_on_curve(curve, parse_point(v["point"]))
            elif op == "point_neg":
                got = point_to_json(point_neg(curve, parse_point(v["point"])))
            elif op == "point_add":
                got = point_to_json(
                    point_add(curve, parse_point(v["p"]), parse_point(v["q"]))
                )
            elif op == "scalar_mul":
                got = point_to_json(scalar_mul(curve, v["k"], parse_point(v["point"])))
            elif op == "point_order":
                got = point_order(curve, parse_point(v["point"]))
            else:
                raise AssertionError(f"unknown op {op}")
        except ValueError as exc:
            assert v.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {v.get('expected_error')}"
            )
            continue

        assert got == v["expected"], f"{op} failed: got {got}, expected {v['expected']}"


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")

