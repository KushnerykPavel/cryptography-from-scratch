import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    Curve,
    Point,
    discrete_log_bruteforce,
    is_on_curve,
    point_add,
    point_neg,
    scalar_mul,
)


def parse_point(value):
    if value is None:
        return None
    return Point(value[0], value[1])


def point_to_json(value):
    if value is None:
        return None
    return [value.x, value.y]


def test_vectors():
    curve = Curve(p=211, a=0, b=7)

    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        if op == "is_on_curve":
            got = is_on_curve(curve, parse_point(v["point"]))
        elif op == "point_neg":
            got = point_to_json(point_neg(curve, parse_point(v["point"])))
        elif op == "point_add":
            got = point_to_json(
                point_add(curve, parse_point(v["p"]), parse_point(v["q"]))
            )
        elif op == "scalar_mul":
            got = point_to_json(scalar_mul(curve, v["k"], parse_point(v["point"])))
        elif op == "discrete_log_bruteforce":
            got = discrete_log_bruteforce(
                curve, parse_point(v["base"]), parse_point(v["target"])
            )
        elif op == "add_mul_consistency":
            base = parse_point(v["base"])
            p1 = scalar_mul(curve, v["k1"], base)
            p2 = scalar_mul(curve, v["k2"], base)
            got = point_to_json(point_add(curve, p1, p2))
        else:
            raise AssertionError(f"unknown op {op}")

        assert got == v["expected"], f"{op} failed: got {got}, expected {v['expected']}"


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")

