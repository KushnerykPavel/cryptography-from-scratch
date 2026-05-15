import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    Curve,
    Point,
    recover_bits_from_trace,
    scalar_mul_double_and_add,
    scalar_mul_montgomery_ladder,
    trace_double_and_add,
    trace_montgomery_ladder,
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

        if op == "trace_double_and_add":
            assert trace_double_and_add(v["k"]) == v["expected"]
            continue
        if op == "trace_montgomery_ladder":
            assert trace_montgomery_ladder(v["k"]) == v["expected"]
            continue
        if op == "recover_bits_from_trace":
            assert recover_bits_from_trace(v["trace"]) == v["expected"]
            continue

        curve = parse_curve(v["curve"])
        point = parse_point(v["point"])
        k = v["k"]

        if op == "scalar_mul_double_and_add":
            got = point_to_json(scalar_mul_double_and_add(curve, k, point))
        elif op == "scalar_mul_montgomery_ladder":
            got = point_to_json(scalar_mul_montgomery_ladder(curve, k, point))
        else:
            raise AssertionError(f"unknown op {op}")

        assert got == v["expected"], f"{op} failed: got {got}, expected {v['expected']}"


def test_ladder_trace_length_is_fixed_per_bitlength():
    for k in [1, 2, 3, 4, 5, 37, 255, 256]:
        t = trace_montgomery_ladder(k)
        assert len(t) == 2 * k.bit_length()


if __name__ == "__main__":
    test_vectors()
    test_ladder_trace_length_is_fixed_per_bitlength()
    print("all vectors pass")

