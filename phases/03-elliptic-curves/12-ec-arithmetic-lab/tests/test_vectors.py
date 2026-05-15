import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    ECError,
    InvalidCurveError,
    InvalidPointError,
    NoInverseError,
    NoSquareRootError,
    Curve,
    Point,
    is_on_curve,
    lift_x,
    mod_sqrt,
    naf_digits,
    parse_point_sec1,
    point_add_affine,
    point_order,
    scalar_mul_affine,
    scalar_mul_jacobian,
    scalar_mul_montgomery_ladder_affine,
    scalar_mul_naf_affine,
    scalar_mul_wnaf_affine,
    serialize_compressed,
    serialize_uncompressed,
    validate_curve,
    wnaf_digits,
)


ERRORS = {
    "ECError": ECError,
    "InvalidCurveError": InvalidCurveError,
    "InvalidPointError": InvalidPointError,
    "NoInverseError": NoInverseError,
    "NoSquareRootError": NoSquareRootError,
}


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


def call(vector):
    op = vector["op"]

    if op == "validate_curve":
        validate_curve(parse_curve(vector["curve"]))
        return True
    if op == "is_on_curve":
        return is_on_curve(parse_curve(vector["curve"]), parse_point(vector["point"]))
    if op == "point_add_affine":
        curve = parse_curve(vector["curve"])
        return point_to_json(
            point_add_affine(curve, parse_point(vector["p"]), parse_point(vector["q"]))
        )
    if op == "scalar_mul_affine":
        curve = parse_curve(vector["curve"])
        return point_to_json(
            scalar_mul_affine(curve, vector["k"], parse_point(vector["point"]))
        )
    if op == "scalar_mul_montgomery_ladder_affine":
        curve = parse_curve(vector["curve"])
        return point_to_json(
            scalar_mul_montgomery_ladder_affine(curve, vector["k"], parse_point(vector["point"]))
        )
    if op == "scalar_mul_naf_affine":
        curve = parse_curve(vector["curve"])
        return point_to_json(
            scalar_mul_naf_affine(curve, vector["k"], parse_point(vector["point"]))
        )
    if op == "scalar_mul_wnaf_affine":
        curve = parse_curve(vector["curve"])
        return point_to_json(
            scalar_mul_wnaf_affine(curve, vector["k"], parse_point(vector["point"]), w=vector.get("w", 5))
        )
    if op == "scalar_mul_jacobian":
        curve = parse_curve(vector["curve"])
        return point_to_json(
            scalar_mul_jacobian(curve, vector["k"], parse_point(vector["point"]))
        )
    if op == "point_order":
        curve = parse_curve(vector["curve"])
        p = parse_point(vector["point"])
        if p is None:
            raise AssertionError("point_order requires a non-infinity point")
        return point_order(curve, p)

    if op == "naf_digits":
        return naf_digits(vector["k"])
    if op == "wnaf_digits":
        return wnaf_digits(vector["k"], vector["w"])
    if op == "mod_sqrt":
        return mod_sqrt(vector["a"], vector["p"])
    if op == "lift_x":
        curve = parse_curve(vector["curve"])
        return point_to_json(lift_x(curve, vector["x"], vector["y_parity"]))
    if op == "serialize_compressed":
        curve = parse_curve(vector["curve"])
        return serialize_compressed(curve, parse_point(vector["point"])).hex()
    if op == "serialize_uncompressed":
        curve = parse_curve(vector["curve"])
        return serialize_uncompressed(curve, parse_point(vector["point"])).hex()
    if op == "parse_point_sec1":
        curve = parse_curve(vector["curve"])
        return point_to_json(parse_point_sec1(curve, bytes.fromhex(vector["hex"])))

    raise AssertionError(f"unknown op {op}")


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for vector in data["vectors"]:
        expected_error = vector.get("expected_error")
        if expected_error:
            try:
                call(vector)
            except ERRORS[expected_error]:
                continue
            raise AssertionError(f"{vector['op']} did not raise {expected_error}")

        got = call(vector)
        if "expected_prefix" in vector:
            assert got[: len(vector["expected_prefix"])] == vector["expected_prefix"], (
                f"{vector['op']} failed: got {got}, expected_prefix {vector['expected_prefix']}"
            )
            continue

        expected = vector["expected_hex"] if "expected_hex" in vector else vector["expected"]
        assert got == expected, f"{vector['op']} failed: got {got}, expected {expected}"


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")

