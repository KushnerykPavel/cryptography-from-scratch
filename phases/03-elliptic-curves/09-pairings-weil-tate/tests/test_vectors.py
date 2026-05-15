import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    FP2_ONE,
    TOY_CURVE,
    TOY_G1_GENERATOR,
    TOY_R,
    distortion_map,
    fp2_to_json,
    point_fp_to_fp2,
    reduced_tate_pairing,
    scalar_mul_fp,
    scalar_mul_fp2,
    weil_pairing,
)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    p = point_fp_to_fp2(TOY_G1_GENERATOR)
    q = distortion_map(p)

    for v in data["vectors"]:
        op = v["op"]

        if op == "scalar_mul_rG_is_infinity":
            got = scalar_mul_fp(TOY_CURVE, TOY_R, TOY_G1_GENERATOR)
            assert got is None
            continue

        if op == "distortion_map_G":
            got = [fp2_to_json(q.x), fp2_to_json(q.y)]
            assert got == v["expected"]
            continue

        if op == "weil_pairing_G_distorted":
            got = fp2_to_json(weil_pairing(TOY_CURVE, TOY_R, p, q))
            assert got == v["expected"]
            continue

        if op == "tate_pairing_G_distorted":
            got = fp2_to_json(reduced_tate_pairing(TOY_CURVE, TOY_R, p, q))
            assert got == v["expected"]
            continue

        if op == "tate_pairing_2G_distorted":
            p2 = scalar_mul_fp2(TOY_CURVE, 2, p)
            got = fp2_to_json(reduced_tate_pairing(TOY_CURVE, TOY_R, p2, q))
            assert got == v["expected"]
            continue

        if op == "weil_pairing_2G_distorted":
            p2 = scalar_mul_fp2(TOY_CURVE, 2, p)
            got = fp2_to_json(weil_pairing(TOY_CURVE, TOY_R, p2, q))
            assert got == v["expected"]
            continue

        raise AssertionError(f"unknown op {op}")

    t = reduced_tate_pairing(TOY_CURVE, TOY_R, p, q)
    assert t != FP2_ONE
    assert (t**TOY_R) == FP2_ONE

    w = weil_pairing(TOY_CURVE, TOY_R, p, q)
    assert w != FP2_ONE
    assert (w**TOY_R) == FP2_ONE


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")

