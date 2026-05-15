import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    SECP256K1,
    SECP256K1_G,
    SECP256K1_N,
    Point,
    lift_x_secp256k1,
    parse_public_key,
    scalar_mul,
    serialize_compressed,
    serialize_uncompressed,
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
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        if op == "scalar_mul_G":
            got = point_to_json(scalar_mul(SECP256K1, v["k"], SECP256K1_G))
            assert got == v["expected"]
            continue

        if op == "scalar_mul_nG_is_infinity":
            got = scalar_mul(SECP256K1, SECP256K1_N, SECP256K1_G)
            assert got is None
            continue

        if op == "encode_compressed":
            point = parse_point(v["point"])
            got = serialize_compressed(point).hex()
            assert got == v["expected_hex"]
            continue

        if op == "encode_uncompressed":
            point = parse_point(v["point"])
            got = serialize_uncompressed(point).hex()
            assert got == v["expected_hex"]
            continue

        if op == "decode_pubkey":
            got = parse_public_key(bytes.fromhex(v["hex"]))
            assert point_to_json(got) == v["expected"]
            continue

        if op == "lift_x":
            got = lift_x_secp256k1(v["x"], v["y_parity"])
            assert point_to_json(got) == v["expected"]
            continue

        raise AssertionError(f"unknown op {op}")

