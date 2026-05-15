import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    P256_P,
    Point,
    encode_to_curve_p256_xmd_sha256_sswu,
    hash_to_curve_p256_xmd_sha256_sswu,
    hash_to_field_fp,
    map_to_curve_simple_swu_p256,
)


def _hex_to_int(h: str) -> int:
    return int(h, 16)


def _assert_point(point: Point, expected: dict) -> None:
    assert point.x == _hex_to_int(expected["x"])
    assert point.y == _hex_to_int(expected["y"])

def _build_msg(v: dict) -> bytes:
    kind = v.get("msg_kind")
    if kind == "q128":
        return b"q128_" + (b"q" * 128)
    if kind == "a512":
        return b"a512_" + (b"a" * 512)
    if kind is not None:
        raise ValueError(f"unknown msg_kind {kind}")
    return v.get("msg", "").encode("ascii")


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]
        msg = _build_msg(v)
        dst = v["dst"].encode("ascii")

        if op == "p256_ro":
            got_u = hash_to_field_fp(msg, 2, dst, p=P256_P, k=128)
            assert got_u[0] == _hex_to_int(v["u_hex"][0])
            assert got_u[1] == _hex_to_int(v["u_hex"][1])

            q0 = map_to_curve_simple_swu_p256(got_u[0])
            q1 = map_to_curve_simple_swu_p256(got_u[1])
            _assert_point(q0, v["q0_hex"])
            _assert_point(q1, v["q1_hex"])

            p = hash_to_curve_p256_xmd_sha256_sswu(msg, dst)
            _assert_point(p, v["p_hex"])
            continue

        if op == "p256_nu":
            got_u = hash_to_field_fp(msg, 1, dst, p=P256_P, k=128)
            assert got_u[0] == _hex_to_int(v["u_hex"][0])

            q = map_to_curve_simple_swu_p256(got_u[0])
            p = encode_to_curve_p256_xmd_sha256_sswu(msg, dst)
            assert (q.x, q.y) == (p.x, p.y)
            _assert_point(p, v["p_hex"])
            continue

        raise AssertionError(f"unknown op {op}")


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
