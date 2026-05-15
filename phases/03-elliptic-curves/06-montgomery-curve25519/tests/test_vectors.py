import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    decode_u_coordinate,
    is_all_zero,
    x25519,
    x25519_basepoint,
    x25519_iterate,
)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        if op == "x25519":
            scalar = bytes.fromhex(v["scalar_hex"])
            u = bytes.fromhex(v["u_hex"])
            got = x25519(scalar, u).hex()
            assert got == v["expected_hex"], f"x25519 failed: got {got}, expected {v['expected_hex']}"
            continue

        if op == "x25519_basepoint":
            scalar = bytes.fromhex(v["scalar_hex"])
            got = x25519_basepoint(scalar).hex()
            assert got == v["expected_hex"], f"x25519_basepoint failed: got {got}, expected {v['expected_hex']}"
            continue

        if op == "iterate":
            got = x25519_iterate(v["n"]).hex()
            assert got == v["expected_hex"], f"iterate({v['n']}) failed: got {got}, expected {v['expected_hex']}"
            continue

        raise AssertionError(f"unknown op {op}")


def test_decode_masks_top_bit():
    u = bytes.fromhex("00" * 31 + "80")
    assert decode_u_coordinate(u) == decode_u_coordinate(bytes.fromhex("00" * 32))


def test_all_zero_helper():
    assert is_all_zero(b"")
    assert is_all_zero(b"\x00" * 32)
    assert not is_all_zero(b"\x01" + b"\x00" * 31)


if __name__ == "__main__":
    test_vectors()
    test_decode_masks_top_bit()
    test_all_zero_helper()
    print("all vectors pass")

