import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    ED25519_L,
    Point,
    ed25519_add_affine,
    ed25519_clear_cofactor,
    ed25519_decode,
    ed25519_encode,
    ed25519_ext_add,
    ed25519_from_ext,
    ed25519_identity,
    ed25519_is_in_prime_subgroup,
    ed25519_scalar_mul,
    ed25519_to_ext,
)


def _pt_from_xy(v):
    return Point(v["x"], v["y"])


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        if op == "decode":
            got = ed25519_decode(bytes.fromhex(v["enc_hex"]))
            exp = _pt_from_xy(v["expected"])
            assert got == exp, f"decode failed: got {got}, expected {exp}"
            continue

        if op == "encode":
            got = ed25519_encode(_pt_from_xy(v["point"])).hex()
            assert got == v["expected_hex"], f"encode failed: got {got}, expected {v['expected_hex']}"
            continue

        if op == "add":
            p = ed25519_decode(bytes.fromhex(v["p_enc_hex"]))
            q = ed25519_decode(bytes.fromhex(v["q_enc_hex"]))
            r_aff = ed25519_add_affine(p, q)
            r_ext = ed25519_from_ext(ed25519_ext_add(ed25519_to_ext(p), ed25519_to_ext(q)))
            assert (
                ed25519_encode(r_aff).hex() == v["expected_enc_hex"]
            ), f"add(affine) failed: got {ed25519_encode(r_aff).hex()}, expected {v['expected_enc_hex']}"
            assert (
                ed25519_encode(r_ext).hex() == v["expected_enc_hex"]
            ), f"add(ext) failed: got {ed25519_encode(r_ext).hex()}, expected {v['expected_enc_hex']}"
            continue

        if op == "scalar_mul":
            p = ed25519_decode(bytes.fromhex(v["point_enc_hex"]))
            k = v["k"]
            got = ed25519_encode(ed25519_from_ext(ed25519_scalar_mul(k, ed25519_to_ext(p)))).hex()
            assert got == v["expected_enc_hex"], f"scalar_mul failed: got {got}, expected {v['expected_enc_hex']}"
            continue

        if op == "is_in_prime_subgroup":
            p = ed25519_decode(bytes.fromhex(v["point_enc_hex"]))
            got = ed25519_is_in_prime_subgroup(p)
            assert got == v["expected"], f"is_in_prime_subgroup failed: got {got}, expected {v['expected']}"
            continue

        if op == "clear_cofactor":
            p = ed25519_decode(bytes.fromhex(v["point_enc_hex"]))
            got = ed25519_encode(ed25519_clear_cofactor(p)).hex()
            assert got == v["expected_enc_hex"], f"clear_cofactor failed: got {got}, expected {v['expected_enc_hex']}"
            continue

        raise AssertionError(f"unknown op {op}")

    b = ed25519_decode(bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666"))
    assert ed25519_from_ext(ed25519_scalar_mul(ED25519_L, ed25519_to_ext(b))) == ed25519_identity()


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")

