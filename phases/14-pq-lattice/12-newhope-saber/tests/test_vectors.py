import json
import os
import sys


THIS_DIR = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as nh  # noqa: E402


def _load_vectors():
    path = os.path.join(THIS_DIR, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_vectors():
    data = _load_vectors()
    vectors = data["vectors"]

    for v in vectors:
        op = v["op"]
        inputs = v["inputs"]
        expected = v["expected"]

        if op == "poly_mul_negacyclic":
            got = nh.poly_mul_negacyclic(inputs["a"], inputs["b"], inputs["q"])
            assert got == expected
        elif op == "sample_small_poly_cbd":
            seed = bytes.fromhex(inputs["seed"])
            got = nh.sample_small_poly_cbd(seed, inputs["n"], inputs["eta"], domain=inputs["domain"].encode("utf-8"))
            assert got == expected
        elif op == "poly_round_to_p":
            got = nh.poly_round_to_p(inputs["poly"], inputs["q"], inputs["p"])
            assert got == expected
        elif op == "poly_lift_from_p":
            got = nh.poly_lift_from_p(inputs["poly_p"], inputs["q"], inputs["p"])
            assert got == expected
        elif op == "encode_bits_as_poly":
            got = nh.encode_bits_as_poly(inputs["bits"], inputs["q"])
            assert got == expected
        elif op == "decode_poly_to_bits":
            got = nh.decode_poly_to_bits(inputs["poly"], inputs["q"])
            assert got == expected
        elif op == "rlwe_encrypt_decrypt":
            pk, sk = nh.rlwe_keygen(inputs["seed_a"].encode("utf-8"), inputs["seed_s"].encode("utf-8"))
            ct = nh.rlwe_encrypt(pk, inputs["msg_bits"], inputs["seed_r"].encode("utf-8"))
            dec = nh.rlwe_decrypt(sk, ct)
            assert ct[0] == expected["u"]
            assert ct[1] == expected["v"]
            assert dec == expected["dec_bits"]
        elif op == "lwr_encrypt_decrypt":
            pk, sk = nh.lwr_keygen(inputs["seed_a"].encode("utf-8"), inputs["seed_s"].encode("utf-8"))
            ct = nh.lwr_encrypt(pk, inputs["msg_bits"], inputs["seed_r"].encode("utf-8"))
            dec = nh.lwr_decrypt(sk, ct)
            assert ct[0] == expected["u"]
            assert ct[1] == expected["v_p"]
            assert dec == expected["dec_bits"]
        else:
            raise AssertionError(f"unknown op: {op}")


def test_cbd_range():
    poly = nh.sample_small_poly_cbd(b"range-test", n=nh.TOY_N, eta=nh.TOY_ETA, domain=b"range")
    assert all(-nh.TOY_ETA <= x <= nh.TOY_ETA for x in poly)


def test_negacyclic_distributive_law():
    q = nh.NEWHOPE_Q
    n = nh.TOY_N

    a = nh.uniform_poly(b"a", n=n, q=q, domain=b"prop")
    b = nh.uniform_poly(b"b", n=n, q=q, domain=b"prop")
    c = nh.uniform_poly(b"c", n=n, q=q, domain=b"prop")

    left = nh.poly_mul_negacyclic(a, nh.poly_add(b, c, q), q)
    right = nh.poly_add(nh.poly_mul_negacyclic(a, b, q), nh.poly_mul_negacyclic(a, c, q), q)
    assert left == right


def test_roundtrip_round_then_lift():
    q = nh.SABER_Q
    p = nh.SABER_P
    n = nh.TOY_N

    x = nh.uniform_poly(b"x", n=n, q=q, domain=b"roundtrip")
    x_p = nh.poly_round_to_p(x, q=q, p=p)
    x_lift = nh.poly_lift_from_p(x_p, q=q, p=p)
    x_p2 = nh.poly_round_to_p(x_lift, q=q, p=p)
    assert x_p2 == x_p


def test_rlwe_roundtrip_varied_messages():
    pk, sk = nh.rlwe_keygen(b"A", b"S")
    for i in range(4):
        msg = [((j + i) % 2) for j in range(nh.TOY_N)]
        ct = nh.rlwe_encrypt(pk, msg, seed_r=f"R{i}".encode("utf-8"))
        dec = nh.rlwe_decrypt(sk, ct)
        assert dec == msg


def test_encode_rejects_non_bits():
    try:
        nh.encode_bits_as_poly([0, 2, 1], nh.NEWHOPE_Q)
        assert False, "expected ValueError"
    except ValueError:
        pass


if __name__ == "__main__":
    try:
        import pytest  # type: ignore

        rc = pytest.main([__file__])
        if rc != 0:
            raise SystemExit(rc)
    except ImportError:
        test_vectors()
        test_cbd_range()
        test_negacyclic_distributive_law()
        test_roundtrip_round_then_lift()
        test_rlwe_roundtrip_varied_messages()
        test_encode_rejects_non_bits()

    print("all tests pass")

