import json
import os
import sys


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as kyber  # noqa: E402


VECTORS_PATH = os.path.join(HERE, "vectors.json")


def _load_vectors():
    with open(VECTORS_PATH, "r", encoding="utf-8") as f:
        doc = json.load(f)
    if "vectors" not in doc or not isinstance(doc["vectors"], list):
        raise ValueError("vectors.json must contain a top-level 'vectors' list")
    return doc


def _hex_to_bytes(s: str) -> bytes:
    if not isinstance(s, str):
        raise TypeError("expected hex string")
    return bytes.fromhex(s)


def _run_vector(vec):
    op = vec["op"]

    if op == "poly_mul_negacyclic":
        return kyber.poly_mul_negacyclic(vec["a"], vec["b"])

    if op == "sample_uniform_poly":
        seed = _hex_to_bytes(vec["seed_hex"])
        return kyber.sample_uniform_poly(seed, int(vec["nonce"]))

    if op == "sample_cbd_poly":
        seed = _hex_to_bytes(vec["seed_hex"])
        return kyber.sample_cbd_poly(seed, int(vec["nonce"]))

    if op == "pke_encrypt_deterministic":
        master_seed = _hex_to_bytes(vec["master_seed_hex"])
        coins = _hex_to_bytes(vec["coins_hex"])
        m = int(vec["m"])
        pk, sk = kyber.keygen(master_seed)
        ct = kyber.encrypt(pk, m=m, coins=coins)
        return {
            "pk_seed_a": pk.seed_a.hex(),
            "pk_t": pk.t,
            "sk_s": sk.s,
            "ct_u": ct.u,
            "ct_v": ct.v,
            "decrypted": kyber.decrypt(sk, ct),
        }

    if op == "pack_bits_le":
        packed = kyber.pack_bits_le(vec["values"], bits=int(vec["bits"]))
        return packed.hex()

    if op == "compress_decompress_poly":
        d = int(vec["d"])
        comp = kyber.compress_poly(vec["poly"], d=d)
        return kyber.decompress_poly(comp, d=d)

    raise ValueError(f"unknown op: {op}")


def test_vectors():
    doc = _load_vectors()
    for i, vec in enumerate(doc["vectors"]):
        got = _run_vector(vec)
        if vec["op"] == "pack_bits_le":
            expected = vec["expected_hex"]
        else:
            expected = vec["expected"]
        assert got == expected, f"vector {i} failed: {vec['op']}"


def test_pack_unpack_roundtrip():
    values = [0, 1, 2, 3, 1023, 17, 511, 7]
    bits = 10
    packed = kyber.pack_bits_le(values, bits=bits)
    unpacked = kyber.unpack_bits_le(packed, count=len(values), bits=bits)
    assert unpacked == [v & ((1 << bits) - 1) for v in values]


def test_poly_mul_distributive():
    seed = b"distrib-test-seed"
    a = kyber.sample_uniform_poly(seed, 0)
    b = kyber.sample_uniform_poly(seed, 1)
    c = kyber.sample_uniform_poly(seed, 2)
    left = kyber.poly_mul_negacyclic(a, kyber.poly_add(b, c))
    right = kyber.poly_add(kyber.poly_mul_negacyclic(a, b), kyber.poly_mul_negacyclic(a, c))
    assert left == right


def test_pke_roundtrip_multiple_messages():
    pk, sk = kyber.keygen(b"roundtrip-seed-0000000000000000")
    coins = b"coins-0000000000000000000000000000"
    for m in [0, 1, 2, 7, 13, 42, 127, 128, 255]:
        ct = kyber.encrypt(pk, m=m, coins=coins + bytes([m]))
        assert kyber.decrypt(sk, ct) == m


def test_rejects_wrong_poly_length():
    try:
        kyber.poly_mul_negacyclic([1, 2], [3, 4])
    except ValueError:
        return
    raise AssertionError("expected ValueError for wrong polynomial length")


def test_unpack_rejects_short_buffer():
    packed = kyber.pack_bits_le([1, 2, 3], bits=10)
    try:
        kyber.unpack_bits_le(packed[:-1], count=3, bits=10)
    except ValueError:
        return
    raise AssertionError("expected ValueError for truncated buffer")


def _run_all():
    test_vectors()
    test_pack_unpack_roundtrip()
    test_poly_mul_distributive()
    test_pke_roundtrip_multiple_messages()
    test_rejects_wrong_poly_length()
    test_unpack_rejects_short_buffer()
    print("all tests pass")


if __name__ == "__main__":
    _run_all()
