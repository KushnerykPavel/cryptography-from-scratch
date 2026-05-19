import json
import os
import random
import sys


THIS_DIR = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as des  # noqa: E402


def _load_vectors():
    path = os.path.join(THIS_DIR, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    return doc["vectors"]


def test_vectors():
    vectors = _load_vectors()
    for v in vectors:
        op = v["op"]
        inputs = v["inputs"]
        expected = v["expected"]

        if op == "des_encrypt_block":
            out = des.des_encrypt_block(bytes.fromhex(inputs["block_hex"]), bytes.fromhex(inputs["key_hex"]))
            assert out.hex().upper() == expected
        elif op == "des_decrypt_block":
            out = des.des_decrypt_block(bytes.fromhex(inputs["block_hex"]), bytes.fromhex(inputs["key_hex"]))
            assert out.hex().upper() == expected
        elif op == "tdea_encrypt_block":
            out = des.tdea_encrypt_block(
                bytes.fromhex(inputs["block_hex"]),
                bytes.fromhex(inputs["k1_hex"]),
                bytes.fromhex(inputs["k2_hex"]),
                bytes.fromhex(inputs["k3_hex"]),
            )
            assert out.hex().upper() == expected
        elif op == "tdea_decrypt_block":
            out = des.tdea_decrypt_block(
                bytes.fromhex(inputs["block_hex"]),
                bytes.fromhex(inputs["k1_hex"]),
                bytes.fromhex(inputs["k2_hex"]),
                bytes.fromhex(inputs["k3_hex"]),
            )
            assert out.hex().upper() == expected
        else:
            raise AssertionError(f"unknown op: {op}")


def _randbytes(rng: random.Random, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        out.extend(rng.getrandbits(32).to_bytes(4, "big"))
    return bytes(out[:n])


def test_des_roundtrip_random_blocks():
    rng = random.Random(0)
    for _ in range(200):
        key = _randbytes(rng, 8)
        block = _randbytes(rng, 8)
        c = des.des_encrypt_block(block, key)
        p2 = des.des_decrypt_block(c, key)
        assert p2 == block


def test_tdea_roundtrip_random_blocks():
    rng = random.Random(1)
    for _ in range(200):
        k1 = _randbytes(rng, 8)
        k2 = _randbytes(rng, 8)
        k3 = _randbytes(rng, 8)
        if k1 == k2 == k3:
            k3 = bytes([k3[0] ^ 0x01]) + k3[1:]
        block = _randbytes(rng, 8)
        c = des.tdea_encrypt_block(block, k1, k2, k3)
        p2 = des.tdea_decrypt_block(c, k1, k2, k3)
        assert p2 == block


def test_tdea_degenerates_to_des_when_k1_k2_k3_all_same_is_rejected():
    key = bytes.fromhex("0101010101010101")
    block = b"\x00" * 8
    try:
        des.tdea_encrypt_block(block, key, key, key)
        raise AssertionError("expected DesError for all-identical TDEA keys")
    except des.DesError:
        pass


def test_rejects_invalid_inputs():
    try:
        des.des_encrypt_block(b"\x00" * 7, b"\x00" * 8)
        raise AssertionError("expected DesError for invalid block length")
    except des.DesError:
        pass

    try:
        des.des_encrypt_block(b"\x00" * 8, b"\x00" * 7)
        raise AssertionError("expected DesError for invalid key length")
    except des.DesError:
        pass


if __name__ == "__main__":
    test_vectors()
    test_des_roundtrip_random_blocks()
    test_tdea_roundtrip_random_blocks()
    test_tdea_degenerates_to_des_when_k1_k2_k3_all_same_is_rejected()
    test_rejects_invalid_inputs()
    print("all tests pass")

