import json
import os
import random
import sys


THIS_DIR = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as feistel  # noqa: E402


def _load_vectors():
    path = os.path.join(THIS_DIR, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    return doc["vectors"]


def _derive(master_key_hex: str, rounds: int):
    return feistel.derive_round_keys(bytes.fromhex(master_key_hex), rounds)


def test_vectors():
    vectors = _load_vectors()
    for v in vectors:
        op = v["op"]
        inputs = v["inputs"]
        expected = v["expected"]

        if op == "split_block":
            left, right = feistel.split_block(inputs["block"], inputs["block_bits"])
            assert {"left": left, "right": right} == expected
        elif op == "join_block":
            out = feistel.join_block(inputs["left"], inputs["right"], inputs["block_bits"])
            assert out == expected
        elif op == "derive_round_keys":
            rks = _derive(inputs["master_key_hex"], inputs["rounds"])
            assert [rk.hex() for rk in rks] == expected["round_keys_hex"]
        elif op == "round_function":
            out = feistel.round_function(
                bytes.fromhex(inputs["round_key_hex"]),
                inputs["round_index"],
                inputs["right"],
                inputs["half_bits"],
            )
            assert out == expected
        elif op == "feistel_encrypt_block":
            rks = _derive(inputs["master_key_hex"], inputs["rounds"])
            out = feistel.feistel_encrypt_block(inputs["block"], inputs["block_bits"], rks)
            assert out == expected
        elif op == "feistel_decrypt_block":
            rks = _derive(inputs["master_key_hex"], inputs["rounds"])
            out = feistel.feistel_decrypt_block(inputs["block"], inputs["block_bits"], rks)
            assert out == expected
        elif op == "feistel_encrypt_bytes":
            rks = _derive(inputs["master_key_hex"], inputs["rounds"])
            out = feistel.feistel_encrypt_bytes(bytes.fromhex(inputs["block_hex"]), rks)
            assert out.hex() == expected
        elif op == "feistel_decrypt_bytes":
            rks = _derive(inputs["master_key_hex"], inputs["rounds"])
            out = feistel.feistel_decrypt_bytes(bytes.fromhex(inputs["block_hex"]), rks)
            assert out.hex() == expected
        else:
            raise AssertionError(f"unknown op: {op}")


def test_roundtrip_random_blocks():
    rng = random.Random(0)
    master_key = b"property-test-key"
    for block_bits in (16, 32, 64):
        rks = feistel.derive_round_keys(master_key, 10)
        limit = 1 << block_bits
        for _ in range(200):
            p = rng.randrange(0, limit)
            c = feistel.feistel_encrypt_block(p, block_bits, rks)
            p2 = feistel.feistel_decrypt_block(c, block_bits, rks)
            assert p2 == p


def test_encrypt_is_permutation_for_small_block():
    block_bits = 8
    rks = feistel.derive_round_keys(b"perm-test-key", 6)
    outs = set()
    for p in range(1 << block_bits):
        c = feistel.feistel_encrypt_block(p, block_bits, rks)
        assert 0 <= c < (1 << block_bits)
        outs.add(c)
    assert len(outs) == 1 << block_bits


def test_rejects_invalid_inputs():
    rks = feistel.derive_round_keys(b"k", 4)

    try:
        feistel.split_block(0, 7)
        raise AssertionError("expected FeistelError for odd block_bits")
    except feistel.FeistelError:
        pass

    try:
        feistel.split_block(1 << 16, 16)
        raise AssertionError("expected FeistelError for out-of-range block")
    except feistel.FeistelError:
        pass

    try:
        feistel.join_block(1 << 8, 0, 16)
        raise AssertionError("expected FeistelError for out-of-range left")
    except feistel.FeistelError:
        pass

    try:
        feistel.feistel_encrypt_bytes(b"\x00\x01\x02", rks)
        raise AssertionError("expected FeistelError for odd-length byte block")
    except feistel.FeistelError:
        pass


if __name__ == "__main__":
    test_vectors()
    test_roundtrip_random_blocks()
    test_encrypt_is_permutation_for_small_block()
    test_rejects_invalid_inputs()
    print("all tests pass")

