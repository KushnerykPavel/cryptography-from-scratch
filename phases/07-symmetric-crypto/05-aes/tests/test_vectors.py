import json
import os
import random
import sys
from pathlib import Path


THIS_DIR = Path(__file__).resolve().parent
CODE_DIR = (THIS_DIR / ".." / "code").resolve()
sys.path.insert(0, str(CODE_DIR))

import main as aes  # noqa: E402


def _hex_to_bytes(s: str) -> bytes:
    s = s.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return bytes.fromhex(s)


def test_vectors() -> None:
    vectors_path = THIS_DIR / "vectors.json"
    data = json.loads(vectors_path.read_text(encoding="utf-8"))
    vectors = data["vectors"]

    for v in vectors:
        op = v["op"]
        if op == "gf_mul":
            got = aes.gf_mul(int(v["a"]), int(v["b"]))
            assert got == int(v["expected"])
        elif op == "sub_bytes":
            state = aes.bytes_to_state(_hex_to_bytes(v["state"]))
            got = aes.state_to_bytes(aes.sub_bytes(state)).hex()
            assert got == v["expected"]
        elif op == "shift_rows":
            state = aes.bytes_to_state(_hex_to_bytes(v["state"]))
            got = aes.state_to_bytes(aes.shift_rows(state)).hex()
            assert got == v["expected"]
        elif op == "mix_columns":
            state = aes.bytes_to_state(_hex_to_bytes(v["state"]))
            got = aes.state_to_bytes(aes.mix_columns(state)).hex()
            assert got == v["expected"]
        elif op == "expand_key_round_key":
            rks = aes.expand_key(_hex_to_bytes(v["key"]))
            got = rks[int(v["round"])].hex()
            assert got == v["expected"]
        elif op == "aes_encrypt_block":
            key = _hex_to_bytes(v["key"])
            pt = _hex_to_bytes(v["plaintext"])
            got = aes.aes_encrypt_block(pt, key).hex()
            assert got == v["expected"]
        elif op == "aes_decrypt_block":
            key = _hex_to_bytes(v["key"])
            ct = _hex_to_bytes(v["ciphertext"])
            got = aes.aes_decrypt_block(ct, key).hex()
            assert got == v["expected"]
        else:
            raise ValueError(f"unknown vector op: {op}")


def test_properties() -> None:
    rng = random.Random(0)

    for _ in range(200):
        a = rng.randrange(256)
        b = rng.randrange(256)
        assert aes.gf_mul(a, b) == aes.gf_mul(b, a)
        assert aes.gf_mul(a, 0) == 0
        assert aes.gf_mul(a, 1) == (a & 0xFF)

    for _ in range(100):
        st = [rng.randrange(256) for _ in range(16)]
        assert aes.inv_shift_rows(aes.shift_rows(st)) == st
        assert aes.inv_sub_bytes(aes.sub_bytes(st)) == st
        assert aes.inv_mix_columns(aes.mix_columns(st)) == st

    for key_len in (16, 24, 32):
        for _ in range(50):
            key = bytes(rng.randrange(256) for _ in range(key_len))
            block = bytes(rng.randrange(256) for _ in range(16))
            ct = aes.aes_encrypt_block(block, key)
            pt = aes.aes_decrypt_block(ct, key)
            assert pt == block


def test_rejections() -> None:
    try:
        aes.bytes_to_state(b"")
        raise AssertionError("expected ValueError for short state")
    except ValueError:
        pass

    try:
        aes.expand_key(b"bad")
        raise AssertionError("expected ValueError for bad key length")
    except ValueError:
        pass

    try:
        aes.aes_encrypt_block(b"short", b"\x00" * 16)
        raise AssertionError("expected ValueError for bad block length")
    except ValueError:
        pass

    try:
        aes.xor_bytes(b"\x00", b"\x00\x00")
        raise AssertionError("expected ValueError for mismatched xor lengths")
    except ValueError:
        pass


if __name__ == "__main__":
    test_vectors()
    test_properties()
    test_rejections()
    print("all tests pass")
