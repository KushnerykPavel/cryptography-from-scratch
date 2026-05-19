"""Test vectors + properties for the stream-ciphers lesson.

Run with pytest:
  pytest -q

Run directly:
  python3 tests/test_vectors.py
"""

from __future__ import annotations

import json
import os
import secrets
import sys
from typing import Any


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

from main import (  # type: ignore  # noqa: E402
    chacha20_block,
    chacha20_decrypt,
    chacha20_encrypt,
    chacha20_keystream,
    quarter_round,
    rotl32,
    xor_bytes,
)


def _parse_int(x: Any) -> int:
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        return int(x, 0)
    raise TypeError("expected int or str")


def _parse_bytes_hex(x: Any) -> bytes:
    if not isinstance(x, str):
        raise TypeError("expected hex string")
    return bytes.fromhex(x)


def _load_vectors() -> dict[str, Any]:
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        return json.load(f)


def test_vectors() -> None:
    data = _load_vectors()
    vectors = data["vectors"]

    for v in vectors:
        op = v["op"]
        if op == "rotl32":
            got = rotl32(_parse_int(v["x"]), _parse_int(v["n"]))
            assert got == _parse_int(v["expected"])
        elif op == "quarter_round":
            got = quarter_round(_parse_int(v["a"]), _parse_int(v["b"]), _parse_int(v["c"]), _parse_int(v["d"]))
            exp = v["expected"]
            assert got == (
                _parse_int(exp["a"]),
                _parse_int(exp["b"]),
                _parse_int(exp["c"]),
                _parse_int(exp["d"]),
            )
        elif op == "chacha20_block":
            got = chacha20_block(
                _parse_bytes_hex(v["key_hex"]),
                _parse_int(v["counter"]),
                _parse_bytes_hex(v["nonce_hex"]),
            )
            assert got == _parse_bytes_hex(v["expected_hex"])
        elif op == "chacha20_keystream":
            got = chacha20_keystream(
                _parse_bytes_hex(v["key_hex"]),
                _parse_bytes_hex(v["nonce_hex"]),
                _parse_int(v["initial_counter"]),
                _parse_int(v["length"]),
            )
            assert got == _parse_bytes_hex(v["expected_hex"])
        elif op == "chacha20_encrypt":
            got = chacha20_encrypt(
                _parse_bytes_hex(v["plaintext_hex"]),
                _parse_bytes_hex(v["key_hex"]),
                _parse_bytes_hex(v["nonce_hex"]),
                _parse_int(v["initial_counter"]),
            )
            assert got == _parse_bytes_hex(v["expected_hex"])
        else:
            raise ValueError(f"unknown op: {op}")


def test_encrypt_roundtrip_random() -> None:
    for length in [0, 1, 2, 7, 31, 32, 63, 64, 65, 127, 128, 255, 256]:
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        pt = secrets.token_bytes(length)
        ct = chacha20_encrypt(pt, key, nonce, initial_counter=1)
        got = chacha20_decrypt(ct, key, nonce, initial_counter=1)
        assert got == pt


def test_nonce_reuse_leaks_xor_relation() -> None:
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    p1 = b"A" * 64
    p2 = b"B" * 64
    c1 = chacha20_encrypt(p1, key, nonce, initial_counter=1)
    c2 = chacha20_encrypt(p2, key, nonce, initial_counter=1)
    assert xor_bytes(c1, c2) == xor_bytes(p1, p2)


def test_reject_invalid_lengths() -> None:
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)

    try:
        chacha20_block(key=b"short", counter=1, nonce=nonce)
        raise AssertionError("expected ValueError for short key")
    except ValueError:
        pass

    try:
        chacha20_block(key=key, counter=1, nonce=b"short")
        raise AssertionError("expected ValueError for short nonce")
    except ValueError:
        pass

    try:
        chacha20_keystream(key, nonce, initial_counter=-1, length=10)
        raise AssertionError("expected ValueError for negative counter")
    except ValueError:
        pass

    try:
        chacha20_keystream(key, nonce, initial_counter=1, length=-1)
        raise AssertionError("expected ValueError for negative length")
    except ValueError:
        pass


if __name__ == "__main__":
    test_vectors()
    test_encrypt_roundtrip_random()
    test_nonce_reuse_leaks_xor_relation()
    test_reject_invalid_lengths()
    print("all tests pass")

