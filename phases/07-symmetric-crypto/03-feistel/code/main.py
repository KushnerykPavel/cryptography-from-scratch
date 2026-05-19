"""
Feistel networks from scratch (educational).

What this file does:
- Implements a small Feistel network for fixed-size blocks using a PRF-like round function (HMAC-SHA256).
- Demonstrates encryption/decryption and how rounds affect diffusion (avalanche).

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hmac
import hashlib
from dataclasses import dataclass


class FeistelError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise FeistelError(message)


def int_to_bytes(x: int, length: int) -> bytes:
    _require(x >= 0, "x must be non-negative")
    _require(length >= 0, "length must be non-negative")
    return x.to_bytes(length, byteorder="big", signed=False)


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big", signed=False)


def split_block(block: int, block_bits: int) -> tuple[int, int]:
    _require(block_bits > 0, "block_bits must be positive")
    _require(block_bits % 2 == 0, "block_bits must be even")
    _require(0 <= block < (1 << block_bits), "block out of range for block_bits")
    half_bits = block_bits // 2
    right = block & ((1 << half_bits) - 1)
    left = block >> half_bits
    return left, right


def join_block(left: int, right: int, block_bits: int) -> int:
    _require(block_bits > 0, "block_bits must be positive")
    _require(block_bits % 2 == 0, "block_bits must be even")
    half_bits = block_bits // 2
    _require(0 <= left < (1 << half_bits), "left out of range for half_bits")
    _require(0 <= right < (1 << half_bits), "right out of range for half_bits")
    return (left << half_bits) | right


def derive_round_keys(master_key: bytes, rounds: int) -> list[bytes]:
    _require(isinstance(master_key, (bytes, bytearray)), "master_key must be bytes-like")
    _require(rounds > 0, "rounds must be positive")
    mk = bytes(master_key)
    out: list[bytes] = []
    for r in range(1, rounds + 1):
        msg = b"feistel-round-key" + r.to_bytes(4, "big")
        out.append(hmac.new(mk, msg, hashlib.sha256).digest())
    return out


def round_function(round_key: bytes, round_index: int, right: int, half_bits: int) -> int:
    _require(half_bits > 0, "half_bits must be positive")
    _require(0 <= right < (1 << half_bits), "right out of range for half_bits")
    _require(round_index >= 1, "round_index must be >= 1")

    out_len = (half_bits + 7) // 8
    msg = b"feistel-f" + round_index.to_bytes(4, "big") + int_to_bytes(right, out_len)
    digest = hmac.new(round_key, msg, hashlib.sha256).digest()
    x = bytes_to_int(digest[:out_len])
    return x & ((1 << half_bits) - 1)


def feistel_encrypt_block(block: int, block_bits: int, round_keys: list[bytes]) -> int:
    _require(len(round_keys) > 0, "need at least one round key")
    left, right = split_block(block, block_bits)
    half_bits = block_bits // 2
    for i, rk in enumerate(round_keys, start=1):
        f = round_function(rk, i, right, half_bits)
        left, right = right, left ^ f
    return join_block(left, right, block_bits)


def feistel_decrypt_block(block: int, block_bits: int, round_keys: list[bytes]) -> int:
    _require(len(round_keys) > 0, "need at least one round key")
    left, right = split_block(block, block_bits)
    half_bits = block_bits // 2
    for i, rk in enumerate(reversed(round_keys), start=1):
        round_index = len(round_keys) - i + 1
        f = round_function(rk, round_index, left, half_bits)
        left, right = right ^ f, left
    return join_block(left, right, block_bits)


def feistel_encrypt_bytes(block: bytes, round_keys: list[bytes]) -> bytes:
    _require(len(block) > 0, "block must be non-empty")
    _require(len(block) % 2 == 0, "block length must be even (split into halves)")
    block_bits = len(block) * 8
    x = bytes_to_int(block)
    y = feistel_encrypt_block(x, block_bits, round_keys)
    return int_to_bytes(y, len(block))


def feistel_decrypt_bytes(block: bytes, round_keys: list[bytes]) -> bytes:
    _require(len(block) > 0, "block must be non-empty")
    _require(len(block) % 2 == 0, "block length must be even (split into halves)")
    block_bits = len(block) * 8
    x = bytes_to_int(block)
    y = feistel_decrypt_block(x, block_bits, round_keys)
    return int_to_bytes(y, len(block))


def hamming_distance_bits(a: int, b: int, bits: int) -> int:
    _require(bits >= 0, "bits must be non-negative")
    _require(0 <= a < (1 << bits), "a out of range for bits")
    _require(0 <= b < (1 << bits), "b out of range for bits")
    return (a ^ b).bit_count()


@dataclass(frozen=True)
class DemoParams:
    master_key: bytes
    rounds: int
    block_bits: int
    plaintext: int


def _format_block(x: int, bits: int) -> str:
    width = (bits + 3) // 4
    return f"0x{x:0{width}x}"


def demo_step_1_split_join(params: DemoParams) -> None:
    print("=== Step 1: Split and join a block ===")
    left, right = split_block(params.plaintext, params.block_bits)
    half_bits = params.block_bits // 2
    print(f"block_bits={params.block_bits} half_bits={half_bits}")
    print(f"P = {_format_block(params.plaintext, params.block_bits)}")
    print(f"L = {_format_block(left, half_bits)}")
    print(f"R = {_format_block(right, half_bits)}")
    rejoined = join_block(left, right, params.block_bits)
    print(f"join(L,R) = {_format_block(rejoined, params.block_bits)}")
    print()


def demo_step_2_round_function(params: DemoParams) -> None:
    print("=== Step 2: A round function F ===")
    half_bits = params.block_bits // 2
    round_keys = derive_round_keys(params.master_key, params.rounds)
    _, right = split_block(params.plaintext, params.block_bits)
    f1 = round_function(round_keys[0], 1, right, half_bits)
    print(f"R0 = {_format_block(right, half_bits)}")
    print(f"F(K1, R0) = {_format_block(f1, half_bits)}")
    print()


def demo_step_3_encrypt_decrypt(params: DemoParams) -> None:
    print("=== Step 3: Encrypt and decrypt ===")
    round_keys = derive_round_keys(params.master_key, params.rounds)
    c = feistel_encrypt_block(params.plaintext, params.block_bits, round_keys)
    p2 = feistel_decrypt_block(c, params.block_bits, round_keys)
    print(f"rounds={params.rounds}")
    print(f"P = {_format_block(params.plaintext, params.block_bits)}")
    print(f"C = {_format_block(c, params.block_bits)}")
    print(f"D(C) = {_format_block(p2, params.block_bits)}")
    print(f"roundtrip_ok={p2 == params.plaintext}")
    print()


def demo_step_4_diffusion(params: DemoParams) -> None:
    print("=== Step 4: Diffusion vs number of rounds ===")
    bit_to_flip = params.block_bits // 3
    flipped = params.plaintext ^ (1 << bit_to_flip)
    print(f"P  = {_format_block(params.plaintext, params.block_bits)}")
    print(f"P' = {_format_block(flipped, params.block_bits)} (flip bit {bit_to_flip})")
    for rounds in (1, 2, 4, 8, params.rounds):
        if rounds <= 0:
            continue
        round_keys = derive_round_keys(params.master_key, rounds)
        c1 = feistel_encrypt_block(params.plaintext, params.block_bits, round_keys)
        c2 = feistel_encrypt_block(flipped, params.block_bits, round_keys)
        hd = hamming_distance_bits(c1, c2, params.block_bits)
        print(f"rounds={rounds:>2}  C={_format_block(c1, params.block_bits)}  hd={hd}/{params.block_bits}")
    print()


def main() -> None:
    params = DemoParams(
        master_key=b"course-demo-key",
        rounds=12,
        block_bits=32,
        plaintext=0x1234_5678,
    )
    demo_step_1_split_join(params)
    demo_step_2_round_function(params)
    demo_step_3_encrypt_decrypt(params)
    demo_step_4_diffusion(params)


if __name__ == "__main__":
    main()
