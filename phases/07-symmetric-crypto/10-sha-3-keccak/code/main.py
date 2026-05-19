"""
Educational SHA-3 / Keccak implementation (stdlib-only).

What this file does:
- Implements the Keccak-f[1600] permutation.
- Builds a sponge construction with the SHA-3 / SHAKE domain separators.
- Exposes SHA3-256, SHA3-512, SHAKE128, SHAKE256 helpers.
- Demonstrates correctness by comparing outputs to Python's hashlib.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


MASK64 = (1 << 64) - 1

KECCAKF_ROUNDS = 24

KECCAKF_ROTC = [
    1,
    3,
    6,
    10,
    15,
    21,
    28,
    36,
    45,
    55,
    2,
    14,
    27,
    41,
    56,
    8,
    25,
    43,
    62,
    18,
    39,
    61,
    20,
    44,
]

KECCAKF_PILN = [
    10,
    7,
    11,
    17,
    18,
    3,
    5,
    16,
    8,
    21,
    24,
    4,
    15,
    23,
    19,
    13,
    12,
    2,
    20,
    14,
    22,
    9,
    6,
    1,
]

KECCAKF_RNDC = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
]


def rol64(x: int, shift: int) -> int:
    shift &= 63
    x &= MASK64
    if shift == 0:
        return x
    return ((x << shift) | (x >> (64 - shift))) & MASK64


def keccak_f1600(lanes: list[int]) -> list[int]:
    if len(lanes) != 25:
        raise ValueError("state must have 25 lanes")

    a = [x & MASK64 for x in lanes]

    for round_index in range(KECCAKF_ROUNDS):
        c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20]
        c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21]
        c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22]
        c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23]
        c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24]

        d0 = c4 ^ rol64(c1, 1)
        d1 = c0 ^ rol64(c2, 1)
        d2 = c1 ^ rol64(c3, 1)
        d3 = c2 ^ rol64(c4, 1)
        d4 = c3 ^ rol64(c0, 1)

        a[0] ^= d0
        a[5] ^= d0
        a[10] ^= d0
        a[15] ^= d0
        a[20] ^= d0

        a[1] ^= d1
        a[6] ^= d1
        a[11] ^= d1
        a[16] ^= d1
        a[21] ^= d1

        a[2] ^= d2
        a[7] ^= d2
        a[12] ^= d2
        a[17] ^= d2
        a[22] ^= d2

        a[3] ^= d3
        a[8] ^= d3
        a[13] ^= d3
        a[18] ^= d3
        a[23] ^= d3

        a[4] ^= d4
        a[9] ^= d4
        a[14] ^= d4
        a[19] ^= d4
        a[24] ^= d4

        t = a[1]
        for i in range(24):
            j = KECCAKF_PILN[i]
            a[j], t = rol64(t, KECCAKF_ROTC[i]), a[j]

        for y in range(5):
            row0 = a[y * 5 + 0]
            row1 = a[y * 5 + 1]
            row2 = a[y * 5 + 2]
            row3 = a[y * 5 + 3]
            row4 = a[y * 5 + 4]
            a[y * 5 + 0] ^= (~row1 & MASK64) & row2
            a[y * 5 + 1] ^= (~row2 & MASK64) & row3
            a[y * 5 + 2] ^= (~row3 & MASK64) & row4
            a[y * 5 + 3] ^= (~row4 & MASK64) & row0
            a[y * 5 + 4] ^= (~row0 & MASK64) & row1

        a[0] ^= KECCAKF_RNDC[round_index]

    return [x & MASK64 for x in a]


def keccak_multirate_pad(rate_bytes: int, message: bytes, delimited_suffix: int) -> bytes:
    if rate_bytes <= 0:
        raise ValueError("rate_bytes must be positive")
    if not (0 <= delimited_suffix <= 0xFF):
        raise ValueError("delimited_suffix must be a byte")

    padded = bytearray(message)
    pad_len = rate_bytes - (len(padded) % rate_bytes)
    padded.extend(b"\x00" * pad_len)
    padded[len(message)] ^= delimited_suffix
    padded[-1] ^= 0x80
    return bytes(padded)


def keccak_sponge(
    *,
    rate_bytes: int,
    message: bytes,
    delimited_suffix: int,
    output_len: int,
) -> bytes:
    if output_len < 0:
        raise ValueError("output_len must be non-negative")
    if rate_bytes % 8 != 0:
        raise ValueError("this educational implementation requires rate_bytes % 8 == 0")

    lanes_in_rate = rate_bytes // 8
    state = [0] * 25

    padded = keccak_multirate_pad(rate_bytes, message, delimited_suffix)
    for offset in range(0, len(padded), rate_bytes):
        block = padded[offset : offset + rate_bytes]
        for i in range(lanes_in_rate):
            state[i] ^= int.from_bytes(block[8 * i : 8 * i + 8], "little")
        state = keccak_f1600(state)

    out = bytearray()
    while len(out) < output_len:
        chunk = b"".join(state[i].to_bytes(8, "little") for i in range(lanes_in_rate))
        out.extend(chunk[: min(rate_bytes, output_len - len(out))])
        if len(out) < output_len:
            state = keccak_f1600(state)
    return bytes(out)


def sha3_256(message: bytes) -> bytes:
    return keccak_sponge(rate_bytes=136, message=message, delimited_suffix=0x06, output_len=32)


def sha3_512(message: bytes) -> bytes:
    return keccak_sponge(rate_bytes=72, message=message, delimited_suffix=0x06, output_len=64)


def shake128(message: bytes, output_len: int) -> bytes:
    return keccak_sponge(rate_bytes=168, message=message, delimited_suffix=0x1F, output_len=output_len)


def shake256(message: bytes, output_len: int) -> bytes:
    return keccak_sponge(rate_bytes=136, message=message, delimited_suffix=0x1F, output_len=output_len)


@dataclass(frozen=True)
class DemoCase:
    name: str
    message: bytes


def _print_hex(label: str, blob: bytes) -> None:
    print(f"{label}: {blob.hex()}")


def main() -> None:
    cases = [
        DemoCase(name="empty", message=b""),
        DemoCase(name="abc", message=b"abc"),
        DemoCase(name="quick-brown-fox", message=b"The quick brown fox jumps over the lazy dog"),
    ]

    print("=== Step 1: State & Lanes ===")
    print("Keccak state is 5×5 lanes of 64 bits (1600 bits total). We store it as 25 little-endian uint64 lanes.")

    print("\n=== Step 2: Keccak-f[1600] Permutation ===")
    state0 = [0] * 25
    state1 = keccak_f1600(state0)
    print(f"Permutation on all-zero state produces lane[0]={state1[0]:016x} (not a hash, just a sanity signal).")

    print("\n=== Step 3: Sponge + Padding ===")
    padded = keccak_multirate_pad(136, b"", 0x06)
    print(f"SHA3-256 padding turns empty message into {len(padded)} bytes (one full rate block).")

    print("\n=== Step 4: SHA3-256 / SHA3-512 ===")
    for c in cases:
        print(f"\nCase: {c.name!r}")
        _print_hex("sha3_256 (ours)", sha3_256(c.message))
        _print_hex("sha3_256 (hashlib)", hashlib.sha3_256(c.message).digest())
        _print_hex("sha3_512 (ours)", sha3_512(c.message))
        _print_hex("sha3_512 (hashlib)", hashlib.sha3_512(c.message).digest())

    print("\n=== Step 5: SHAKE (XOF) ===")
    for c in cases:
        print(f"\nCase: {c.name!r}")
        out_len_128 = 32
        out_len_256 = 64
        _print_hex(f"shake128[{out_len_128}] (ours)", shake128(c.message, out_len_128))
        _print_hex(f"shake128[{out_len_128}] (hashlib)", hashlib.shake_128(c.message).digest(out_len_128))
        _print_hex(f"shake256[{out_len_256}] (ours)", shake256(c.message, out_len_256))
        _print_hex(f"shake256[{out_len_256}] (hashlib)", hashlib.shake_256(c.message).digest(out_len_256))


if __name__ == "__main__":
    main()
