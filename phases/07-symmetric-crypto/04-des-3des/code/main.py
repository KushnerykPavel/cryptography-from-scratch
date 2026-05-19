"""
DES and 3DES (TDEA) from scratch (educational).

What this file does:
- Implements the DES (DEA) 64-bit block cipher with a 56-bit effective key (8 parity bits).
- Builds 3DES (TDEA) using the standard EDE construction: E_K3(D_K2(E_K1(P))).
- Demonstrates known-answer test vectors from NIST publications.

Run:
  python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass


class DesError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DesError(message)


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big", signed=False)


def int_to_bytes(x: int, length: int) -> bytes:
    _require(x >= 0, "x must be non-negative")
    _require(length >= 0, "length must be non-negative")
    return x.to_bytes(length, byteorder="big", signed=False)


def _require_block8(block: bytes) -> bytes:
    _require(isinstance(block, (bytes, bytearray)), "block must be bytes-like")
    b = bytes(block)
    _require(len(b) == 8, "block must be exactly 8 bytes (64 bits)")
    return b


def _require_key8(key: bytes) -> bytes:
    _require(isinstance(key, (bytes, bytearray)), "key must be bytes-like")
    k = bytes(key)
    _require(len(k) == 8, "key must be exactly 8 bytes (64 bits, includes parity bits)")
    return k


def permute_bits(x: int, in_bits: int, table: list[int]) -> int:
    _require(in_bits > 0, "in_bits must be positive")
    _require(0 <= x < (1 << in_bits), "x out of range for in_bits")
    out = 0
    for p in table:
        _require(1 <= p <= in_bits, "table entry out of range")
        out = (out << 1) | ((x >> (in_bits - p)) & 1)
    return out


def rotate_left(x: int, shift: int, width: int) -> int:
    _require(width > 0, "width must be positive")
    _require(0 <= x < (1 << width), "x out of range for width")
    s = shift % width
    mask = (1 << width) - 1
    return ((x << s) | (x >> (width - s))) & mask


IP = [
    58,
    50,
    42,
    34,
    26,
    18,
    10,
    2,
    60,
    52,
    44,
    36,
    28,
    20,
    12,
    4,
    62,
    54,
    46,
    38,
    30,
    22,
    14,
    6,
    64,
    56,
    48,
    40,
    32,
    24,
    16,
    8,
    57,
    49,
    41,
    33,
    25,
    17,
    9,
    1,
    59,
    51,
    43,
    35,
    27,
    19,
    11,
    3,
    61,
    53,
    45,
    37,
    29,
    21,
    13,
    5,
    63,
    55,
    47,
    39,
    31,
    23,
    15,
    7,
]

FP = [
    40,
    8,
    48,
    16,
    56,
    24,
    64,
    32,
    39,
    7,
    47,
    15,
    55,
    23,
    63,
    31,
    38,
    6,
    46,
    14,
    54,
    22,
    62,
    30,
    37,
    5,
    45,
    13,
    53,
    21,
    61,
    29,
    36,
    4,
    44,
    12,
    52,
    20,
    60,
    28,
    35,
    3,
    43,
    11,
    51,
    19,
    59,
    27,
    34,
    2,
    42,
    10,
    50,
    18,
    58,
    26,
    33,
    1,
    41,
    9,
    49,
    17,
    57,
    25,
]

E = [
    32,
    1,
    2,
    3,
    4,
    5,
    4,
    5,
    6,
    7,
    8,
    9,
    8,
    9,
    10,
    11,
    12,
    13,
    12,
    13,
    14,
    15,
    16,
    17,
    16,
    17,
    18,
    19,
    20,
    21,
    20,
    21,
    22,
    23,
    24,
    25,
    24,
    25,
    26,
    27,
    28,
    29,
    28,
    29,
    30,
    31,
    32,
    1,
]

P = [
    16,
    7,
    20,
    21,
    29,
    12,
    28,
    17,
    1,
    15,
    23,
    26,
    5,
    18,
    31,
    10,
    2,
    8,
    24,
    14,
    32,
    27,
    3,
    9,
    19,
    13,
    30,
    6,
    22,
    11,
    4,
    25,
]

PC1 = [
    57,
    49,
    41,
    33,
    25,
    17,
    9,
    1,
    58,
    50,
    42,
    34,
    26,
    18,
    10,
    2,
    59,
    51,
    43,
    35,
    27,
    19,
    11,
    3,
    60,
    52,
    44,
    36,
    63,
    55,
    47,
    39,
    31,
    23,
    15,
    7,
    62,
    54,
    46,
    38,
    30,
    22,
    14,
    6,
    61,
    53,
    45,
    37,
    29,
    21,
    13,
    5,
    28,
    20,
    12,
    4,
]

PC2 = [
    14,
    17,
    11,
    24,
    1,
    5,
    3,
    28,
    15,
    6,
    21,
    10,
    23,
    19,
    12,
    4,
    26,
    8,
    16,
    7,
    27,
    20,
    13,
    2,
    41,
    52,
    31,
    37,
    47,
    55,
    30,
    40,
    51,
    45,
    33,
    48,
    44,
    49,
    39,
    56,
    34,
    53,
    46,
    42,
    50,
    36,
    29,
    32,
]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

SBOXES = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
]


def des_round_f(right32: int, subkey48: int) -> int:
    _require(0 <= right32 < (1 << 32), "right32 out of range")
    _require(0 <= subkey48 < (1 << 48), "subkey48 out of range")
    expanded = permute_bits(right32, 32, E)  # 48 bits
    x = expanded ^ subkey48
    out32 = 0
    for i in range(8):
        chunk = (x >> (42 - 6 * i)) & 0x3F
        row = ((chunk & 0x20) >> 4) | (chunk & 0x01)
        col = (chunk >> 1) & 0x0F
        out32 = (out32 << 4) | SBOXES[i][row][col]
    return permute_bits(out32, 32, P)


def des_key_schedule(key: bytes) -> list[int]:
    k = _require_key8(key)
    key64 = bytes_to_int(k)
    key56 = permute_bits(key64, 64, PC1)
    c = (key56 >> 28) & ((1 << 28) - 1)
    d = key56 & ((1 << 28) - 1)
    subkeys: list[int] = []
    for shift in SHIFTS:
        c = rotate_left(c, shift, 28)
        d = rotate_left(d, shift, 28)
        cd56 = (c << 28) | d
        subkeys.append(permute_bits(cd56, 56, PC2))
    return subkeys


def _des_crypt_block(block: bytes, subkeys: list[int]) -> bytes:
    b = _require_block8(block)
    _require(len(subkeys) == 16, "DES needs exactly 16 subkeys")

    x = bytes_to_int(b)
    ip = permute_bits(x, 64, IP)
    left = (ip >> 32) & 0xFFFF_FFFF
    right = ip & 0xFFFF_FFFF

    for k in subkeys:
        left, right = right, left ^ des_round_f(right, k)

    preoutput = (right << 32) | left
    out = permute_bits(preoutput, 64, FP)
    return int_to_bytes(out, 8)


def des_encrypt_block(block: bytes, key: bytes) -> bytes:
    subkeys = des_key_schedule(key)
    return _des_crypt_block(block, subkeys)


def des_decrypt_block(block: bytes, key: bytes) -> bytes:
    subkeys = list(reversed(des_key_schedule(key)))
    return _des_crypt_block(block, subkeys)


def tdea_encrypt_block(block: bytes, key1: bytes, key2: bytes, key3: bytes) -> bytes:
    b = _require_block8(block)
    k1 = _require_key8(key1)
    k2 = _require_key8(key2)
    k3 = _require_key8(key3)
    _require(not (k1 == k2 == k3), "TDEA key bundle must not have three identical keys")
    return des_encrypt_block(des_decrypt_block(des_encrypt_block(b, k1), k2), k3)


def tdea_decrypt_block(block: bytes, key1: bytes, key2: bytes, key3: bytes) -> bytes:
    b = _require_block8(block)
    k1 = _require_key8(key1)
    k2 = _require_key8(key2)
    k3 = _require_key8(key3)
    _require(not (k1 == k2 == k3), "TDEA key bundle must not have three identical keys")
    return des_decrypt_block(des_encrypt_block(des_decrypt_block(b, k3), k2), k1)


def hamming_distance_bits(a: bytes, b: bytes) -> int:
    _require(len(a) == len(b), "inputs must have the same length")
    return (bytes_to_int(a) ^ bytes_to_int(b)).bit_count()


def _hx(b: bytes) -> str:
    return b.hex().upper()


@dataclass(frozen=True)
class DemoParams:
    des_key: bytes
    des_plaintext: bytes
    tdea_k1: bytes
    tdea_k2: bytes
    tdea_k3: bytes
    tdea_plaintext_blocks: list[bytes]


def demo_step_1_permutations() -> None:
    print("=== Step 1: Bits, bytes, and permutations ===")
    x = int("0123456789ABCDEF", 16)
    y = permute_bits(x, 64, IP)
    z = permute_bits(y, 64, FP)
    print(f"x   = 0x{x:016X}")
    print(f"IP  = 0x{y:016X}")
    print(f"FP  = 0x{z:016X}")
    print(f"roundtrip_ok={z == x}")
    print()


def demo_step_2_key_schedule(params: DemoParams) -> None:
    print("=== Step 2: DES key schedule (subkeys) ===")
    subkeys = des_key_schedule(params.des_key)
    print(f"key = {_hx(params.des_key)} (64-bit with parity bits)")
    print(f"K1  = 0x{subkeys[0]:012X}")
    print(f"K16 = 0x{subkeys[-1]:012X}")
    print()


def demo_step_3_round_function(params: DemoParams) -> None:
    print("=== Step 3: The DES f-function (E, S-boxes, P) ===")
    subkeys = des_key_schedule(params.des_key)
    ip = permute_bits(bytes_to_int(params.des_plaintext), 64, IP)
    right0 = ip & 0xFFFF_FFFF
    f1 = des_round_f(right0, subkeys[0])
    print(f"P   = {_hx(params.des_plaintext)}")
    print(f"R0  = 0x{right0:08X}")
    print(f"f(R0,K1) = 0x{f1:08X}")
    print()


def demo_step_4_des_encrypt_decrypt(params: DemoParams) -> None:
    print("=== Step 4: DES encrypt/decrypt (single block) ===")
    c = des_encrypt_block(params.des_plaintext, params.des_key)
    p2 = des_decrypt_block(c, params.des_key)
    print(f"key = {_hx(params.des_key)}")
    print(f"P   = {_hx(params.des_plaintext)}")
    print(f"C   = {_hx(c)}")
    print(f"D(C)= {_hx(p2)}")
    print(f"roundtrip_ok={p2 == params.des_plaintext}")
    print()

    flipped = bytes([params.des_plaintext[0] ^ 0x01]) + params.des_plaintext[1:]
    c2 = des_encrypt_block(flipped, params.des_key)
    hd = hamming_distance_bits(c, c2)
    print("avalanche_demo (flip 1 plaintext bit):")
    print(f"P'  = {_hx(flipped)}")
    print(f"C'  = {_hx(c2)}")
    print(f"hamming_distance={hd}/64")
    print()


def demo_step_5_tdea(params: DemoParams) -> None:
    print("=== Step 5: 3DES (TDEA) via EDE ===")
    print(f"K1 = {_hx(params.tdea_k1)}")
    print(f"K2 = {_hx(params.tdea_k2)}")
    print(f"K3 = {_hx(params.tdea_k3)}")
    for i, p in enumerate(params.tdea_plaintext_blocks, start=1):
        c = tdea_encrypt_block(p, params.tdea_k1, params.tdea_k2, params.tdea_k3)
        p2 = tdea_decrypt_block(c, params.tdea_k1, params.tdea_k2, params.tdea_k3)
        print(f"P{i} = {_hx(p)}  -> C{i} = {_hx(c)}  (roundtrip_ok={p2 == p})")
    print()


def main() -> None:
    params = DemoParams(
        des_key=bytes.fromhex("133457799BBCDFF1"),
        des_plaintext=bytes.fromhex("0123456789ABCDEF"),
        tdea_k1=bytes.fromhex("0123456789ABCDEF"),
        tdea_k2=bytes.fromhex("23456789ABCDEF01"),
        tdea_k3=bytes.fromhex("456789ABCDEF0123"),
        tdea_plaintext_blocks=[
            bytes.fromhex("5468652071756663"),  # "The quic"
            bytes.fromhex("6B2062726F776E20"),  # "k brown "
            bytes.fromhex("666F78206A756D70"),  # "fox jump"
        ],
    )
    demo_step_1_permutations()
    demo_step_2_key_schedule(params)
    demo_step_3_round_function(params)
    demo_step_4_des_encrypt_decrypt(params)
    demo_step_5_tdea(params)


if __name__ == "__main__":
    main()
