"""
Educational AES implementation (AES-128/192/256) in pure Python (stdlib only).

Runs a small, step-by-step demo of the AES building blocks (state layout,
SubBytes/ShiftRows/MixColumns, key expansion) and validates against the FIPS 197
Appendix C.1 AES-128 test vector.

Run:
  python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence, Tuple


SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i


RCON = [
    0x00,
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x80,
    0x1B,
    0x36,
]


def _hex_to_bytes(s: str) -> bytes:
    s = s.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) % 2 != 0:
        raise ValueError("hex string must have even length")
    return bytes.fromhex(s)


def _bytes_to_hex(b: bytes) -> str:
    return b.hex()


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor_bytes requires equal-length inputs")
    return bytes(x ^ y for x, y in zip(a, b))


def bytes_to_state(block: bytes) -> List[int]:
    if len(block) != 16:
        raise ValueError("AES state is exactly 16 bytes")
    return list(block)


def state_to_bytes(state: Sequence[int]) -> bytes:
    if len(state) != 16:
        raise ValueError("AES state must have length 16")
    return bytes(int(x) & 0xFF for x in state)


def add_round_key(state: List[int], round_key: bytes) -> List[int]:
    if len(round_key) != 16:
        raise ValueError("round_key must be 16 bytes")
    return [s ^ k for s, k in zip(state, round_key)]


def sub_bytes(state: List[int]) -> List[int]:
    return [SBOX[b] for b in state]


def inv_sub_bytes(state: List[int]) -> List[int]:
    return [INV_SBOX[b] for b in state]


def shift_rows(state: List[int]) -> List[int]:
    out = state[:]
    for r in range(4):
        row = [state[r + 4 * c] for c in range(4)]
        row = row[r:] + row[:r]
        for c in range(4):
            out[r + 4 * c] = row[c]
    return out


def inv_shift_rows(state: List[int]) -> List[int]:
    out = state[:]
    for r in range(4):
        row = [state[r + 4 * c] for c in range(4)]
        if r:
            row = row[-r:] + row[:-r]
        for c in range(4):
            out[r + 4 * c] = row[c]
    return out


def xtime(a: int) -> int:
    a &= 0xFF
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def gf_mul(a: int, b: int) -> int:
    a &= 0xFF
    b &= 0xFF
    res = 0
    x = a
    y = b
    for _ in range(8):
        if y & 1:
            res ^= x
        y >>= 1
        x = xtime(x)
    return res & 0xFF


def mix_single_column(col: Sequence[int]) -> List[int]:
    if len(col) != 4:
        raise ValueError("column must have 4 bytes")
    a0, a1, a2, a3 = (int(x) & 0xFF for x in col)
    return [
        gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3,
        a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3,
        a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3),
        gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2),
    ]


def inv_mix_single_column(col: Sequence[int]) -> List[int]:
    if len(col) != 4:
        raise ValueError("column must have 4 bytes")
    a0, a1, a2, a3 = (int(x) & 0xFF for x in col)
    return [
        gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9),
        gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13),
        gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11),
        gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14),
    ]


def mix_columns(state: List[int]) -> List[int]:
    out = state[:]
    for c in range(4):
        col = [state[r + 4 * c] for r in range(4)]
        mixed = mix_single_column(col)
        for r in range(4):
            out[r + 4 * c] = mixed[r]
    return out


def inv_mix_columns(state: List[int]) -> List[int]:
    out = state[:]
    for c in range(4):
        col = [state[r + 4 * c] for r in range(4)]
        mixed = inv_mix_single_column(col)
        for r in range(4):
            out[r + 4 * c] = mixed[r]
    return out


def rot_word(word: bytes) -> bytes:
    if len(word) != 4:
        raise ValueError("word must be 4 bytes")
    return word[1:] + word[:1]


def sub_word(word: bytes) -> bytes:
    if len(word) != 4:
        raise ValueError("word must be 4 bytes")
    return bytes(SBOX[b] for b in word)


def _nk_nr_from_key_len(key_len: int) -> Tuple[int, int]:
    if key_len == 16:
        return 4, 10
    if key_len == 24:
        return 6, 12
    if key_len == 32:
        return 8, 14
    raise ValueError("AES key must be 16/24/32 bytes (128/192/256-bit)")


def expand_key(key: bytes) -> List[bytes]:
    nk, nr = _nk_nr_from_key_len(len(key))
    words: List[bytes] = [key[4 * i : 4 * (i + 1)] for i in range(nk)]
    i = nk
    while len(words) < 4 * (nr + 1):
        temp = words[-1]
        if i % nk == 0:
            temp = bytes(
                t ^ r
                for t, r in zip(sub_word(rot_word(temp)), bytes([RCON[i // nk], 0, 0, 0]))
            )
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)
        words.append(bytes(a ^ b for a, b in zip(words[-nk], temp)))
        i += 1

    round_keys: List[bytes] = []
    for r in range(nr + 1):
        rk = b"".join(words[4 * r : 4 * (r + 1)])
        round_keys.append(rk)
    return round_keys


def aes_encrypt_block(plaintext: bytes, key: bytes) -> bytes:
    if len(plaintext) != 16:
        raise ValueError("AES encrypt_block expects a single 16-byte block")
    round_keys = expand_key(key)
    nr = len(round_keys) - 1

    state = bytes_to_state(plaintext)
    state = add_round_key(state, round_keys[0])
    for r in range(1, nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[r])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[nr])
    return state_to_bytes(state)


def aes_decrypt_block(ciphertext: bytes, key: bytes) -> bytes:
    if len(ciphertext) != 16:
        raise ValueError("AES decrypt_block expects a single 16-byte block")
    round_keys = expand_key(key)
    nr = len(round_keys) - 1

    state = bytes_to_state(ciphertext)
    state = add_round_key(state, round_keys[nr])
    for r in range(nr - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[r])
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    return state_to_bytes(state)


def format_state(state: Sequence[int]) -> str:
    if len(state) != 16:
        raise ValueError("state must have length 16")
    rows = []
    for r in range(4):
        row = [state[r + 4 * c] for c in range(4)]
        rows.append(" ".join(f"{b:02x}" for b in row))
    return "\n".join(rows)


@dataclass(frozen=True)
class Step:
    n: int
    name: str


def _print_step(step: Step) -> None:
    print(f"=== Step {step.n}: {step.name} ===")


def demo_step_1_state_and_addroundkey() -> None:
    _print_step(Step(1, "State and AddRoundKey"))
    pt = _hex_to_bytes("00112233445566778899aabbccddeeff")
    key = _hex_to_bytes("000102030405060708090a0b0c0d0e0f")
    state = bytes_to_state(pt)
    start = add_round_key(state, key)
    print("plaintext:", _bytes_to_hex(pt))
    print("key      :", _bytes_to_hex(key))
    print("round[1].start:", _bytes_to_hex(state_to_bytes(start)))
    print("state grid (rows):")
    print(format_state(start))
    print()


def demo_step_2_subbytes_and_shiftrows() -> None:
    _print_step(Step(2, "SubBytes and ShiftRows"))
    start = bytes_to_state(_hex_to_bytes("00102030405060708090a0b0c0d0e0f0"))
    s_box = sub_bytes(start)
    s_row = shift_rows(s_box)
    print("round[1].start:", _bytes_to_hex(state_to_bytes(start)))
    print("round[1].s_box :", _bytes_to_hex(state_to_bytes(s_box)))
    print("round[1].s_row :", _bytes_to_hex(state_to_bytes(s_row)))
    print()


def demo_step_3_gf_and_mixcolumns() -> None:
    _print_step(Step(3, "GF(2^8) and MixColumns"))
    print("gf_mul(0x57, 0x83) =", f"{gf_mul(0x57, 0x83):02x}")
    print("gf_mul(0x57, 0x13) =", f"{gf_mul(0x57, 0x13):02x}")
    s_row = bytes_to_state(_hex_to_bytes("6353e08c0960e104cd70b751bacad0e7"))
    m_col = mix_columns(s_row)
    print("round[1].s_row:", _bytes_to_hex(state_to_bytes(s_row)))
    print("round[1].m_col:", _bytes_to_hex(state_to_bytes(m_col)))
    print()


def demo_step_4_key_expansion() -> None:
    _print_step(Step(4, "Key Expansion"))
    key = _hex_to_bytes("000102030405060708090a0b0c0d0e0f")
    rks = expand_key(key)
    print("round[0].k_sch:", _bytes_to_hex(rks[0]))
    print("round[1].k_sch:", _bytes_to_hex(rks[1]))
    print("round[10].k_sch:", _bytes_to_hex(rks[10]))
    print()


def demo_step_5_encrypt_decrypt_block() -> None:
    _print_step(Step(5, "Encrypt and decrypt one block"))
    pt = _hex_to_bytes("00112233445566778899aabbccddeeff")
    key = _hex_to_bytes("000102030405060708090a0b0c0d0e0f")
    ct = aes_encrypt_block(pt, key)
    dec = aes_decrypt_block(ct, key)
    print("plaintext :", _bytes_to_hex(pt))
    print("ciphertext:", _bytes_to_hex(ct))
    print("decrypt   :", _bytes_to_hex(dec))
    print()


def main() -> None:
    demo_step_1_state_and_addroundkey()
    demo_step_2_subbytes_and_shiftrows()
    demo_step_3_gf_and_mixcolumns()
    demo_step_4_key_expansion()
    demo_step_5_encrypt_decrypt_block()


if __name__ == "__main__":
    main()
