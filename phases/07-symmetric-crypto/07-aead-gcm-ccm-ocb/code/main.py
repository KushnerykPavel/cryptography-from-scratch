"""
Educational, from-scratch AES-GCM demo (AEAD) with deterministic test vectors.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor requires equal-length byte strings")
    return bytes(x ^ y for x, y in zip(a, b))


def _chunks(data: bytes, n: int) -> list[bytes]:
    if n <= 0:
        raise ValueError("chunk size must be positive")
    return [data[i : i + n] for i in range(0, len(data), n)]


def _pad16(data: bytes) -> bytes:
    if len(data) % 16 == 0:
        return data
    return data + b"\x00" * (16 - (len(data) % 16))


def _u64be(n: int) -> bytes:
    if n < 0 or n >= 1 << 64:
        raise ValueError("u64 out of range")
    return n.to_bytes(8, "big")


def _u128be(n: int) -> bytes:
    if n < 0 or n >= 1 << 128:
        raise ValueError("u128 out of range")
    return n.to_bytes(16, "big")


def _from_u128be(b: bytes) -> int:
    if len(b) != 16:
        raise ValueError("expected 16 bytes")
    return int.from_bytes(b, "big")


SBOX = [
    0x63,
    0x7C,
    0x77,
    0x7B,
    0xF2,
    0x6B,
    0x6F,
    0xC5,
    0x30,
    0x01,
    0x67,
    0x2B,
    0xFE,
    0xD7,
    0xAB,
    0x76,
    0xCA,
    0x82,
    0xC9,
    0x7D,
    0xFA,
    0x59,
    0x47,
    0xF0,
    0xAD,
    0xD4,
    0xA2,
    0xAF,
    0x9C,
    0xA4,
    0x72,
    0xC0,
    0xB7,
    0xFD,
    0x93,
    0x26,
    0x36,
    0x3F,
    0xF7,
    0xCC,
    0x34,
    0xA5,
    0xE5,
    0xF1,
    0x71,
    0xD8,
    0x31,
    0x15,
    0x04,
    0xC7,
    0x23,
    0xC3,
    0x18,
    0x96,
    0x05,
    0x9A,
    0x07,
    0x12,
    0x80,
    0xE2,
    0xEB,
    0x27,
    0xB2,
    0x75,
    0x09,
    0x83,
    0x2C,
    0x1A,
    0x1B,
    0x6E,
    0x5A,
    0xA0,
    0x52,
    0x3B,
    0xD6,
    0xB3,
    0x29,
    0xE3,
    0x2F,
    0x84,
    0x53,
    0xD1,
    0x00,
    0xED,
    0x20,
    0xFC,
    0xB1,
    0x5B,
    0x6A,
    0xCB,
    0xBE,
    0x39,
    0x4A,
    0x4C,
    0x58,
    0xCF,
    0xD0,
    0xEF,
    0xAA,
    0xFB,
    0x43,
    0x4D,
    0x33,
    0x85,
    0x45,
    0xF9,
    0x02,
    0x7F,
    0x50,
    0x3C,
    0x9F,
    0xA8,
    0x51,
    0xA3,
    0x40,
    0x8F,
    0x92,
    0x9D,
    0x38,
    0xF5,
    0xBC,
    0xB6,
    0xDA,
    0x21,
    0x10,
    0xFF,
    0xF3,
    0xD2,
    0xCD,
    0x0C,
    0x13,
    0xEC,
    0x5F,
    0x97,
    0x44,
    0x17,
    0xC4,
    0xA7,
    0x7E,
    0x3D,
    0x64,
    0x5D,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4F,
    0xDC,
    0x22,
    0x2A,
    0x90,
    0x88,
    0x46,
    0xEE,
    0xB8,
    0x14,
    0xDE,
    0x5E,
    0x0B,
    0xDB,
    0xE0,
    0x32,
    0x3A,
    0x0A,
    0x49,
    0x06,
    0x24,
    0x5C,
    0xC2,
    0xD3,
    0xAC,
    0x62,
    0x91,
    0x95,
    0xE4,
    0x79,
    0xE7,
    0xC8,
    0x37,
    0x6D,
    0x8D,
    0xD5,
    0x4E,
    0xA9,
    0x6C,
    0x56,
    0xF4,
    0xEA,
    0x65,
    0x7A,
    0xAE,
    0x08,
    0xBA,
    0x78,
    0x25,
    0x2E,
    0x1C,
    0xA6,
    0xB4,
    0xC6,
    0xE8,
    0xDD,
    0x74,
    0x1F,
    0x4B,
    0xBD,
    0x8B,
    0x8A,
    0x70,
    0x3E,
    0xB5,
    0x66,
    0x48,
    0x03,
    0xF6,
    0x0E,
    0x61,
    0x35,
    0x57,
    0xB9,
    0x86,
    0xC1,
    0x1D,
    0x9E,
    0xE1,
    0xF8,
    0x98,
    0x11,
    0x69,
    0xD9,
    0x8E,
    0x94,
    0x9B,
    0x1E,
    0x87,
    0xE9,
    0xCE,
    0x55,
    0x28,
    0xDF,
    0x8C,
    0xA1,
    0x89,
    0x0D,
    0xBF,
    0xE6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2D,
    0x0F,
    0xB0,
    0x54,
    0xBB,
    0x16,
]


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
    0x6C,
    0xD8,
    0xAB,
    0x4D,
    0x9A,
]


def _rot_word(w: bytes) -> bytes:
    if len(w) != 4:
        raise ValueError("word must be 4 bytes")
    return w[1:] + w[:1]


def _sub_word(w: bytes) -> bytes:
    if len(w) != 4:
        raise ValueError("word must be 4 bytes")
    return bytes(SBOX[b] for b in w)


def _bytes_to_state(block: bytes) -> list[list[int]]:
    if len(block) != 16:
        raise ValueError("block must be 16 bytes")
    return [list(block[i::4]) for i in range(4)]


def _state_to_bytes(state: list[list[int]]) -> bytes:
    if len(state) != 4 or any(len(r) != 4 for r in state):
        raise ValueError("state must be 4x4")
    return bytes(state[r][c] for c in range(4) for r in range(4))


def _add_round_key(state: list[list[int]], round_key: bytes) -> None:
    rk = _bytes_to_state(round_key)
    for r in range(4):
        for c in range(4):
            state[r][c] ^= rk[r][c]


def _sub_bytes(state: list[list[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = SBOX[state[r][c]]


def _shift_rows(state: list[list[int]]) -> None:
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]


def _xtime(a: int) -> int:
    a &= 0xFF
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF


def _mix_single_column(col: list[int]) -> list[int]:
    if len(col) != 4:
        raise ValueError("column must have 4 bytes")
    a0, a1, a2, a3 = (x & 0xFF for x in col)
    t = a0 ^ a1 ^ a2 ^ a3
    return [
        a0 ^ t ^ _xtime(a0 ^ a1),
        a1 ^ t ^ _xtime(a1 ^ a2),
        a2 ^ t ^ _xtime(a2 ^ a3),
        a3 ^ t ^ _xtime(a3 ^ a0),
    ]


def _mix_columns(state: list[list[int]]) -> None:
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mixed = _mix_single_column(col)
        for r in range(4):
            state[r][c] = mixed[r]


def aes_expand_key(key: bytes) -> list[bytes]:
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    nk = len(key) // 4
    nr = nk + 6
    nb = 4

    w: list[bytes] = [b""] * (nb * (nr + 1))
    for i in range(nk):
        w[i] = key[4 * i : 4 * i + 4]

    for i in range(nk, nb * (nr + 1)):
        temp = w[i - 1]
        if i % nk == 0:
            temp = _sub_word(_rot_word(temp))
            temp = bytes([temp[0] ^ RCON[i // nk], temp[1], temp[2], temp[3]])
        elif nk > 6 and i % nk == 4:
            temp = _sub_word(temp)
        w[i] = _xor_bytes(w[i - nk], temp)

    round_keys: list[bytes] = []
    for r in range(nr + 1):
        round_keys.append(b"".join(w[4 * r : 4 * r + 4]))
    return round_keys


def aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    round_keys = aes_expand_key(key)
    nr = len(round_keys) - 1

    state = _bytes_to_state(block)
    _add_round_key(state, round_keys[0])

    for r in range(1, nr):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[r])

    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[nr])
    return _state_to_bytes(state)


def inc32(block: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("inc32 expects 16 bytes")
    prefix = block[:12]
    ctr = int.from_bytes(block[12:], "big")
    ctr = (ctr + 1) & 0xFFFFFFFF
    return prefix + ctr.to_bytes(4, "big")


def gctr(key: bytes, icb: bytes, data: bytes) -> bytes:
    if len(icb) != 16:
        raise ValueError("icb must be 16 bytes")
    if not data:
        return b""

    out = bytearray()
    cb = icb
    for block in _chunks(data, 16):
        stream = aes_encrypt_block(key, cb)
        out.extend(_xor_bytes(block, stream[: len(block)]))
        cb = inc32(cb)
    return bytes(out)


def gf128_mul(x: int, y: int) -> int:
    if x < 0 or x >= 1 << 128 or y < 0 or y >= 1 << 128:
        raise ValueError("gf128_mul inputs must be 128-bit integers")
    r = 0xE1000000000000000000000000000000
    z = 0
    v = x
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ r
        else:
            v >>= 1
    return z


def ghash(h: bytes, data: bytes) -> bytes:
    if len(h) != 16:
        raise ValueError("H must be 16 bytes")
    if len(data) % 16 != 0:
        raise ValueError("GHASH input must be a multiple of 16 bytes (pad before calling)")
    h_int = _from_u128be(h)
    y = 0
    for block in _chunks(data, 16):
        y ^= _from_u128be(block)
        y = gf128_mul(y, h_int)
    return _u128be(y)


def gcm_encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"", tag_len: int = 16
) -> tuple[bytes, bytes]:
    if len(nonce) != 12:
        raise ValueError("this educational implementation supports 12-byte nonces only")
    if tag_len != 16:
        raise ValueError("this educational implementation supports 16-byte tags only")

    h = aes_encrypt_block(key, b"\x00" * 16)
    j0 = nonce + b"\x00\x00\x00\x01"
    ciphertext = gctr(key, inc32(j0), plaintext)

    a_padded = _pad16(aad)
    c_padded = _pad16(ciphertext)
    lengths = _u64be(len(aad) * 8) + _u64be(len(ciphertext) * 8)
    s = ghash(h, a_padded + c_padded + lengths)
    tag = gctr(key, j0, s)
    return ciphertext, tag


def gcm_decrypt(
    key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, tag: bytes
) -> bytes:
    if len(tag) != 16:
        raise ValueError("tag must be 16 bytes")
    pt = gctr(key, inc32(nonce + b"\x00\x00\x00\x01"), ciphertext)
    _, computed_tag = gcm_encrypt(key, nonce, pt, aad=aad, tag_len=16)
    if not hmac.compare_digest(computed_tag, tag):
        raise ValueError("authentication failed")
    return pt


@dataclass(frozen=True)
class PackedAEAD:
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def to_bytes(self) -> bytes:
        return self.nonce + self.ciphertext + self.tag

    @staticmethod
    def from_bytes(data: bytes, nonce_len: int = 12, tag_len: int = 16) -> "PackedAEAD":
        if len(data) < nonce_len + tag_len:
            raise ValueError("packed message too short")
        nonce = data[:nonce_len]
        tag = data[-tag_len:]
        ciphertext = data[nonce_len:-tag_len]
        return PackedAEAD(nonce=nonce, ciphertext=ciphertext, tag=tag)


def xor_of_two_time_pad(plaintext1: bytes, plaintext2: bytes) -> bytes:
    if len(plaintext1) != len(plaintext2):
        raise ValueError("same-length plaintexts required")
    return _xor_bytes(plaintext1, plaintext2)


def main() -> None:
    print("=== Step 1: AES block encryption ===")
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct_block = aes_encrypt_block(key, block)
    print("key      =", key.hex())
    print("block    =", block.hex())
    print("E(K,blk) =", ct_block.hex())
    print()

    print("=== Step 2: CTR keystream (GCTR) with a 32-bit counter ===")
    icb = b"CTR-demo-nonce"[:12] + b"\x00\x00\x00\x01"
    data = b"CTR is XOR with a keystream."
    enc = gctr(key, icb, data)
    dec = gctr(key, icb, enc)
    print("icb      =", icb.hex())
    print("data     =", data)
    print("enc      =", enc.hex())
    print("dec      =", dec)
    print("ok       =", dec == data)
    print()

    print("=== Step 3: GHASH (polynomial hashing in GF(2^128)) ===")
    h = aes_encrypt_block(key, b"\x00" * 16)
    sample = b"hello"
    g = ghash(h, _pad16(sample))
    print("H        =", h.hex())
    print("data     =", sample.hex())
    print("GHASH    =", g.hex())
    print()

    print("=== Step 4: AES-GCM encrypt/decrypt (AEAD) ===")
    nonce = b"0123456789:;"
    aad = b"header:content-type=msg"
    plaintext = b"attack at dawn"
    ciphertext, tag = gcm_encrypt(key, nonce, plaintext, aad=aad)
    recovered = gcm_decrypt(key, nonce, ciphertext, aad=aad, tag=tag)
    print("nonce    =", nonce.hex())
    print("aad      =", aad)
    print("pt       =", plaintext)
    print("ct       =", ciphertext.hex())
    print("tag      =", tag.hex())
    print("pt'      =", recovered)
    print()

    print("NOTE: Nonce reuse breaks confidentiality (CTR keystream reuse).")
    nonce_reused = b"nonce-reuse!"
    pt1 = b"PAY BOB $1000"
    pt2 = b"PAY EVE $9999"
    c1, t1 = gcm_encrypt(key, nonce_reused, pt1, aad=b"tx")
    c2, t2 = gcm_encrypt(key, nonce_reused, pt2, aad=b"tx")
    leaked = xor_of_two_time_pad(c1, c2)
    expected = xor_of_two_time_pad(pt1, pt2)
    print("pt1      =", pt1)
    print("pt2      =", pt2)
    print("ct1      =", c1.hex(), "tag1 =", t1.hex())
    print("ct2      =", c2.hex(), "tag2 =", t2.hex())
    print("ct1^ct2  =", leaked.hex())
    print("pt1^pt2  =", expected.hex())
    print("leak ok  =", leaked == expected)
    print()

    print("=== Step 5: Pack `nonce|ciphertext|tag` for transport ===")
    packed = PackedAEAD(nonce=nonce, ciphertext=ciphertext, tag=tag).to_bytes()
    parsed = PackedAEAD.from_bytes(packed)
    print("packed   =", packed.hex())
    print("parsed.n =", parsed.nonce.hex())
    print("parsed.c =", parsed.ciphertext.hex())
    print("parsed.t =", parsed.tag.hex())


if __name__ == "__main__":
    main()
