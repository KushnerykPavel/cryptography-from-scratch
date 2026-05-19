"""
ChaCha20-Poly1305 (RFC 8439) from scratch, in pure Python (stdlib only).

Run:
  python3 code/main.py

This file implements:
- ChaCha20 block function and stream cipher (IETF 96-bit nonce + 32-bit counter)
- Poly1305 one-time MAC
- AEAD_CHACHA20_POLY1305 encryption/decryption (with AAD)

Educational implementation. Not constant-time. Not production-safe.
"""

from __future__ import annotations

import binascii
import hmac
import struct
from typing import Iterable, Tuple


def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def _rotl32(x: int, n: int) -> int:
    x = _u32(x)
    return _u32((x << n) | (x >> (32 - n)))


def _le_u32(data: bytes) -> int:
    return struct.unpack("<I", data)[0]


def _u32_le(x: int) -> bytes:
    return struct.pack("<I", _u32(x))


def _chunks(data: bytes, size: int) -> Iterable[bytes]:
    for i in range(0, len(data), size):
        yield data[i : i + size]


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def _hex(data: bytes) -> str:
    return binascii.hexlify(data).decode("ascii")


def quarter_round(a: int, b: int, c: int, d: int) -> Tuple[int, int, int, int]:
    a = _u32(a + b)
    d ^= a
    d = _rotl32(d, 16)

    c = _u32(c + d)
    b ^= c
    b = _rotl32(b, 12)

    a = _u32(a + b)
    d ^= a
    d = _rotl32(d, 8)

    c = _u32(c + d)
    b ^= c
    b = _rotl32(b, 7)

    return a, b, c, d


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """
    ChaCha20 block function (RFC 8439).

    Inputs:
    - key: 32 bytes
    - counter: 32-bit unsigned integer
    - nonce: 12 bytes (IETF 96-bit nonce)

    Output:
    - 64-byte keystream block
    """
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    if not (0 <= counter <= 0xFFFFFFFF):
        raise ValueError("counter must fit in 32 bits")

    constants = (b"expa", b"nd 3", b"2-by", b"te k")
    state = [0] * 16

    state[0] = _le_u32(constants[0])
    state[1] = _le_u32(constants[1])
    state[2] = _le_u32(constants[2])
    state[3] = _le_u32(constants[3])

    for i in range(8):
        state[4 + i] = _le_u32(key[i * 4 : (i + 1) * 4])

    state[12] = counter
    state[13] = _le_u32(nonce[0:4])
    state[14] = _le_u32(nonce[4:8])
    state[15] = _le_u32(nonce[8:12])

    working = state[:]

    for _ in range(10):
        working[0], working[4], working[8], working[12] = quarter_round(
            working[0], working[4], working[8], working[12]
        )
        working[1], working[5], working[9], working[13] = quarter_round(
            working[1], working[5], working[9], working[13]
        )
        working[2], working[6], working[10], working[14] = quarter_round(
            working[2], working[6], working[10], working[14]
        )
        working[3], working[7], working[11], working[15] = quarter_round(
            working[3], working[7], working[11], working[15]
        )

        working[0], working[5], working[10], working[15] = quarter_round(
            working[0], working[5], working[10], working[15]
        )
        working[1], working[6], working[11], working[12] = quarter_round(
            working[1], working[6], working[11], working[12]
        )
        working[2], working[7], working[8], working[13] = quarter_round(
            working[2], working[7], working[8], working[13]
        )
        working[3], working[4], working[9], working[14] = quarter_round(
            working[3], working[4], working[9], working[14]
        )

    out = bytearray()
    for i in range(16):
        out += _u32_le(working[i] + state[i])
    return bytes(out)


def chacha20_keystream(key: bytes, counter: int, nonce: bytes, length: int) -> bytes:
    if length < 0:
        raise ValueError("length must be non-negative")
    out = bytearray()
    block_counter = counter
    while len(out) < length:
        out += chacha20_block(key, block_counter, nonce)
        block_counter = _u32(block_counter + 1)
    return bytes(out[:length])


def chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    ks = chacha20_keystream(key, counter, nonce, len(data))
    return _xor_bytes(data, ks)


def chacha20_encrypt(key: bytes, counter: int, nonce: bytes, plaintext: bytes) -> bytes:
    return chacha20_xor(key, counter, nonce, plaintext)


def chacha20_decrypt(key: bytes, counter: int, nonce: bytes, ciphertext: bytes) -> bytes:
    return chacha20_xor(key, counter, nonce, ciphertext)


def poly1305_key_gen(key: bytes, nonce: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    return chacha20_block(key, 0, nonce)[:32]


def _poly1305_clamp_r(r: bytes) -> bytes:
    if len(r) != 16:
        raise ValueError("r must be 16 bytes")
    r = bytearray(r)
    r[3] &= 0x0F
    r[7] &= 0x0F
    r[11] &= 0x0F
    r[15] &= 0x0F
    r[4] &= 0xFC
    r[8] &= 0xFC
    r[12] &= 0xFC
    return bytes(r)


def poly1305_mac(msg: bytes, key: bytes) -> bytes:
    """
    Poly1305 one-time MAC (RFC 8439).

    key: 32 bytes = r(16) || s(16)
    returns: 16-byte tag
    """
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")

    r_bytes = _poly1305_clamp_r(key[:16])
    s_bytes = key[16:]

    r = int.from_bytes(r_bytes, "little")
    s = int.from_bytes(s_bytes, "little")
    p = (1 << 130) - 5

    a = 0
    for block in _chunks(msg, 16):
        n = int.from_bytes(block + b"\x01", "little")
        a = (a + n) % p
        a = (a * r) % p

    a = a + s
    tag = a & ((1 << 128) - 1)
    return tag.to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    rem = len(data) % 16
    if rem == 0:
        return b""
    return b"\x00" * (16 - rem)


def aead_chacha20_poly1305_encrypt(
    key: bytes, nonce: bytes, aad: bytes, plaintext: bytes
) -> Tuple[bytes, bytes]:
    """
    AEAD_CHACHA20_POLY1305 (RFC 8439).

    Returns (ciphertext, tag).
    """
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")

    otk = poly1305_key_gen(key, nonce)
    ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)

    mac_data = aad + _pad16(aad)
    mac_data += ciphertext + _pad16(ciphertext)
    mac_data += struct.pack("<Q", len(aad))
    mac_data += struct.pack("<Q", len(ciphertext))

    tag = poly1305_mac(mac_data, otk)
    return ciphertext, tag


def aead_chacha20_poly1305_decrypt(
    key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, tag: bytes
) -> bytes:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    if len(tag) != 16:
        raise ValueError("tag must be 16 bytes")

    otk = poly1305_key_gen(key, nonce)
    mac_data = aad + _pad16(aad)
    mac_data += ciphertext + _pad16(ciphertext)
    mac_data += struct.pack("<Q", len(aad))
    mac_data += struct.pack("<Q", len(ciphertext))
    expected = poly1305_mac(mac_data, otk)
    if not hmac.compare_digest(expected, tag):
        raise ValueError("invalid tag")
    return chacha20_decrypt(key, 1, nonce, ciphertext)


def _print_step(n: int, name: str) -> None:
    print(f"=== Step {n}: {name} ===")


def main() -> None:
    _print_step(1, "ChaCha20 block function")
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    block = chacha20_block(key, 1, nonce)
    print("block(hex) =", _hex(block))

    _print_step(2, "ChaCha20 stream cipher (XOR)")
    nonce2 = bytes.fromhex("000000000000004a00000000")
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    )
    ciphertext = chacha20_encrypt(key, 1, nonce2, plaintext)
    print("ciphertext(hex) =", _hex(ciphertext))
    roundtrip = chacha20_decrypt(key, 1, nonce2, ciphertext)
    print("roundtrip_ok =", roundtrip == plaintext)

    _print_step(3, "Poly1305 one-time MAC")
    poly_key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b"
    )
    msg = b"Cryptographic Forum Research Group"
    tag = poly1305_mac(msg, poly_key)
    print("tag(hex) =", _hex(tag))

    _print_step(4, "AEAD ChaCha20-Poly1305")
    aead_key = bytes.fromhex(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
    )
    aead_nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    pt = plaintext
    ct, t = aead_chacha20_poly1305_encrypt(aead_key, aead_nonce, aad, pt)
    print("aead_ciphertext(hex) =", _hex(ct))
    print("aead_tag(hex) =", _hex(t))
    dec = aead_chacha20_poly1305_decrypt(aead_key, aead_nonce, aad, ct, t)
    print("aead_roundtrip_ok =", dec == pt)


if __name__ == "__main__":
    main()
