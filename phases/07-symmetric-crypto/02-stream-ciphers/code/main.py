"""Stream ciphers from scratch: ChaCha20 core, keystream generation, and misuse.

This script implements the IETF ChaCha20 stream cipher variant (RFC 8439):
- 256-bit key (32 bytes)
- 32-bit block counter
- 96-bit nonce (12 bytes)

It demonstrates:
1) "ciphertext = plaintext XOR keystream"
2) how ChaCha20 generates keystream blocks
3) why reusing the same (key, nonce) is catastrophic (two-time pad)

Run:
  python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


U32_MASK = 0xFFFFFFFF


def _require_bytes(value: object, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes-like")
    return bytes(value)


def _require_int(value: object, name: str) -> int:
    if not isinstance(value, int):
        raise TypeError(f"{name} must be int")
    return int(value)


def to_hex(data: bytes) -> str:
    data = _require_bytes(data, "data")
    return data.hex()


def from_hex(hex_str: str) -> bytes:
    if not isinstance(hex_str, str):
        raise TypeError("hex_str must be str")
    try:
        return bytes.fromhex(hex_str)
    except ValueError as e:
        raise ValueError("invalid hex string") from e


def xor_bytes(a: bytes, b: bytes) -> bytes:
    a = _require_bytes(a, "a")
    b = _require_bytes(b, "b")
    if len(a) != len(b):
        raise ValueError("inputs must have the same length")
    return bytes(x ^ y for x, y in zip(a, b))


def xor_with_keystream(data: bytes, keystream: bytes) -> bytes:
    data = _require_bytes(data, "data")
    keystream = _require_bytes(keystream, "keystream")
    if len(keystream) < len(data):
        raise ValueError("keystream must be at least as long as data")
    return bytes(x ^ y for x, y in zip(data, keystream[: len(data)]))


def rotl32(x: int, n: int) -> int:
    x = _require_int(x, "x")
    n = _require_int(n, "n")
    if n < 0 or n >= 32:
        raise ValueError("n must be in [0, 31]")
    x &= U32_MASK
    return ((x << n) & U32_MASK) | (x >> (32 - n))


def _le_u32_to_int(block4: bytes) -> int:
    if len(block4) != 4:
        raise ValueError("block4 must be exactly 4 bytes")
    return int.from_bytes(block4, "little")


def _int_to_le_u32(x: int) -> bytes:
    x = _require_int(x, "x")
    return (x & U32_MASK).to_bytes(4, "little")


def quarter_round(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    a = _require_int(a, "a") & U32_MASK
    b = _require_int(b, "b") & U32_MASK
    c = _require_int(c, "c") & U32_MASK
    d = _require_int(d, "d") & U32_MASK

    a = (a + b) & U32_MASK
    d ^= a
    d = rotl32(d, 16)

    c = (c + d) & U32_MASK
    b ^= c
    b = rotl32(b, 12)

    a = (a + b) & U32_MASK
    d ^= a
    d = rotl32(d, 8)

    c = (c + d) & U32_MASK
    b ^= c
    b = rotl32(b, 7)

    return a, b, c, d


def _rounds_20(state: list[int]) -> list[int]:
    if len(state) != 16:
        raise ValueError("state must have 16 words")

    x = [w & U32_MASK for w in state]
    for _ in range(10):
        x[0], x[4], x[8], x[12] = quarter_round(x[0], x[4], x[8], x[12])
        x[1], x[5], x[9], x[13] = quarter_round(x[1], x[5], x[9], x[13])
        x[2], x[6], x[10], x[14] = quarter_round(x[2], x[6], x[10], x[14])
        x[3], x[7], x[11], x[15] = quarter_round(x[3], x[7], x[11], x[15])

        x[0], x[5], x[10], x[15] = quarter_round(x[0], x[5], x[10], x[15])
        x[1], x[6], x[11], x[12] = quarter_round(x[1], x[6], x[11], x[12])
        x[2], x[7], x[8], x[13] = quarter_round(x[2], x[7], x[8], x[13])
        x[3], x[4], x[9], x[14] = quarter_round(x[3], x[4], x[9], x[14])

    return x


def _chacha20_state(key: bytes, counter: int, nonce: bytes) -> list[int]:
    key = _require_bytes(key, "key")
    nonce = _require_bytes(nonce, "nonce")
    counter = _require_int(counter, "counter")

    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    if counter < 0 or counter > U32_MASK:
        raise ValueError("counter must be a 32-bit unsigned integer")

    constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    key_words = [_le_u32_to_int(key[i : i + 4]) for i in range(0, 32, 4)]
    nonce_words = [_le_u32_to_int(nonce[i : i + 4]) for i in range(0, 12, 4)]
    return constants + key_words + [counter] + nonce_words


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = _chacha20_state(key, counter, nonce)
    working = _rounds_20(state)
    out_words = [(w + s) & U32_MASK for w, s in zip(working, state)]
    return b"".join(_int_to_le_u32(w) for w in out_words)


def chacha20_keystream(key: bytes, nonce: bytes, initial_counter: int, length: int) -> bytes:
    key = _require_bytes(key, "key")
    nonce = _require_bytes(nonce, "nonce")
    initial_counter = _require_int(initial_counter, "initial_counter")
    length = _require_int(length, "length")

    if length < 0:
        raise ValueError("length must be >= 0")
    if initial_counter < 0 or initial_counter > U32_MASK:
        raise ValueError("initial_counter must be a 32-bit unsigned integer")

    blocks: list[bytes] = []
    remaining = length
    counter = initial_counter
    while remaining > 0:
        blocks.append(chacha20_block(key, counter, nonce))
        counter = (counter + 1) & U32_MASK
        remaining -= 64
    return b"".join(blocks)[:length]


def chacha20_encrypt(plaintext: bytes, key: bytes, nonce: bytes, initial_counter: int = 1) -> bytes:
    plaintext = _require_bytes(plaintext, "plaintext")
    keystream = chacha20_keystream(key, nonce, initial_counter, len(plaintext))
    return xor_with_keystream(plaintext, keystream)


def chacha20_decrypt(ciphertext: bytes, key: bytes, nonce: bytes, initial_counter: int = 1) -> bytes:
    ciphertext = _require_bytes(ciphertext, "ciphertext")
    keystream = chacha20_keystream(key, nonce, initial_counter, len(ciphertext))
    return xor_with_keystream(ciphertext, keystream)


@dataclass(frozen=True)
class Packet:
    nonce: bytes
    ciphertext: bytes


def pack_stream_cipher_message(plaintext: bytes, key: bytes, nonce: bytes) -> Packet:
    nonce = _require_bytes(nonce, "nonce")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    ciphertext = chacha20_encrypt(plaintext, key, nonce, initial_counter=1)
    return Packet(nonce=nonce, ciphertext=ciphertext)


def demo_keystream_reuse_attack(c1: bytes, c2: bytes, known_p1: bytes) -> bytes:
    c1 = _require_bytes(c1, "c1")
    c2 = _require_bytes(c2, "c2")
    known_p1 = _require_bytes(known_p1, "known_p1")
    if len(c1) != len(c2) or len(c1) != len(known_p1):
        raise ValueError("c1, c2, and known_p1 must have the same length")
    return xor_bytes(xor_bytes(c1, c2), known_p1)


def _chunk_hex(data: bytes, width: int = 32) -> str:
    data = _require_bytes(data, "data")
    width = _require_int(width, "width")
    if width <= 0:
        raise ValueError("width must be > 0")
    h = data.hex()
    return "\n".join(h[i : i + width] for i in range(0, len(h), width))


def main() -> None:
    print("=== Step 1: Stream ciphers are XOR with a keystream ===")
    msg = b"this is a secret message"
    fake_keystream = bytes(range(len(msg)))
    ct = xor_with_keystream(msg, fake_keystream)
    pt = xor_with_keystream(ct, fake_keystream)
    print(f"plaintext  = {msg!r}")
    print(f"keystream  = {to_hex(fake_keystream)}")
    print(f"ciphertext = {to_hex(ct)}")
    print(f"roundtrip  = {pt!r}")
    print()

    print("=== Step 2: ChaCha20 quarter round (RFC 8439 test) ===")
    a, b, c, d = 0x11111111, 0x01020304, 0x9B8D6F43, 0x01234567
    a2, b2, c2, d2 = quarter_round(a, b, c, d)
    print(f"in : {a:08x} {b:08x} {c:08x} {d:08x}")
    print(f"out: {a2:08x} {b2:08x} {c2:08x} {d2:08x}")
    print()

    print("=== Step 3: ChaCha20 block function (first 64 bytes of keystream) ===")
    key = from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    nonce = from_hex("000000090000004a00000000")
    block = chacha20_block(key, counter=1, nonce=nonce)
    print("key   =", to_hex(key))
    print("nonce =", to_hex(nonce))
    print("block =")
    print(_chunk_hex(block, width=32))
    print()

    print("=== Step 4: Encrypt/decrypt and the nonce-reuse disaster ===")
    nonce_msg = from_hex("000000000000000000000002")
    p1 = b"send more money!!"
    p2 = b"meet at the park!"
    c1 = chacha20_encrypt(p1, key, nonce_msg, initial_counter=1)
    c2 = chacha20_encrypt(p2, key, nonce_msg, initial_counter=1)
    recovered_p2 = demo_keystream_reuse_attack(c1, c2, known_p1=p1)

    print(f"p1        = {p1!r}")
    print(f"p2        = {p2!r}")
    print(f"nonce     = {to_hex(nonce_msg)}  (reused: this is the bug)")
    print(f"c1 (hex)  = {to_hex(c1)}")
    print(f"c2 (hex)  = {to_hex(c2)}")
    print(f"c1^c2(hex)= {to_hex(xor_bytes(c1, c2))}  (equals p1^p2)")
    print(f"if attacker knows p1, p2 = (c1^c2)^p1 = {recovered_p2!r}")
    print()

    print("Also: stream ciphers provide no integrity (bit flipping)")
    pkt = pack_stream_cipher_message(b"pay bob $100", key, from_hex("000000000000000000000003"))
    tampered = bytearray(pkt.ciphertext)
    tampered[8] ^= 0x01
    tampered_pt = chacha20_decrypt(bytes(tampered), key, pkt.nonce, initial_counter=1)
    print(f"ciphertext (hex) = {to_hex(pkt.ciphertext)}")
    print(f"tampered    (hex) = {to_hex(bytes(tampered))}")
    print(f"decrypt(tampered) = {tampered_pt!r}")


if __name__ == "__main__":
    main()
