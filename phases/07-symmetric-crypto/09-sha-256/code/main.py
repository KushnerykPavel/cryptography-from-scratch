"""
SHA-256 from scratch (educational).

This file implements SHA-256 in pure Python (stdlib only), plus a small
streaming interface for incremental hashing.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable, List


_IV: List[int] = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]

_K: List[int] = [
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
]


def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def rotr32(x: int, n: int) -> int:
    if not (0 <= n <= 31):
        raise ValueError("n must be in [0, 31]")
    x = _u32(x)
    return _u32((x >> n) | (x << (32 - n)))


def _ch(x: int, y: int, z: int) -> int:
    return (x & y) ^ (~x & z)


def _maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)


def _Sigma0(x: int) -> int:
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22)


def _Sigma1(x: int) -> int:
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25)


def _sigma0(x: int) -> int:
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (_u32(x) >> 3)


def _sigma1(x: int) -> int:
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (_u32(x) >> 10)


def sha256_padding(message_len_bytes: int) -> bytes:
    if message_len_bytes < 0:
        raise ValueError("message_len_bytes must be non-negative")

    bit_len = message_len_bytes * 8
    if bit_len >= 1 << 64:
        raise ValueError("message too long for SHA-256 length field")

    pad = bytearray()
    pad.append(0x80)
    while ((message_len_bytes + len(pad)) % 64) != 56:
        pad.append(0)
    pad.extend(bit_len.to_bytes(8, "big"))
    return bytes(pad)


def _iter_chunks(data: bytes, chunk_size: int) -> Iterable[bytes]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    for i in range(0, len(data), chunk_size):
        yield data[i : i + chunk_size]


def _sha256_compress(h: List[int], chunk: bytes) -> None:
    if len(chunk) != 64:
        raise ValueError("chunk must be 64 bytes")

    w = [0] * 64
    for i in range(16):
        w[i] = int.from_bytes(chunk[i * 4 : (i + 1) * 4], "big")
    for i in range(16, 64):
        w[i] = _u32(_sigma1(w[i - 2]) + w[i - 7] + _sigma0(w[i - 15]) + w[i - 16])

    a, b, c, d, e, f, g, hh = h

    for i in range(64):
        t1 = _u32(hh + _Sigma1(e) + _ch(e, f, g) + _K[i] + w[i])
        t2 = _u32(_Sigma0(a) + _maj(a, b, c))
        hh = g
        g = f
        f = e
        e = _u32(d + t1)
        d = c
        c = b
        b = a
        a = _u32(t1 + t2)

    h[0] = _u32(h[0] + a)
    h[1] = _u32(h[1] + b)
    h[2] = _u32(h[2] + c)
    h[3] = _u32(h[3] + d)
    h[4] = _u32(h[4] + e)
    h[5] = _u32(h[5] + f)
    h[6] = _u32(h[6] + g)
    h[7] = _u32(h[7] + hh)


def sha256(message: bytes) -> bytes:
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes-like")

    data = bytes(message)
    data += sha256_padding(len(data))

    h = _IV[:]
    for chunk in _iter_chunks(data, 64):
        _sha256_compress(h, chunk)

    return b"".join(x.to_bytes(4, "big") for x in h)


def sha256_hex(message: bytes) -> str:
    return sha256(message).hex()


@dataclass
class SHA256:
    _h: List[int]
    _total_len: int
    _buf: bytes

    def __init__(self, data: bytes = b""):
        self._h = _IV[:]
        self._total_len = 0
        self._buf = b""
        if data:
            self.update(data)

    def copy(self) -> "SHA256":
        clone = SHA256()
        clone._h = self._h[:]
        clone._total_len = self._total_len
        clone._buf = self._buf
        return clone

    def update(self, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes-like")

        if not data:
            return

        self._total_len += len(data)
        data_bytes = self._buf + bytes(data)

        full_len = (len(data_bytes) // 64) * 64
        for chunk in _iter_chunks(data_bytes[:full_len], 64):
            _sha256_compress(self._h, chunk)
        self._buf = data_bytes[full_len:]

    def digest(self) -> bytes:
        clone = self.copy()
        clone.update(sha256_padding(clone._total_len))
        if clone._buf:
            raise AssertionError("buffer must be empty after final padding")
        return b"".join(x.to_bytes(4, "big") for x in clone._h)

    def hexdigest(self) -> str:
        return self.digest().hex()


def main() -> None:
    print("=== Step 1: 32-bit words ===")
    x = 0x12345678
    print(f"rotr32(0x{x:08x}, 8) = 0x{rotr32(x, 8):08x}")

    print("\n=== Step 2: Padding ===")
    msg = b"abc"
    pad = sha256_padding(len(msg))
    padded_len = len(msg) + len(pad)
    print(f"len(msg) = {len(msg)} bytes")
    print(f"padding length = {len(pad)} bytes")
    print(f"len(msg || pad) = {padded_len} bytes (multiple of 64? {padded_len % 64 == 0})")

    print("\n=== Step 3: Compression + digest ===")
    print(f"sha256_hex(b'abc') = {sha256_hex(b'abc')}")
    print(f"sha256_hex(b'')    = {sha256_hex(b'')}")

    print("\n=== Step 4: Streaming vs stdlib hashlib ===")
    hasher = SHA256()
    hasher.update(b"a")
    hasher.update(b"b")
    hasher.update(b"c")
    ours = hasher.hexdigest()
    std = hashlib.sha256(b"abc").hexdigest()
    print(f"streaming SHA256('a'+'b'+'c') = {ours}")
    print(f"hashlib.sha256(b'abc')        = {std}")
    print(f"match? {ours == std}")


if __name__ == "__main__":
    main()
