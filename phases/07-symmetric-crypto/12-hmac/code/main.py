"""
HMAC (SHA-256) from scratch (educational).

Run:
  python3 code/main.py

This script implements the HMAC construction using the stdlib SHA-256 hash and
demonstrates:
- key normalization to the hash block size
- the ipad/opad two-pass structure
- safe tag verification (no `==` on secrets)
- tag truncation as a protocol choice
"""

from __future__ import annotations

import hashlib


class HmacError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise HmacError(message)


def _as_bytes(x: bytes | bytearray, *, name: str) -> bytes:
    if not isinstance(x, (bytes, bytearray)):
        raise HmacError(f"{name} must be bytes-like")
    return bytes(x)


SHA256_BLOCK_SIZE = 64
SHA256_DIGEST_SIZE = 32


def sha256(data: bytes | bytearray) -> bytes:
    b = _as_bytes(data, name="data")
    return hashlib.sha256(b).digest()


def xor_bytes(a: bytes | bytearray, b: bytes | bytearray) -> bytes:
    aa = _as_bytes(a, name="a")
    bb = _as_bytes(b, name="b")
    _require(len(aa) == len(bb), "a and b must have the same length")
    return bytes(x ^ y for x, y in zip(aa, bb))


def normalize_hmac_key_sha256(key: bytes | bytearray) -> bytes:
    k = _as_bytes(key, name="key")
    if len(k) > SHA256_BLOCK_SIZE:
        k = sha256(k)
    return k.ljust(SHA256_BLOCK_SIZE, b"\x00")


def hmac_sha256(key: bytes | bytearray, msg: bytes | bytearray) -> bytes:
    k0 = normalize_hmac_key_sha256(key)
    m = _as_bytes(msg, name="msg")

    ipad = bytes([0x36]) * SHA256_BLOCK_SIZE
    opad = bytes([0x5C]) * SHA256_BLOCK_SIZE

    inner = sha256(xor_bytes(k0, ipad) + m)
    return sha256(xor_bytes(k0, opad) + inner)


def hmac_sha256_truncated(key: bytes | bytearray, msg: bytes | bytearray, tag_len: int) -> bytes:
    _require(isinstance(tag_len, int), "tag_len must be int")
    _require(0 <= tag_len <= SHA256_DIGEST_SIZE, "tag_len out of range for SHA-256")
    return hmac_sha256(key, msg)[:tag_len]


def constant_time_equal(a: bytes | bytearray, b: bytes | bytearray) -> bool:
    aa = _as_bytes(a, name="a")
    bb = _as_bytes(b, name="b")
    if len(aa) != len(bb):
        return False
    diff = 0
    for x, y in zip(aa, bb):
        diff |= x ^ y
    return diff == 0


def verify_hmac_sha256(key: bytes | bytearray, msg: bytes | bytearray, tag: bytes | bytearray) -> bool:
    expected = hmac_sha256(key, msg)
    return constant_time_equal(expected, tag)


def verify_hmac_sha256_truncated(
    key: bytes | bytearray, msg: bytes | bytearray, tag: bytes | bytearray, tag_len: int
) -> bool:
    expected = hmac_sha256_truncated(key, msg, tag_len)
    t = _as_bytes(tag, name="tag")
    if len(t) != tag_len:
        return False
    return constant_time_equal(expected, t)


def _demo_bytes(label: str, b: bytes) -> None:
    print(f"{label}: {b.hex()}")


def main() -> None:
    print("=== Step 1: Hash and byte helpers ===")
    _demo_bytes("sha256(b'hello')", sha256(b"hello"))
    _demo_bytes("xor_bytes(b'\\x0f\\x0f', b'\\xf0\\x00')", xor_bytes(b"\x0f\x0f", b"\xf0\x00"))
    print()

    print("=== Step 2: Normalize the HMAC key (K0) ===")
    short_key = b"key"
    long_key = b"A" * 100
    _demo_bytes("normalize_hmac_key_sha256(b'key')", normalize_hmac_key_sha256(short_key))
    _demo_bytes("normalize_hmac_key_sha256(b'A'*100)", normalize_hmac_key_sha256(long_key))
    print()

    print("=== Step 3: Compute HMAC-SHA-256 (ipad/opad) ===")
    key = b"Jefe"
    msg = b"what do ya want for nothing?"
    tag = hmac_sha256(key, msg)
    _demo_bytes("hmac_sha256(key, msg)", tag)
    print(f"tag_len={len(tag)} bytes")
    print()

    print("=== Step 4: Verify tags and truncate intentionally ===")
    ok = verify_hmac_sha256(key, msg, tag)
    bad = verify_hmac_sha256(key, msg, tag[:-1] + bytes([tag[-1] ^ 0x01]))
    print(f"verify_hmac_sha256(correct tag) -> {ok}")
    print(f"verify_hmac_sha256(mutated tag) -> {bad}")

    t16 = hmac_sha256_truncated(key, msg, 16)
    _demo_bytes("hmac_sha256_truncated(key, msg, 16)", t16)
    print(f"verify_hmac_sha256_truncated(tag_len=16) -> {verify_hmac_sha256_truncated(key, msg, t16, 16)}")
    print(f"verify_hmac_sha256_truncated(wrong_len) -> {verify_hmac_sha256_truncated(key, msg, t16 + b'\\x00', 16)}")


if __name__ == "__main__":
    main()
