"""
Crypto CTF triage walkthroughs (educational, toy problems).

Run:
  python3 code/main.py

This lesson demonstrates a practical workflow for common beginner/intermediate
CTF-style crypto tasks: decode layers, crack single-byte XOR, and spot shared
prime factors in RSA moduli.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from math import gcd
from typing import Optional, Tuple


def looks_like_hex(s: str) -> bool:
    if len(s) % 2 != 0 or not s:
        return False
    for ch in s:
        if ch not in "0123456789abcdefABCDEF":
            return False
    return True


def decode_hex_or_base64(s: str) -> bytes:
    if looks_like_hex(s):
        return bytes.fromhex(s)
    return base64.b64decode(s, validate=True)


def xor_with_byte(data: bytes, k: int) -> bytes:
    if k < 0 or k > 255:
        raise ValueError("k must be a byte")
    return bytes(b ^ k for b in data)


def score_english(data: bytes) -> float:
    if not data:
        return -1e9
    score = 0.0
    for b in data:
        if 32 <= b <= 126:
            score += 1.0
        if b in b" etaoinshrdluETAOINSHRDLU":
            score += 1.0
        if b in b"\n\r\t":
            score += 0.2
    bad = sum(1 for b in data if b < 9 or (13 < b < 32) or b > 126)
    score -= 5.0 * bad
    return score


def break_single_byte_xor(ciphertext: bytes) -> Tuple[int, bytes]:
    best_k = 0
    best_pt = b""
    best_score = -1e18
    for k in range(256):
        pt = xor_with_byte(ciphertext, k)
        s = score_english(pt)
        if s > best_score:
            best_score = s
            best_k = k
            best_pt = pt
    return best_k, best_pt


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def inv_mod(a: int, n: int) -> int:
    a %= n
    g, x, _ = egcd(a, n)
    if g != 1:
        raise ValueError("not invertible")
    return x % n


def i2osp(x: int, k: int) -> bytes:
    return x.to_bytes(k, "big")


def os2ip(b: bytes) -> int:
    return int.from_bytes(b, "big")


@dataclass(frozen=True)
class RSAPublic:
    n: int
    e: int

    @property
    def k(self) -> int:
        return (self.n.bit_length() + 7) // 8


def rsa_encrypt_bytes(m: bytes, pub: RSAPublic) -> int:
    mi = os2ip(m)
    if mi >= pub.n:
        raise ValueError("message too large")
    return pow(mi, pub.e, pub.n)


def rsa_decrypt_int(c: int, p: int, q: int, e: int) -> bytes:
    n = p * q
    phi = (p - 1) * (q - 1)
    d = inv_mod(e, phi)
    m = pow(c, d, n)
    k = (n.bit_length() + 7) // 8
    return i2osp(m, k).lstrip(b"\x00")


def find_shared_prime(n1: int, n2: int) -> Optional[int]:
    g = gcd(n1, n2)
    if g == 1 or g == n1 or g == n2:
        return None
    return g


def main():
    print("=== Step 1: Decode layers (hex vs base64) ===")
    s_hex = "48656c6c6f2c2043544621"
    s_b64 = base64.b64encode(b"hello, base64").decode("ascii")
    print("hex_decoded:", decode_hex_or_base64(s_hex))
    print("b64_decoded:", decode_hex_or_base64(s_b64))

    print("=== Step 2: Crack single-byte XOR with scoring ===")
    pt = b"crypto is fun"
    k = 42
    ct = xor_with_byte(pt, k)
    rec_k, rec_pt = break_single_byte_xor(ct)
    print("recovered_key:", rec_k)
    print("recovered_pt :", rec_pt)

    print("=== Step 3: RSA shared-prime detection (GCD) ===")
    p = 1_000_003
    q1 = 1_000_033
    q2 = 1_000_037
    e = 65537
    n1 = p * q1
    n2 = p * q2
    pub1 = RSAPublic(n=n1, e=e)
    msg = b"hi"
    c1 = rsa_encrypt_bytes(msg, pub1)
    g = find_shared_prime(n1, n2)
    if g is None:
        raise RuntimeError("expected a shared prime")
    recovered = rsa_decrypt_int(c1, p=g, q=n1 // g, e=e)
    print("shared_prime:", g)
    print("recovered_msg:", recovered)


if __name__ == "__main__":
    main()
