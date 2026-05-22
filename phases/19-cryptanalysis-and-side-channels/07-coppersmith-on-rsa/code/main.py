"""
Coppersmith-style small-root demo (educational, brute-force).

Run:
  python3 code/main.py

This lesson demonstrates the idea behind Coppersmith attacks: if you can build a
polynomial f(x) such that f(x0) == 0 (mod N) and the root x0 is small, then you
can recover x0. Real Coppersmith uses lattices; this demo uses brute force on
tiny parameters.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple


def poly_eval_mod(coeffs: List[int], x: int, n: int) -> int:
    acc = 0
    for c in coeffs:
        acc = (acc * x + c) % n
    return acc


def find_small_root_bruteforce(coeffs: List[int], n: int, x_bound: int) -> Optional[int]:
    for x in range(x_bound):
        if poly_eval_mod(coeffs, x, n) == 0:
            return x
    return None


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


@dataclass(frozen=True)
class RSAKey:
    n: int
    e: int
    d: int


def rsa_encrypt(m: int, n: int, e: int) -> int:
    if not (0 <= m < n):
        raise ValueError("m out of range")
    return pow(m, e, n)


def rsa_decrypt(c: int, n: int, d: int) -> int:
    if not (0 <= c < n):
        raise ValueError("c out of range")
    return pow(c, d, n)


def build_stereotyped_message_polynomial(m0: int, e: int, c: int, n: int) -> List[int]:
    if e != 3:
        raise ValueError("demo uses e=3")
    a3 = 1
    a2 = (3 * m0) % n
    a1 = (3 * (m0 % n) * (m0 % n)) % n
    a0 = (pow(m0, 3, n) - c) % n
    return [a3, a2, a1, a0]


def _toy_key() -> RSAKey:
    p = 4294967357
    q = 4294967387
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 3
    d = inv_mod(e, phi)
    return RSAKey(n=n, e=e, d=d)


def main():
    key = _toy_key()
    m0 = 1234567890000
    x0 = 4242
    m = m0 + x0
    c = rsa_encrypt(m, key.n, key.e)

    print("=== Step 1: Build a modular polynomial with a small root ===")
    coeffs = build_stereotyped_message_polynomial(m0, key.e, c, key.n)
    print("f(x0) mod N:", poly_eval_mod(coeffs, x0, key.n))

    print("=== Step 2: Find the small root by brute force (toy) ===")
    x = find_small_root_bruteforce(coeffs, key.n, x_bound=1 << 16)
    print("recovered_x:", x)

    print("=== Step 3: Recover the full message from m0 + x ===")
    if x is None:
        raise RuntimeError("root not found")
    recovered_m = m0 + x
    print("recovered_m:", recovered_m)
    print("decrypt(c)  :", rsa_decrypt(c, key.n, key.d))


if __name__ == "__main__":
    main()
