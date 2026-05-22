"""
Fault attack demo (educational).

Run:
  python3 code/main.py

This lesson demonstrates a classic fault attack against RSA-CRT: if a single
faulty signature (or decryption result) is produced during CRT recombination,
an attacker can often factor N with a GCD.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import gcd
from typing import Optional, Tuple


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
class RSAKeyCRT:
    p: int
    q: int
    e: int
    d: int

    @property
    def n(self) -> int:
        return self.p * self.q

    @property
    def dp(self) -> int:
        return self.d % (self.p - 1)

    @property
    def dq(self) -> int:
        return self.d % (self.q - 1)

    @property
    def qinv(self) -> int:
        return inv_mod(self.q, self.p)


def rsa_encrypt(m: int, n: int, e: int) -> int:
    if not (0 <= m < n):
        raise ValueError("m out of range")
    return pow(m, e, n)


def rsa_decrypt_crt(c: int, key: RSAKeyCRT, fault_mod_p: Optional[int] = None) -> int:
    if not (0 <= c < key.n):
        raise ValueError("c out of range")
    mp = pow(c, key.dp, key.p)
    mq = pow(c, key.dq, key.q)
    if fault_mod_p is not None:
        mp = fault_mod_p % key.p
    h = (key.qinv * (mp - mq)) % key.p
    return mq + h * key.q


def factor_from_faulty_pair(n: int, correct: int, faulty: int) -> Tuple[int, int]:
    g = gcd((correct - faulty) % n, n)
    if g == 1 or g == n:
        raise ValueError("fault did not reveal a factor")
    p = g
    q = n // g
    return (min(p, q), max(p, q))


def _toy_key() -> RSAKeyCRT:
    p = 251444687128489
    q = 274004257255073
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 5
    d = inv_mod(e, phi)
    if (e * d) % phi != 1:
        raise AssertionError("bad key")
    return RSAKeyCRT(p=p, q=q, e=e, d=d)


def main():
    key = _toy_key()
    msg = 123456789
    c = rsa_encrypt(msg, key.n, key.e)

    print("=== Step 1: CRT-RSA decryption/signing ===")
    s_ok = rsa_decrypt_crt(c, key)
    print("roundtrip_ok:", s_ok == msg)

    print("=== Step 2: Inject a fault in one CRT branch ===")
    s_faulty = rsa_decrypt_crt(c, key, fault_mod_p=(s_ok + 1) % key.p)
    print("faulty_differs:", s_faulty != s_ok)

    print("=== Step 3: Use GCD to factor N from (correct, faulty) ===")
    p, q = factor_from_faulty_pair(key.n, s_ok, s_faulty)
    print("recovered_p:", p)
    print("recovered_q:", q)


if __name__ == "__main__":
    main()
