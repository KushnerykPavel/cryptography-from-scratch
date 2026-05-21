"""
Toy NewHope/Saber building blocks (educational).

This script demonstrates:
- Negacyclic polynomial arithmetic in R_q = Z_q[x]/(x^n + 1)
- Small-noise sampling via centered binomial distribution (CBD)
- A tiny RLWE-style PKE (NewHope-family flavor): encode bit -> coefficient near 0 or q/2
- A tiny LWR-style PKE (Saber-family flavor): deterministic rounding noise (chop bits)

Run:
  python3 code/main.py

Notes:
- Parameters are intentionally small so the math is visible and naive O(n^2) multiplication is fast.
- Educational implementation. Not constant-time. Not production-safe.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable, List, Tuple


NEWHOPE_Q = 12289
SABER_Q = 8192
SABER_P = 1024

TOY_N = 16
TOY_ETA = 4


def xof(seed: bytes, domain: bytes, outlen: int) -> bytes:
    if outlen < 0:
        raise ValueError("outlen must be non-negative")
    return hashlib.shake_256(domain + seed).digest(outlen)


def _bit_at(buf: bytes, bit_index: int) -> int:
    if bit_index < 0:
        raise ValueError("bit_index must be non-negative")
    return (buf[bit_index // 8] >> (bit_index % 8)) & 1


def sample_small_poly_cbd(seed: bytes, n: int, eta: int, domain: bytes = b"cbd") -> List[int]:
    if n <= 0:
        raise ValueError("n must be positive")
    if eta <= 0:
        raise ValueError("eta must be positive")

    bits_needed = n * 2 * eta
    buf = xof(seed, domain, (bits_needed + 7) // 8)
    coeffs: List[int] = []
    bitpos = 0
    for _ in range(n):
        a = 0
        b = 0
        for _ in range(eta):
            a += _bit_at(buf, bitpos)
            bitpos += 1
        for _ in range(eta):
            b += _bit_at(buf, bitpos)
            bitpos += 1
        coeffs.append(a - b)
    return coeffs


def uniform_poly(seed: bytes, n: int, q: int, domain: bytes = b"uniform") -> List[int]:
    if n <= 0:
        raise ValueError("n must be positive")
    if q <= 1:
        raise ValueError("q must be > 1")

    limit = (65536 // q) * q
    out: List[int] = []
    counter = 0
    buf = b""
    pos = 0
    while len(out) < n:
        if pos + 2 > len(buf):
            counter_bytes = counter.to_bytes(4, "little")
            buf = xof(seed, domain + counter_bytes, 256)
            pos = 0
            counter += 1
        val = int.from_bytes(buf[pos : pos + 2], "little")
        pos += 2
        if val < limit:
            out.append(val % q)
    return out


def mod_q(x: int, q: int) -> int:
    return x % q


def poly_add(a: List[int], b: List[int], q: int) -> List[int]:
    if len(a) != len(b):
        raise ValueError("length mismatch")
    return [(x + y) % q for x, y in zip(a, b)]


def poly_sub(a: List[int], b: List[int], q: int) -> List[int]:
    if len(a) != len(b):
        raise ValueError("length mismatch")
    return [(x - y) % q for x, y in zip(a, b)]


def poly_mul_negacyclic(a: List[int], b: List[int], q: int) -> List[int]:
    if len(a) != len(b):
        raise ValueError("length mismatch")
    n = len(a)
    acc = [0] * n
    for i in range(n):
        ai = a[i]
        for j in range(n):
            prod = ai * b[j]
            k = i + j
            if k < n:
                acc[k] += prod
            else:
                acc[k - n] -= prod
    return [x % q for x in acc]


def poly_round_to_p(poly: List[int], q: int, p: int) -> List[int]:
    if p <= 0 or (q % p) != 0:
        raise ValueError("require p>0 and p|q")
    scale = q // p
    half = scale // 2
    out: List[int] = []
    for x in poly:
        out.append(((x + half) // scale) % p)
    return out


def poly_lift_from_p(poly_p: List[int], q: int, p: int) -> List[int]:
    if p <= 0 or (q % p) != 0:
        raise ValueError("require p>0 and p|q")
    scale = q // p
    return [(x % p) * scale % q for x in poly_p]


def _dist_mod(a: int, b: int, q: int) -> int:
    d = (a - b) % q
    return min(d, q - d)


def encode_bits_as_poly(bits: Iterable[int], q: int) -> List[int]:
    half = q // 2
    out = []
    for bit in bits:
        if bit not in (0, 1):
            raise ValueError("bits must be 0/1")
        out.append((bit * half) % q)
    return out


def decode_poly_to_bits(poly: List[int], q: int) -> List[int]:
    half = q // 2
    out: List[int] = []
    for x in poly:
        d0 = _dist_mod(x, 0, q)
        d1 = _dist_mod(x, half, q)
        out.append(1 if d1 < d0 else 0)
    return out


@dataclass(frozen=True)
class RLWEPublicKey:
    seed_a: bytes
    b: List[int]


@dataclass(frozen=True)
class RLWESecretKey:
    s: List[int]


def rlwe_keygen(seed_a: bytes, seed_s: bytes, n: int = TOY_N, q: int = NEWHOPE_Q, eta: int = TOY_ETA) -> Tuple[RLWEPublicKey, RLWESecretKey]:
    a = uniform_poly(seed_a, n=n, q=q, domain=b"rlwe-a")
    s = sample_small_poly_cbd(seed_s, n=n, eta=eta, domain=b"rlwe-s")
    e = sample_small_poly_cbd(seed_s, n=n, eta=eta, domain=b"rlwe-e")

    as_ = poly_mul_negacyclic(a, [x % q for x in s], q)
    b = poly_add(as_, [x % q for x in e], q)
    return RLWEPublicKey(seed_a=seed_a, b=b), RLWESecretKey(s=[x % q for x in s])


def rlwe_encrypt(pk: RLWEPublicKey, msg_bits: List[int], seed_r: bytes, n: int = TOY_N, q: int = NEWHOPE_Q, eta: int = TOY_ETA) -> Tuple[List[int], List[int]]:
    if len(msg_bits) != n:
        raise ValueError("msg_bits length must equal n")
    a = uniform_poly(pk.seed_a, n=n, q=q, domain=b"rlwe-a")
    sp = sample_small_poly_cbd(seed_r, n=n, eta=eta, domain=b"rlwe-sp")
    ep = sample_small_poly_cbd(seed_r, n=n, eta=eta, domain=b"rlwe-ep")
    epp = sample_small_poly_cbd(seed_r, n=n, eta=eta, domain=b"rlwe-epp")

    u = poly_add(poly_mul_negacyclic(a, [x % q for x in sp], q), [x % q for x in ep], q)
    v = poly_add(poly_mul_negacyclic(pk.b, [x % q for x in sp], q), [x % q for x in epp], q)
    v = poly_add(v, encode_bits_as_poly(msg_bits, q), q)
    return u, v


def rlwe_decrypt(sk: RLWESecretKey, ct: Tuple[List[int], List[int]], n: int = TOY_N, q: int = NEWHOPE_Q) -> List[int]:
    u, v = ct
    if len(u) != n or len(v) != n:
        raise ValueError("ciphertext polynomials must have length n")
    us = poly_mul_negacyclic(u, [x % q for x in sk.s], q)
    mpoly = poly_sub(v, us, q)
    return decode_poly_to_bits(mpoly, q)


@dataclass(frozen=True)
class LWRPublicKey:
    seed_a: bytes
    b_p: List[int]


@dataclass(frozen=True)
class LWRSecretKey:
    s: List[int]


def lwr_keygen(seed_a: bytes, seed_s: bytes, n: int = TOY_N, q: int = SABER_Q, p: int = SABER_P, eta: int = TOY_ETA) -> Tuple[LWRPublicKey, LWRSecretKey]:
    a = uniform_poly(seed_a, n=n, q=q, domain=b"lwr-a")
    s = sample_small_poly_cbd(seed_s, n=n, eta=eta, domain=b"lwr-s")
    as_ = poly_mul_negacyclic(a, [x % q for x in s], q)
    b_p = poly_round_to_p(as_, q=q, p=p)
    return LWRPublicKey(seed_a=seed_a, b_p=b_p), LWRSecretKey(s=[x % q for x in s])


def lwr_encrypt(pk: LWRPublicKey, msg_bits: List[int], seed_r: bytes, n: int = TOY_N, q: int = SABER_Q, p: int = SABER_P, eta: int = TOY_ETA) -> Tuple[List[int], List[int]]:
    if len(msg_bits) != n:
        raise ValueError("msg_bits length must equal n")
    a = uniform_poly(pk.seed_a, n=n, q=q, domain=b"lwr-a")
    sp = sample_small_poly_cbd(seed_r, n=n, eta=eta, domain=b"lwr-sp")
    ep = sample_small_poly_cbd(seed_r, n=n, eta=eta, domain=b"lwr-ep")

    u = poly_add(poly_mul_negacyclic(a, [x % q for x in sp], q), [x % q for x in ep], q)

    b_lift = poly_lift_from_p(pk.b_p, q=q, p=p)
    v = poly_mul_negacyclic(b_lift, [x % q for x in sp], q)
    v_p = poly_round_to_p(v, q=q, p=p)

    half_p = p // 2
    v_p = [(x + (bit * half_p)) % p for x, bit in zip(v_p, msg_bits)]
    return u, v_p


def lwr_decrypt(sk: LWRSecretKey, ct: Tuple[List[int], List[int]], n: int = TOY_N, q: int = SABER_Q, p: int = SABER_P) -> List[int]:
    u, v_p = ct
    if len(u) != n or len(v_p) != n:
        raise ValueError("ciphertext polynomials must have length n")
    us = poly_mul_negacyclic(u, [x % q for x in sk.s], q)
    us_p = poly_round_to_p(us, q=q, p=p)

    half_p = p // 2
    out: List[int] = []
    for x, y in zip(v_p, us_p):
        d0 = _dist_mod((x - y) % p, 0, p)
        d1 = _dist_mod((x - y) % p, half_p, p)
        out.append(1 if d1 < d0 else 0)
    return out


def _format_poly(poly: List[int], max_terms: int = 8) -> str:
    head = poly[:max_terms]
    tail = "" if len(poly) <= max_terms else ", ..."
    return "[" + ", ".join(str(x) for x in head) + tail + "]"


def main():
    n = TOY_N

    print("=== Step 1: Ring arithmetic (negacyclic polynomials) ===")
    a = [1, 2, 3] + [0] * (n - 3)
    b = [4, 5, 6] + [0] * (n - 3)
    c = poly_mul_negacyclic(a, b, q=NEWHOPE_Q)
    print("a =", _format_poly(a))
    print("b =", _format_poly(b))
    print("a*b mod (x^n+1, q) =", _format_poly(c))
    print()

    print("=== Step 2: Noise sampling (CBD) ===")
    noise = sample_small_poly_cbd(b"demo-seed", n=n, eta=TOY_ETA, domain=b"demo-cbd")
    print("eta =", TOY_ETA)
    print("noise =", _format_poly(noise))
    print()

    print("=== Step 3: NewHope-style RLWE PKE (toy) ===")
    pk, sk = rlwe_keygen(seed_a=b"public-a", seed_s=b"alice-secret")
    msg = [int(x) for x in (0, 1) * (n // 2)]
    ct = rlwe_encrypt(pk, msg_bits=msg, seed_r=b"bob-ephemeral")
    dec = rlwe_decrypt(sk, ct)
    print("msg bits =", msg)
    print("dec bits =", dec)
    print("match =", dec == msg)
    print()

    print("=== Step 4: Saber-style LWR PKE (toy) ===")
    pk2, sk2 = lwr_keygen(seed_a=b"public-a2", seed_s=b"alice-secret2")
    msg2 = [1] * (n // 2) + [0] * (n // 2)
    ct2 = lwr_encrypt(pk2, msg_bits=msg2, seed_r=b"bob-ephemeral2")
    dec2 = lwr_decrypt(sk2, ct2)
    print("msg bits =", msg2)
    print("dec bits =", dec2)
    print("match =", dec2 == msg2)


if __name__ == "__main__":
    main()
