"""
Toy NTRUEncrypt (educational).

This file implements a minimal, from-scratch NTRU-style public-key encryption
scheme over a cyclic polynomial ring, plus a deterministic demo.

Run:
  python3 code/main.py

WARNING: Educational implementation. Not constant-time. Not production-safe.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import random
from typing import Iterable, List, Tuple


def poly_add(a: List[int], b: List[int], mod: int | None = None) -> List[int]:
    if len(a) != len(b):
        raise ValueError("poly_add: mismatched lengths")
    out = [a[i] + b[i] for i in range(len(a))]
    if mod is not None:
        out = [x % mod for x in out]
    return out


def poly_sub(a: List[int], b: List[int], mod: int | None = None) -> List[int]:
    if len(a) != len(b):
        raise ValueError("poly_sub: mismatched lengths")
    out = [a[i] - b[i] for i in range(len(a))]
    if mod is not None:
        out = [x % mod for x in out]
    return out


def poly_scalar_mul(a: List[int], k: int, mod: int | None = None) -> List[int]:
    out = [k * x for x in a]
    if mod is not None:
        out = [x % mod for x in out]
    return out


def poly_mod(a: List[int], mod: int) -> List[int]:
    return [x % mod for x in a]


def poly_center_lift(a: List[int], mod: int) -> List[int]:
    if mod <= 1:
        raise ValueError("poly_center_lift: mod must be > 1")
    half = mod // 2
    out = []
    for x in a:
        r = x % mod
        if r > half:
            r -= mod
        out.append(r)
    return out


def poly_mul_cyclic(a: List[int], b: List[int], N: int, mod: int | None = None) -> List[int]:
    if len(a) != N or len(b) != N:
        raise ValueError("poly_mul_cyclic: inputs must have length N")
    acc = [0] * N
    for i in range(N):
        ai = a[i]
        if ai == 0:
            continue
        for j in range(N):
            acc[(i + j) % N] += ai * b[j]
    if mod is not None:
        acc = [x % mod for x in acc]
    return acc


def poly_to_str(a: List[int]) -> str:
    terms = []
    for i, c in enumerate(a):
        if c == 0:
            continue
        if i == 0:
            terms.append(str(c))
        elif i == 1:
            terms.append(f"{c}·x")
        else:
            terms.append(f"{c}·x^{i}")
    if not terms:
        return "0"
    return " + ".join(terms)


def _poly_strip(a: List[int]) -> List[int]:
    a = a[:]
    while len(a) > 1 and a[-1] == 0:
        a.pop()
    return a


def _poly_add_mod(a: List[int], b: List[int], mod: int) -> List[int]:
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        out[i] = ((a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)) % mod
    return _poly_strip(out)


def _poly_sub_mod(a: List[int], b: List[int], mod: int) -> List[int]:
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        out[i] = ((a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0)) % mod
    return _poly_strip(out)


def _poly_mul_mod(a: List[int], b: List[int], mod: int) -> List[int]:
    if a == [0] or b == [0]:
        return [0]
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            out[i + j] = (out[i + j] + ai * bj) % mod
    return _poly_strip(out)


def _poly_scale_mod(a: List[int], k: int, mod: int) -> List[int]:
    return _poly_strip([(k * x) % mod for x in a])


def _poly_divmod_mod(a: List[int], b: List[int], mod: int) -> Tuple[List[int], List[int]]:
    a = _poly_strip([x % mod for x in a])
    b = _poly_strip([x % mod for x in b])
    if b == [0]:
        raise ZeroDivisionError("polynomial division by zero")
    if a == [0] or len(a) < len(b):
        return [0], a

    q = [0] * (len(a) - len(b) + 1)
    r = a[:]
    inv_lc = pow(b[-1], -1, mod)
    while r != [0] and len(r) >= len(b):
        deg = len(r) - len(b)
        coef = (r[-1] * inv_lc) % mod
        q[deg] = coef
        subtract = _poly_scale_mod(([0] * deg) + b, coef, mod)
        r = _poly_sub_mod(r, subtract, mod)
    return _poly_strip(q), _poly_strip(r)


def poly_inverse_mod_prime(f: List[int], N: int, prime: int) -> List[int]:
    """
    Compute f^{-1} in (Z/prime Z)[x] / (x^N - 1), if it exists.

    Returns a length-N polynomial with coefficients in 0..prime-1.
    """
    if prime <= 2:
        raise ValueError("poly_inverse_mod_prime: prime must be an odd prime")
    if len(f) != N:
        raise ValueError("poly_inverse_mod_prime: f must have length N")

    f_mod = [x % prime for x in f]
    phi = [(-1) % prime] + [0] * (N - 1) + [1]

    r0, r1 = _poly_strip(phi), _poly_strip(f_mod)
    s0, s1 = [1], [0]
    t0, t1 = [0], [1]

    while r1 != [0]:
        q, r2 = _poly_divmod_mod(r0, r1, prime)
        r0, r1 = r1, r2
        s0, s1 = s1, _poly_sub_mod(s0, _poly_mul_mod(q, s1, prime), prime)
        t0, t1 = t1, _poly_sub_mod(t0, _poly_mul_mod(q, t1, prime), prime)

    if len(r0) != 1 or r0[0] == 0:
        raise ValueError("polynomial is not invertible modulo (x^N - 1) over this prime")

    scale = pow(r0[0], -1, prime)
    inv = _poly_scale_mod(t0, scale, prime)  # s0*phi + inv*f = 1
    _, inv_red = _poly_divmod_mod(inv, phi, prime)
    inv_red = inv_red[:N] + [0] * (N - len(inv_red))
    return inv_red


def _rand_from_seed(seed: str) -> random.Random:
    h = hashlib.sha256(seed.encode("utf-8")).digest()
    return random.Random(int.from_bytes(h[:8], "big"))


def sample_ternary(N: int, rand: random.Random, weight: int) -> List[int]:
    """
    Sample a "small" polynomial with exactly `weight` non-zero coefficients,
    each chosen from {-1, +1}.
    """
    if weight < 0 or weight > N:
        raise ValueError("sample_ternary: invalid weight")
    out = [0] * N
    positions = list(range(N))
    rand.shuffle(positions)
    chosen = positions[:weight]
    half = weight // 2
    for i, pos in enumerate(chosen):
        out[pos] = 1 if i < half else -1
    rand.shuffle(out)
    return out


@dataclass(frozen=True)
class NTRUParams:
    N: int
    p: int
    q: int


@dataclass(frozen=True)
class NTRUPublicKey:
    params: NTRUParams
    h: List[int]  # coefficients modulo q


@dataclass(frozen=True)
class NTRUPrivateKey:
    params: NTRUParams
    f: List[int]  # small coefficients (centered integers)
    f_inv_p: List[int]  # coefficients modulo p (0..p-1)


def ntru_keygen_deterministic(params: NTRUParams, seed: str) -> Tuple[NTRUPublicKey, NTRUPrivateKey]:
    """
    Deterministic toy key generation for NTRUEncrypt-style encryption.

    This is a teaching aid: it uses small primes and brute-force sampling
    until an invertible `f` is found.
    """
    if params.p <= 2 or params.q <= 2 or params.p >= params.q:
        raise ValueError("ntru_keygen_deterministic: require 2 < p < q")
    if params.N < 3:
        raise ValueError("ntru_keygen_deterministic: N too small")

    rand = _rand_from_seed(seed)

    for _ in range(10_000):
        f = sample_ternary(params.N, rand, weight=max(3, params.N // 3))
        try:
            f_inv_p = poly_inverse_mod_prime(f, params.N, params.p)
            f_inv_q = poly_inverse_mod_prime(f, params.N, params.q)
        except ValueError:
            continue

        g = sample_ternary(params.N, rand, weight=max(3, params.N // 3))
        h = poly_mul_cyclic(f_inv_q, g, params.N, mod=params.q)
        h = poly_scalar_mul(h, params.p, mod=params.q)

        pub = NTRUPublicKey(params=params, h=h)
        priv = NTRUPrivateKey(params=params, f=f, f_inv_p=f_inv_p)
        return pub, priv

    raise RuntimeError("ntru_keygen_deterministic: failed to find invertible f")


def ntru_encrypt(pub: NTRUPublicKey, m: List[int], r: List[int]) -> List[int]:
    """
    Encrypt a message polynomial m using blinding polynomial r:
      e = r*h + m (mod q)
    """
    N, q = pub.params.N, pub.params.q
    if len(m) != N or len(r) != N:
        raise ValueError("ntru_encrypt: m and r must have length N")
    e = poly_add(poly_mul_cyclic(r, pub.h, N, mod=q), poly_mod(m, q), mod=q)
    return e


def ntru_decrypt(priv: NTRUPrivateKey, e: List[int]) -> List[int]:
    """
    Decrypt:
      a = f*e (mod q) then center-lift a to small integers
      m = f^{-1} * a (mod p) then center-lift modulo p
    """
    N, p, q = priv.params.N, priv.params.p, priv.params.q
    if len(e) != N:
        raise ValueError("ntru_decrypt: ciphertext must have length N")
    a = poly_mul_cyclic(priv.f, e, N, mod=q)
    a_center = poly_center_lift(a, q)
    m_mod_p = poly_mul_cyclic(priv.f_inv_p, poly_mod(a_center, p), N, mod=p)
    m_center = poly_center_lift(m_mod_p, p)
    return m_center


def _demo_params() -> NTRUParams:
    return NTRUParams(N=11, p=3, q=61)


def _demo_keypair() -> Tuple[NTRUPublicKey, NTRUPrivateKey]:
    return ntru_keygen_deterministic(_demo_params(), seed="ntru-demo-keygen-v1")


def _demo_message(params: NTRUParams) -> List[int]:
    if params.p != 3:
        raise ValueError("demo_message expects p=3")
    m = [0] * params.N
    for i, v in enumerate([1, 0, -1, 1, 0, 0, -1]):
        m[i] = v
    return m


def _demo_blinding(params: NTRUParams) -> List[int]:
    rand = _rand_from_seed("ntru-demo-r-v1")
    return sample_ternary(params.N, rand, weight=max(3, params.N // 4))


def main():
    params = _demo_params()

    print(f"params: N={params.N}, p={params.p}, q={params.q}\n")

    print("=== Step 1: Ring arithmetic ===")
    a = [1, -1, 0, 2, 0, 0, 1, 0, 0, 0, 0]
    b = [0, 1, 1, 0, 0, -1, 0, 0, 0, 2, 0]
    prod = poly_mul_cyclic(a, b, params.N, mod=params.q)
    print("a(x) =", poly_to_str(a))
    print("b(x) =", poly_to_str(b))
    print("a*b mod q =", prod)
    print("center-lift(a*b) =", poly_center_lift(prod, params.q))
    print()

    print("=== Step 2: Inverting a polynomial mod a prime ===")
    f = [1, 1, 0, 0, -1, 0, 0, 1, 0, 0, 0]
    inv_p = poly_inverse_mod_prime(f, params.N, params.p)
    check = poly_mul_cyclic(poly_mod(f, params.p), inv_p, params.N, mod=params.p)
    print("f(x) =", f)
    print("f^{-1} mod p =", inv_p)
    print("f * f^{-1} mod p =", check, "(should be [1,0,...])")
    print()

    print("=== Step 3: Key generation + encryption ===")
    pub, priv = _demo_keypair()
    m = _demo_message(params)
    r = _demo_blinding(params)
    e = ntru_encrypt(pub, m, r)
    print("public h =", pub.h)
    print("private f =", priv.f)
    print("message m =", m)
    print("blinding r =", r)
    print("ciphertext e =", e)
    print()

    print("=== Step 4: Decryption + roundtrip ===")
    m2 = ntru_decrypt(priv, e)
    print("decrypted m' =", m2)
    print("roundtrip ok =", m2 == poly_center_lift(poly_mod(m, params.p), params.p))
    print()


if __name__ == "__main__":
    main()
