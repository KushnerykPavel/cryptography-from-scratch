"""
Toy BGV/BFV (RLWE) walk-through.

This lesson implements a tiny, educational BFV-style scheme over the ring:
    R_q = Z_q[x] / (x^n + 1)

It supports:
- key generation
- encryption/decryption of small integer polynomials (exact, not approximate)
- homomorphic addition
- homomorphic multiplication (with scale-and-round) + relinearization
- a toy modulus-switch demo (BGV-style idea: scale-and-round to a smaller q)

Run:
    python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import random
from typing import Iterable, List, Sequence, Tuple


Poly = List[int]


@dataclass(frozen=True)
class Params:
    n: int
    q: int
    t: int
    delta: int
    relin_base: int


@dataclass(frozen=True)
class Ciphertext:
    c0: Poly
    c1: Poly


@dataclass(frozen=True)
class Ciphertext3:
    c0: Poly
    c1: Poly
    c2: Poly


@dataclass(frozen=True)
class RelinKey:
    base: int
    pieces: List[Tuple[Poly, Poly]]  # [(k0_i, k1_i)] where k0_i + k1_i*s ~= base^i * s^2 (mod q)


def _check_params(params: Params) -> None:
    if params.n <= 0 or (params.n & (params.n - 1)) != 0:
        raise ValueError("n must be a power of two")
    if params.q <= 2 or params.t <= 1:
        raise ValueError("q must be >2 and t must be >1")
    if params.q <= params.t:
        raise ValueError("need q >> t for correctness (q must be > t)")
    if params.delta != params.q // params.t:
        raise ValueError("delta must equal q//t")
    if params.relin_base <= 1:
        raise ValueError("relin_base must be > 1")


def mod_centered(x: int, q: int) -> int:
    r = x % q
    if r > q // 2:
        r -= q
    return r


def round_div(num: int, den: int) -> int:
    if den <= 0:
        raise ValueError("den must be positive")
    if num == 0:
        return 0
    sign = 1 if num >= 0 else -1
    num_abs = abs(num)
    q, r = divmod(num_abs, den)
    if 2 * r >= den:
        q += 1
    return sign * q


def poly_mod(a: Sequence[int], q: int) -> Poly:
    return [x % q for x in a]


def poly_add(a: Sequence[int], b: Sequence[int], q: int) -> Poly:
    if len(a) != len(b):
        raise ValueError("poly_add: length mismatch")
    return [(x + y) % q for x, y in zip(a, b)]


def poly_sub(a: Sequence[int], b: Sequence[int], q: int) -> Poly:
    if len(a) != len(b):
        raise ValueError("poly_sub: length mismatch")
    return [(x - y) % q for x, y in zip(a, b)]


def poly_scalar_mul(a: Sequence[int], k: int, q: int) -> Poly:
    return [(k * x) % q for x in a]


def poly_mul_negacyclic_int(a: Sequence[int], b: Sequence[int]) -> Poly:
    if len(a) != len(b):
        raise ValueError("poly_mul_negacyclic_int: length mismatch")
    n = len(a)
    tmp = [0] * (2 * n - 1)
    for i in range(n):
        ai = a[i]
        for j in range(n):
            tmp[i + j] += ai * b[j]
    res = [0] * n
    for k, v in enumerate(tmp):
        if k < n:
            res[k] += v
        else:
            res[k - n] -= v  # x^n == -1
    return res


def poly_mul_negacyclic(a: Sequence[int], b: Sequence[int], q: int) -> Poly:
    return poly_mod(poly_mul_negacyclic_int(a, b), q)


def poly_lift_centered(a: Sequence[int], q: int) -> Poly:
    return [mod_centered(x, q) for x in a]


def poly_add_int(a: Sequence[int], b: Sequence[int]) -> Poly:
    if len(a) != len(b):
        raise ValueError("poly_add_int: length mismatch")
    return [x + y for x, y in zip(a, b)]


def poly_scale_round(a_int: Sequence[int], mul: int, den: int, out_mod: int) -> Poly:
    return [round_div(x * mul, den) % out_mod for x in a_int]


def digits_for_base(q: int, base: int) -> int:
    if q <= 0 or base <= 1:
        raise ValueError("invalid q/base")
    k = 0
    power = 1
    while power < q:
        power *= base
        k += 1
    return k


def poly_decompose_base(a: Sequence[int], base: int, digits: int) -> List[Poly]:
    if base <= 1 or digits <= 0:
        raise ValueError("invalid base/digits")
    out: List[Poly] = [[0] * len(a) for _ in range(digits)]
    for idx, coeff in enumerate(a):
        x = int(coeff)
        for d in range(digits):
            out[d][idx] = x % base
            x //= base
    return out


def sample_ternary(n: int, rng: random.Random) -> Poly:
    out: Poly = []
    for _ in range(n):
        r = rng.randrange(4)
        if r == 0:
            out.append(-1)
        elif r in (1, 2):
            out.append(0)
        else:
            out.append(1)
    return out


def sample_small(n: int, rng: random.Random, bound: int = 1) -> Poly:
    if bound < 0:
        raise ValueError("bound must be >= 0")
    return [rng.randint(-bound, bound) for _ in range(n)]


def sample_uniform(n: int, q: int, rng: random.Random) -> Poly:
    return [rng.randrange(q) for _ in range(n)]


def bfv_keygen(params: Params, rng: random.Random) -> Poly:
    _check_params(params)
    return sample_ternary(params.n, rng)


def bfv_encrypt(params: Params, s: Sequence[int], m: Sequence[int], rng: random.Random) -> Ciphertext:
    _check_params(params)
    if len(s) != params.n or len(m) != params.n:
        raise ValueError("bfv_encrypt: length mismatch")
    a = sample_uniform(params.n, params.q, rng)
    e = sample_small(params.n, rng, bound=1)
    a_s = poly_mul_negacyclic(a, poly_mod(s, params.q), params.q)
    delta_m = poly_scalar_mul(poly_mod(m, params.q), params.delta, params.q)
    c0 = poly_add(poly_add(a_s, poly_mod(e, params.q), params.q), delta_m, params.q)
    c1 = poly_sub([0] * params.n, a, params.q)
    return Ciphertext(c0=c0, c1=c1)


def bfv_decrypt(params: Params, s: Sequence[int], ct: Ciphertext) -> Poly:
    _check_params(params)
    if len(s) != params.n or len(ct.c0) != params.n or len(ct.c1) != params.n:
        raise ValueError("bfv_decrypt: length mismatch")
    c1s = poly_mul_negacyclic(ct.c1, poly_mod(s, params.q), params.q)
    u = poly_add(ct.c0, c1s, params.q)
    u_centered = poly_lift_centered(u, params.q)
    return [round_div(x * params.t, params.q) % params.t for x in u_centered]


def bfv_add(params: Params, a: Ciphertext, b: Ciphertext) -> Ciphertext:
    if len(a.c0) != params.n or len(b.c0) != params.n:
        raise ValueError("bfv_add: length mismatch")
    return Ciphertext(
        c0=poly_add(a.c0, b.c0, params.q),
        c1=poly_add(a.c1, b.c1, params.q),
    )


def bfv_mul_raw(params: Params, a: Ciphertext, b: Ciphertext) -> Ciphertext3:
    """
    BFV/FV-style ciphertext multiplication, producing a 3-component ciphertext:
        (d0, d1, d2) where d0 + d1*s + d2*s^2 ~= Δ*(m*m') (mod q)

    Implementation detail: we compute products using the centered lift to
    reduce wrap-around surprises, then scale-and-round by t/q.
    """

    if len(a.c0) != params.n or len(b.c0) != params.n:
        raise ValueError("bfv_mul_raw: length mismatch")

    a0 = poly_lift_centered(a.c0, params.q)
    a1 = poly_lift_centered(a.c1, params.q)
    b0 = poly_lift_centered(b.c0, params.q)
    b1 = poly_lift_centered(b.c1, params.q)

    p00 = poly_mul_negacyclic_int(a0, b0)
    p01 = poly_add_int(poly_mul_negacyclic_int(a0, b1), poly_mul_negacyclic_int(a1, b0))
    p11 = poly_mul_negacyclic_int(a1, b1)

    d0 = poly_scale_round(p00, params.t, params.q, params.q)
    d1 = poly_scale_round(p01, params.t, params.q, params.q)
    d2 = poly_scale_round(p11, params.t, params.q, params.q)
    return Ciphertext3(c0=d0, c1=d1, c2=d2)


def bfv_decrypt3(params: Params, s: Sequence[int], ct: Ciphertext3) -> Poly:
    _check_params(params)
    if len(s) != params.n:
        raise ValueError("bfv_decrypt3: length mismatch")
    s_mod = poly_mod(s, params.q)
    s2 = poly_mul_negacyclic(s_mod, s_mod, params.q)
    c1s = poly_mul_negacyclic(ct.c1, s_mod, params.q)
    c2s2 = poly_mul_negacyclic(ct.c2, s2, params.q)
    u = poly_add(poly_add(ct.c0, c1s, params.q), c2s2, params.q)
    u_centered = poly_lift_centered(u, params.q)
    return [round_div(x * params.t, params.q) % params.t for x in u_centered]


def bfv_relin_keygen(params: Params, s: Sequence[int], rng: random.Random) -> RelinKey:
    _check_params(params)
    if len(s) != params.n:
        raise ValueError("bfv_relin_keygen: length mismatch")
    base = params.relin_base
    digits = digits_for_base(params.q, base)

    s_mod = poly_mod(s, params.q)
    s2 = poly_mul_negacyclic(s_mod, s_mod, params.q)

    pieces: List[Tuple[Poly, Poly]] = []
    pow_base = 1
    for _ in range(digits):
        a = sample_uniform(params.n, params.q, rng)
        e = sample_small(params.n, rng, bound=1)
        a_s = poly_mul_negacyclic(a, s_mod, params.q)
        msg = poly_scalar_mul(s2, pow_base, params.q)
        k0 = poly_add(poly_add(a_s, poly_mod(e, params.q), params.q), msg, params.q)
        k1 = poly_sub([0] * params.n, a, params.q)
        pieces.append((k0, k1))
        pow_base = (pow_base * base) % params.q
    return RelinKey(base=base, pieces=pieces)


def bfv_relinearize(params: Params, ct: Ciphertext3, rlk: RelinKey) -> Ciphertext:
    if rlk.base != params.relin_base:
        raise ValueError("bfv_relinearize: rlk base mismatch")
    digits = len(rlk.pieces)
    dec = poly_decompose_base(ct.c2, rlk.base, digits)

    acc0 = ct.c0[:]
    acc1 = ct.c1[:]
    for di, (k0, k1) in zip(dec, rlk.pieces):
        acc0 = poly_add(acc0, poly_mul_negacyclic(k0, di, params.q), params.q)
        acc1 = poly_add(acc1, poly_mul_negacyclic(k1, di, params.q), params.q)
    return Ciphertext(c0=acc0, c1=acc1)


def bfv_mul(params: Params, a: Ciphertext, b: Ciphertext, rlk: RelinKey) -> Ciphertext:
    ct3 = bfv_mul_raw(params, a, b)
    return bfv_relinearize(params, ct3, rlk)


def bfv_modulus_switch(params: Params, ct: Ciphertext, q_new: int) -> Ciphertext:
    """
    Toy BGV-style modulus switching:

    For each coefficient c in Z_q, map it to Z_{q_new} by:
        c' = round((q_new/q) * lift_centered(c)) mod q_new

    This is only a demo. Real BGV/BFV implementations do this across an RNS
    modulus chain (many primes), and correctness constraints are subtle.
    """

    _check_params(params)
    if q_new <= 2 or q_new >= params.q:
        raise ValueError("q_new must be in (2, q)")

    def switch_poly(p: Sequence[int]) -> Poly:
        lifted = poly_lift_centered(p, params.q)
        return [round_div(x * q_new, params.q) % q_new for x in lifted]

    return Ciphertext(c0=switch_poly(ct.c0), c1=switch_poly(ct.c1))


def poly_to_str(a: Sequence[int]) -> str:
    terms = []
    for i, c in enumerate(a):
        if c == 0:
            continue
        if i == 0:
            terms.append(str(c))
        elif i == 1:
            terms.append(f"{c}*x")
        else:
            terms.append(f"{c}*x^{i}")
    return " + ".join(terms) if terms else "0"


def main() -> None:
    params = Params(n=8, q=40961, t=17, delta=40961 // 17, relin_base=64)
    rng = random.Random(1337)
    s = bfv_keygen(params, rng)

    m1 = [3, 1, 4, 1, 5, 0, 0, 0]
    m2 = [2, 7, 1, 8, 2, 0, 0, 0]
    m1 = [x % params.t for x in m1]
    m2 = [x % params.t for x in m2]

    print("=== Step 1: Ring arithmetic (R_q = Z_q[x]/(x^n+1)) ===")
    a = [1, 2, 3, 4, 0, 0, 0, 0]
    b = [5, 6, 7, 8, 0, 0, 0, 0]
    prod = poly_mul_negacyclic(a, b, params.q)
    print("a(x) =", poly_to_str(a))
    print("b(x) =", poly_to_str(b))
    print("a(x)*b(x) mod (x^n+1, q) =", poly_to_str(prod))
    print()

    print("=== Step 2: BFV-style Encrypt/Decrypt (exact integers mod t) ===")
    ct1 = bfv_encrypt(params, s, m1, rng)
    ct2 = bfv_encrypt(params, s, m2, rng)
    dec1 = bfv_decrypt(params, s, ct1)
    dec2 = bfv_decrypt(params, s, ct2)
    print("m1 =", m1)
    print("dec(m1) =", dec1)
    print("m2 =", m2)
    print("dec(m2) =", dec2)
    print()

    print("=== Step 3: Homomorphic addition ===")
    ct_add = bfv_add(params, ct1, ct2)
    dec_add = bfv_decrypt(params, s, ct_add)
    expect_add = [(x + y) % params.t for x, y in zip(m1, m2)]
    print("dec(ct1 + ct2) =", dec_add)
    print("expected        =", expect_add)
    print()

    print("=== Step 4: Homomorphic multiplication + relinearization ===")
    rlk = bfv_relin_keygen(params, s, rng)
    ct_mul = bfv_mul(params, ct1, ct2, rlk)
    dec_mul = bfv_decrypt(params, s, ct_mul)
    expect_mul = poly_mod(poly_mul_negacyclic_int(m1, m2), params.t)
    print("dec(ct1 * ct2) =", dec_mul)
    print("expected       =", expect_mul)
    print()

    print("=== Step 5: Modulus switching (BGV-style idea) ===")
    q_small = 12289
    ct_sw = bfv_modulus_switch(params, ct_mul, q_small)
    params_small = Params(
        n=params.n,
        q=q_small,
        t=params.t,
        delta=q_small // params.t,
        relin_base=params.relin_base,
    )
    dec_sw = bfv_decrypt(params_small, s, ct_sw)
    print(f"switched q: {params.q} -> {q_small}")
    print("dec(mod_switch(ct_mul)) =", dec_sw)
    print("expected                =", expect_mul)


if __name__ == "__main__":
    main()
