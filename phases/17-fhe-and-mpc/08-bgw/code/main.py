"""
BGW (Ben-Or/Goldwasser/Wigderson) MPC demo for arithmetic circuits.

This file implements a tiny, educational subset of the BGW idea:
- secrets live in a prime field F_p
- secrets are Shamir-shared among n parties with threshold t
- additions are local (no communication)
- multiplications use a BGW-style "degree reduction" sub-protocol

Run:
  python3 code/main.py
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple


Share = Tuple[int, int]  # (party_id, value)


def mod_inv(a: int, p: int) -> int:
    a %= p
    if a == 0:
        raise ValueError("inverse of 0 does not exist")
    t0, t1 = 0, 1
    r0, r1 = p, a
    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        t0, t1 = t1, t0 - q * t1
    if r0 != 1:
        raise ValueError("a is not invertible modulo p")
    return t0 % p


def mod_div(a: int, b: int, p: int) -> int:
    return (a % p) * mod_inv(b, p) % p


def poly_eval(coeffs: Sequence[int], x: int, p: int) -> int:
    x %= p
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % p
    return acc


def lagrange_coeffs_at_zero(xs: Sequence[int], p: int) -> List[int]:
    xs = list(xs)
    if len(set(xs)) != len(xs):
        raise ValueError("x coordinates must be distinct")
    if any(x % p == 0 for x in xs):
        raise ValueError("x coordinates must be non-zero for sharing")

    coeffs: List[int] = []
    for i, xi in enumerate(xs):
        num = 1
        den = 1
        for j, xj in enumerate(xs):
            if i == j:
                continue
            num = (num * xj) % p
            den = (den * (xj - xi)) % p
        coeffs.append(num * mod_inv(den, p) % p)
    return coeffs


def shamir_share(
    secret: int,
    n: int,
    t: int,
    p: int,
    *,
    rng: random.Random | None = None,
    coeffs: Sequence[int] | None = None,
) -> List[Share]:
    if n <= 0:
        raise ValueError("n must be positive")
    if t < 0 or t >= n:
        raise ValueError("require 0 <= t < n")

    if coeffs is None:
        if rng is None:
            rng = random.Random()
        poly = [secret % p] + [rng.randrange(0, p) for _ in range(t)]
    else:
        poly = [c % p for c in coeffs]
        if len(poly) != t + 1:
            raise ValueError("coeffs must have length t+1")
        if poly[0] != secret % p:
            raise ValueError("coeffs[0] must equal secret mod p")

    return [(i, poly_eval(poly, i, p)) for i in range(1, n + 1)]


def shamir_reconstruct(shares: Sequence[Share], p: int) -> int:
    if len(shares) == 0:
        raise ValueError("need at least one share")
    xs = [x for x, _ in shares]
    ys = [y % p for _, y in shares]
    lambdas = lagrange_coeffs_at_zero(xs, p)
    return sum((lam * y) % p for lam, y in zip(lambdas, ys)) % p


def shamir_add(a: Sequence[Share], b: Sequence[Share], p: int) -> List[Share]:
    if len(a) != len(b):
        raise ValueError("share sets must have same size")
    out: List[Share] = []
    for (i1, v1), (i2, v2) in zip(a, b):
        if i1 != i2:
            raise ValueError("party ids must align")
        out.append((i1, (v1 + v2) % p))
    return out


def shamir_scalar_mul(shares: Sequence[Share], k: int, p: int) -> List[Share]:
    return [(i, (k % p) * (v % p) % p) for i, v in shares]


def _bgw_degree_reduce_from_degree_2t(
    degree_2t_shares: Sequence[Share],
    *,
    t: int,
    p: int,
    rng: random.Random,
) -> List[Share]:
    n = len(degree_2t_shares)
    if n < 2 * t + 1:
        raise ValueError("need n >= 2t+1 for degree-2t reconstruction")

    dealers = list(degree_2t_shares[: 2 * t + 1])
    dealer_ids = [i for i, _ in dealers]
    lambdas = lagrange_coeffs_at_zero(dealer_ids, p)
    lambda_by_dealer = {i: lam for i, lam in zip(dealer_ids, lambdas)}

    party_ids = [i for i, _ in degree_2t_shares]
    subshares_by_party: Dict[int, List[int]] = {pid: [] for pid in party_ids}

    for dealer_id, dealer_value in dealers:
        poly = [dealer_value % p] + [rng.randrange(0, p) for _ in range(t)]
        for pid in party_ids:
            subshares_by_party[pid].append(poly_eval(poly, pid, p))

    reduced: List[Share] = []
    for pid in party_ids:
        acc = 0
        for (dealer_id, _), sub in zip(dealers, subshares_by_party[pid]):
            acc = (acc + lambda_by_dealer[dealer_id] * sub) % p
        reduced.append((pid, acc))
    return reduced


def bgw_multiply(
    a: Sequence[Share],
    b: Sequence[Share],
    *,
    t: int,
    p: int,
    rng: random.Random,
) -> List[Share]:
    if len(a) != len(b):
        raise ValueError("share sets must have same size")
    if len(a) < 2 * t + 1:
        raise ValueError("need n >= 2t+1 for multiplication")

    local_products: List[Share] = []
    for (i1, va), (i2, vb) in zip(a, b):
        if i1 != i2:
            raise ValueError("party ids must align")
        local_products.append((i1, (va % p) * (vb % p) % p))

    return _bgw_degree_reduce_from_degree_2t(local_products, t=t, p=p, rng=rng)


@dataclass(frozen=True)
class CircuitInput:
    a: int
    b: int
    c: int
    d: int


def bgw_demo_circuit(
    inp: CircuitInput,
    *,
    n: int,
    t: int,
    p: int,
    rng: random.Random,
) -> int:
    share_a = shamir_share(inp.a, n, t, p, rng=rng)
    share_b = shamir_share(inp.b, n, t, p, rng=rng)
    share_c = shamir_share(inp.c, n, t, p, rng=rng)
    share_d = shamir_share(inp.d, n, t, p, rng=rng)

    share_a_plus_b = shamir_add(share_a, share_b, p)
    share_mul = bgw_multiply(share_a_plus_b, share_c, t=t, p=p, rng=rng)
    share_out = shamir_add(share_mul, share_d, p)

    return shamir_reconstruct(share_out[: t + 1], p)


def main() -> None:
    p = 2089  # prime field for a tiny demo
    n = 5
    t = 2
    rng = random.Random(1337)

    print("=== Step 1: Prime-field arithmetic ===")
    a = 17
    b = 31
    print(f"mod_div({a}, {b}) mod p = {mod_div(a, b, p)} (p={p})")

    print("\n=== Step 2: Shamir secret sharing (t-out-of-n) ===")
    secret = 1234
    shares = shamir_share(secret, n, t, p, rng=rng)
    print(f"secret = {secret}")
    print(f"shares (n={n}, t={t}): {shares}")
    rec = shamir_reconstruct(shares[: t + 1], p)
    print(f"reconstruct from {t+1} shares -> {rec}")

    print("\n=== Step 3: BGW multiplication via degree reduction ===")
    x = 42
    y = 77
    sx = shamir_share(x, n, t, p, rng=rng)
    sy = shamir_share(y, n, t, p, rng=rng)
    sxy = bgw_multiply(sx, sy, t=t, p=p, rng=rng)
    xy = shamir_reconstruct(sxy[: t + 1], p)
    print(f"x = {x}, y = {y}, x*y mod p = {(x*y)%p}")
    print(f"MPC reconstruct(x*y) -> {xy}")

    print("\n=== Step 4: Evaluate a small arithmetic circuit ===")
    inp = CircuitInput(a=11, b=22, c=33, d=44)
    out = bgw_demo_circuit(inp, n=n, t=t, p=p, rng=rng)
    expected = ((inp.a + inp.b) * inp.c + inp.d) % p
    print(f"circuit: (a+b)*c + d  with {inp}")
    print(f"expected = {expected}")
    print(f"MPC output = {out}")


if __name__ == "__main__":
    main()
