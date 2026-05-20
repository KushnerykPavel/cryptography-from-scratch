"""
FRI (Fast Reed–Solomon IOP) — tiny, dependency-free demo.

This script implements the core *folding* idea behind FRI over a small prime
field and a power-of-two roots-of-unity domain. It is intentionally minimal:
no Merkle trees, no Fiat–Shamir transcript, no polynomial commitments.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple


def mod_inv(a: int, p: int) -> int:
    a %= p
    if a == 0:
        raise ZeroDivisionError("no inverse for 0 mod p")
    # Extended Euclid for prime p (works for any modulus where gcd(a,p)=1).
    t0, t1 = 0, 1
    r0, r1 = p, a
    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        t0, t1 = t1, t0 - q * t1
    if r0 != 1:
        raise ZeroDivisionError("a is not invertible mod p")
    return t0 % p


def _prime_factors(n: int) -> List[int]:
    out: List[int] = []
    d = 2
    while d * d <= n:
        while n % d == 0:
            out.append(d)
            n //= d
        d += 1
    if n > 1:
        out.append(n)
    return out


def find_primitive_root(p: int) -> int:
    if p < 3:
        raise ValueError("p must be an odd prime >= 3")
    phi = p - 1
    factors = sorted(set(_prime_factors(phi)))
    for g in range(2, p):
        ok = True
        for q in factors:
            if pow(g, phi // q, p) == 1:
                ok = False
                break
        if ok:
            return g
    raise ValueError("no primitive root found (is p prime?)")


def is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def get_root_of_unity(p: int, n: int) -> int:
    if n <= 1 or not is_power_of_two(n):
        raise ValueError("n must be a power of two >= 2")
    if (p - 1) % n != 0:
        raise ValueError("n must divide p-1")
    g = find_primitive_root(p)
    omega = pow(g, (p - 1) // n, p)
    if pow(omega, n, p) != 1:
        raise ValueError("constructed element is not an n-th root of unity")
    if pow(omega, n // 2, p) != p - 1:
        raise ValueError("omega^(n/2) must be -1 for power-of-two domain")
    return omega


def roots_of_unity_domain(p: int, n: int) -> List[int]:
    omega = get_root_of_unity(p, n)
    xs = [1]
    for _ in range(1, n):
        xs.append((xs[-1] * omega) % p)
    return xs


def poly_degree(coeffs: Sequence[int]) -> int:
    d = -1
    for i, c in enumerate(coeffs):
        if c != 0:
            d = i
    return d


def poly_eval(coeffs: Sequence[int], x: int, p: int) -> int:
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % p
    return acc


def poly_eval_all(coeffs: Sequence[int], xs: Sequence[int], p: int) -> List[int]:
    return [poly_eval(coeffs, x, p) for x in xs]


def fri_fold_layer(evals: Sequence[int], beta: int, p: int) -> List[int]:
    n = len(evals)
    if n <= 1 or (n % 2) != 0:
        raise ValueError("layer length must be even and >= 2")
    beta %= p
    half = n // 2
    inv2 = mod_inv(2, p)
    out: List[int] = []
    for i in range(half):
        a = evals[i] % p
        b = evals[i + half] % p
        out.append(((a + beta * b) % p) * inv2 % p)
    return out


def fri_fold_rounds(evals: Sequence[int], betas: Sequence[int], p: int) -> List[List[int]]:
    layers: List[List[int]] = [list(evals)]
    cur = list(evals)
    for beta in betas:
        cur = fri_fold_layer(cur, beta, p)
        layers.append(cur)
    return layers


def expected_degree_after_fri_rounds(initial_degree: int, rounds: int) -> int:
    if initial_degree < 0:
        return -1
    return initial_degree // (2**rounds)


def challenges_from_seed(seed: str, rounds: int, p: int) -> List[int]:
    if rounds < 0:
        raise ValueError("rounds must be >= 0")
    out: List[int] = []
    state = seed.encode("utf-8")
    for i in range(rounds):
        h = hashlib.sha256(state + i.to_bytes(4, "big")).digest()
        beta = int.from_bytes(h, "big") % p
        if beta == 0:
            beta = 1
        out.append(beta)
        state = h
    return out


@dataclass(frozen=True)
class FriDemoParams:
    p: int
    n: int
    coeffs: Tuple[int, ...]
    seed: str


def run_demo(params: FriDemoParams) -> None:
    p, n = params.p, params.n
    if not is_power_of_two(n):
        raise ValueError("n must be a power of two")

    omega = get_root_of_unity(p, n)
    domain = roots_of_unity_domain(p, n)
    degree = poly_degree(params.coeffs)
    evals = poly_eval_all(params.coeffs, domain, p)

    print("=== Step 1: A tiny field and a roots-of-unity domain ===")
    print(f"p = {p}")
    print(f"n = {n}")
    print(f"primitive n-th root of unity omega = {omega}")
    print(f"domain[0..7] = {domain[:8]}")
    print()

    print("=== Step 2: Evaluate a polynomial on the domain ===")
    print(f"coeffs (low -> high) = {list(params.coeffs)}")
    print(f"degree = {degree}")
    print(f"evals[0..7] = {evals[:8]}")
    print()

    rounds = int(math.log2(n))
    betas = challenges_from_seed(params.seed, rounds=rounds, p=p)
    print("=== Step 3: Fold evaluations (the heart of FRI) ===")
    print(f"betas = {betas}")
    layers = fri_fold_rounds(evals, betas, p)
    for r in range(1, len(layers)):
        expected_deg = expected_degree_after_fri_rounds(degree, r)
        print(f"round {r}: len={len(layers[r])}, expected_degree_bound={expected_deg}, head={layers[r][:8]}")
    print()

    print("=== Step 4: Show how tampering is detected (in the full protocol) ===")
    tampered = list(evals)
    tampered[3] = (tampered[3] + 1) % p
    honest_final = layers[-1][0]
    tampered_final = fri_fold_rounds(tampered, betas, p)[-1][0]
    print(f"honest final value = {honest_final}")
    print(f"tampered final value = {tampered_final}")
    print("In a real FRI-based scheme, Merkle commitments + random queries force a prover")
    print("to open consistent pairs across rounds, making this kind of tampering unlikely to pass.")


if __name__ == "__main__":
    run_demo(
        FriDemoParams(
            p=97,
            n=16,
            coeffs=(3, 1, 4, 1, 5, 9),
            seed="fri-demo-v1",
        )
    )
