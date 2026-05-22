"""
Beaver triples (multiplication triples) for arithmetic MPC.

Runs a tiny from-scratch demo of:
- additive secret sharing over a prime field F_p
- dealer-generated Beaver triples (a, b, c=a*b)
- online multiplication of shared secrets by opening masked d=x-a and e=y-b

Run:
  python3 code/main.py
"""

from __future__ import annotations

import random


def modp(x: int, p: int) -> int:
    return x % p


def field_add(a: int, b: int, p: int) -> int:
    return (a + b) % p


def field_sub(a: int, b: int, p: int) -> int:
    return (a - b) % p


def field_mul(a: int, b: int, p: int) -> int:
    return (a * b) % p


def share_secret(x: int, n: int, p: int, rng) -> list[int]:
    if n < 2:
        raise ValueError("n must be >= 2")
    x = modp(x, p)
    shares = [rng.randrange(p) for _ in range(n - 1)]
    last = x
    for s in shares:
        last = field_sub(last, s, p)
    shares.append(last)
    return shares


def reconstruct(shares: list[int], p: int) -> int:
    total = 0
    for s in shares:
        total = field_add(total, s, p)
    return total


def generate_beaver_triple_shares(n: int, p: int, rng) -> tuple[list[int], list[int], list[int]]:
    a = rng.randrange(p)
    b = rng.randrange(p)
    c = field_mul(a, b, p)
    a_sh = share_secret(a, n, p, rng)
    b_sh = share_secret(b, n, p, rng)
    c_sh = share_secret(c, n, p, rng)
    return a_sh, b_sh, c_sh


def share_sub(x_sh: list[int], y_sh: list[int], p: int) -> list[int]:
    if len(x_sh) != len(y_sh):
        raise ValueError("share length mismatch")
    return [field_sub(a, b, p) for a, b in zip(x_sh, y_sh)]


def share_add(x_sh: list[int], y_sh: list[int], p: int) -> list[int]:
    if len(x_sh) != len(y_sh):
        raise ValueError("share length mismatch")
    return [field_add(a, b, p) for a, b in zip(x_sh, y_sh)]


def share_scalar_mul(x_sh: list[int], k: int, p: int) -> list[int]:
    k = modp(k, p)
    return [field_mul(s, k, p) for s in x_sh]


def beaver_multiply_shares(
    x_sh: list[int],
    y_sh: list[int],
    a_sh: list[int],
    b_sh: list[int],
    c_sh: list[int],
    p: int,
    dealer_party: int = 0,
) -> tuple[list[int], int, int]:
    n = len(x_sh)
    if not (len(y_sh) == len(a_sh) == len(b_sh) == len(c_sh) == n):
        raise ValueError("share length mismatch")
    if not (0 <= dealer_party < n):
        raise ValueError("dealer_party out of range")

    d_sh = share_sub(x_sh, a_sh, p)
    e_sh = share_sub(y_sh, b_sh, p)
    d = reconstruct(d_sh, p)
    e = reconstruct(e_sh, p)

    z_sh = []
    for i in range(n):
        part = c_sh[i]
        part = field_add(part, field_mul(d, b_sh[i], p), p)
        part = field_add(part, field_mul(e, a_sh[i], p), p)
        if i == dealer_party:
            part = field_add(part, field_mul(d, e, p), p)
        z_sh.append(part)

    return z_sh, d, e


def circuit_example(
    x: int, y: int, z: int, n: int, p: int, rng
) -> tuple[int, int]:
    x_sh = share_secret(x, n, p, rng)
    y_sh = share_secret(y, n, p, rng)
    z_sh = share_secret(z, n, p, rng)

    a1, b1, c1 = generate_beaver_triple_shares(n, p, rng)
    xy_sh, _, _ = beaver_multiply_shares(x_sh, y_sh, a1, b1, c1, p)

    sum_sh = share_add(xy_sh, z_sh, p)
    opened = reconstruct(sum_sh, p)
    expected = field_add(field_mul(modp(x, p), modp(y, p), p), modp(z, p), p)
    return opened, expected


def _print_step(title: str) -> None:
    print(f"=== {title} ===")


def main() -> None:
    p = 101
    n = 3
    rng = random.Random(0)

    _print_step("Step 1: Field arithmetic + additive secret sharing")
    x = 42
    x_sh = share_secret(x, n, p, rng)
    print(f"p={p}, n={n}")
    print(f"x={x} -> shares={x_sh} -> open={reconstruct(x_sh, p)}")

    _print_step("Step 2: Generate a Beaver triple (dealer model)")
    a_sh, b_sh, c_sh = generate_beaver_triple_shares(n, p, rng)
    a = reconstruct(a_sh, p)
    b = reconstruct(b_sh, p)
    c = reconstruct(c_sh, p)
    print(f"a shares={a_sh} (open a={a})")
    print(f"b shares={b_sh} (open b={b})")
    print(f"c shares={c_sh} (open c={c}, check a*b mod p={(a*b)%p})")

    _print_step("Step 3: Multiply shared secrets using a triple (online phase)")
    y = 77
    x_sh = share_secret(x, n, p, rng)
    y_sh = share_secret(y, n, p, rng)
    z_sh, d, e = beaver_multiply_shares(x_sh, y_sh, a_sh, b_sh, c_sh, p)
    z_open = reconstruct(z_sh, p)
    print(f"x shares={x_sh}")
    print(f"y shares={y_sh}")
    print(f"opened d=x-a={d}, e=y-b={e}")
    print(f"z=x*y mod p -> shares={z_sh} -> open={z_open}, expected={(x*y)%p}")

    _print_step("Step 4: Evaluate a tiny arithmetic circuit")
    out, expected = circuit_example(x=12, y=34, z=56, n=n, p=p, rng=rng)
    print(f"Compute (x*y)+z with x=12,y=34,z=56 -> open={out}, expected={expected}")


if __name__ == "__main__":
    main()
