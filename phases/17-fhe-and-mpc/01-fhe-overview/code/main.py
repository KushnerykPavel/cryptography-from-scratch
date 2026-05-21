"""
Toy FHE overview: a tiny (insecure) DGHV-style somewhat homomorphic scheme over integers.

This script demonstrates the core mental model behind many practical FHE schemes:

- ciphertext = plaintext + noise (hidden inside a larger modulus)
- homomorphic ops (add/mul) are "just" add/mul on ciphertexts
- noise grows with each operation, limiting circuit depth unless you refresh (bootstrap)

Run:
  python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass
import random
from typing import Sequence


def _require_odd_positive(name: str, x: int) -> None:
    if not isinstance(x, int):
        raise TypeError(f"{name} must be int")
    if x <= 0:
        raise ValueError(f"{name} must be > 0")
    if x % 2 == 0:
        raise ValueError(f"{name} must be odd")


def _require_bit(name: str, m: int) -> None:
    if not isinstance(m, int):
        raise TypeError(f"{name} must be int")
    if m not in (0, 1):
        raise ValueError(f"{name} must be 0 or 1")


def centered_mod(x: int, modulus: int) -> int:
    _require_odd_positive("modulus", modulus)
    r = x % modulus
    if r > modulus // 2:
        r -= modulus
    return r


def generate_odd_int(bits: int, rng: random.Random) -> int:
    if not isinstance(bits, int):
        raise TypeError("bits must be int")
    if bits < 3:
        raise ValueError("bits must be >= 3")
    if not isinstance(rng, random.Random):
        raise TypeError("rng must be random.Random")

    x = rng.getrandbits(bits)
    x |= 1
    x |= 1 << (bits - 1)
    return x


def keygen_dghv(*, p_bits: int, rng: random.Random) -> int:
    return generate_odd_int(p_bits, rng)


@dataclass(frozen=True)
class ToyDGHVParams:
    p_bits: int
    q_bits: int
    r_bound: int


def encrypt_bit_with_qr(p: int, m: int, *, q: int, r: int) -> int:
    _require_odd_positive("p", p)
    _require_bit("m", m)
    if not isinstance(q, int):
        raise TypeError("q must be int")
    if q <= 0:
        raise ValueError("q must be > 0")
    if not isinstance(r, int):
        raise TypeError("r must be int")
    return p * q + 2 * r + m


def encrypt_bit(
    p: int,
    m: int,
    *,
    q_bits: int,
    r_bound: int,
    rng: random.Random,
) -> int:
    _require_odd_positive("p", p)
    _require_bit("m", m)
    if not isinstance(q_bits, int):
        raise TypeError("q_bits must be int")
    if q_bits < 2:
        raise ValueError("q_bits must be >= 2")
    if not isinstance(r_bound, int):
        raise TypeError("r_bound must be int")
    if r_bound <= 0:
        raise ValueError("r_bound must be > 0")
    if not isinstance(rng, random.Random):
        raise TypeError("rng must be random.Random")

    q = rng.getrandbits(q_bits) | 1
    r = rng.randint(-r_bound, r_bound)
    return encrypt_bit_with_qr(p, m, q=q, r=r)


def decrypt_bit(p: int, c: int) -> int:
    _require_odd_positive("p", p)
    if not isinstance(c, int):
        raise TypeError("c must be int")
    mu = centered_mod(c, p)
    return mu % 2


def ciphertext_noise(p: int, c: int) -> int:
    _require_odd_positive("p", p)
    if not isinstance(c, int):
        raise TypeError("c must be int")
    mu = centered_mod(c, p)
    m = mu % 2
    return abs(mu - m)


def noise_budget_ok(p: int, c: int) -> bool:
    _require_odd_positive("p", p)
    if not isinstance(c, int):
        raise TypeError("c must be int")
    return ciphertext_noise(p, c) < (p // 4)


def homomorphic_xor(c1: int, c2: int) -> int:
    if not isinstance(c1, int) or not isinstance(c2, int):
        raise TypeError("c1 and c2 must be int")
    return c1 + c2


def homomorphic_and(c1: int, c2: int) -> int:
    if not isinstance(c1, int) or not isinstance(c2, int):
        raise TypeError("c1 and c2 must be int")
    return c1 * c2


def refresh_via_decrypt_reencrypt(
    p: int,
    c: int,
    *,
    q_bits: int,
    r_bound: int,
    rng: random.Random,
) -> int:
    m = decrypt_bit(p, c)
    return encrypt_bit(p, m, q_bits=q_bits, r_bound=r_bound, rng=rng)


def eval_circuit_xor_and(
    p: int,
    c_bits: Sequence[int],
    *,
    q_bits: int,
    r_bound: int,
    rng: random.Random,
) -> int:
    if len(c_bits) != 3:
        raise ValueError("c_bits must have length 3 (a, b, c)")
    a, b, c = c_bits
    t = homomorphic_and(a, b)
    out = homomorphic_xor(t, c)
    if not noise_budget_ok(p, out):
        out = refresh_via_decrypt_reencrypt(p, out, q_bits=q_bits, r_bound=r_bound, rng=rng)
    return out


def _print_step_header(n: int, name: str) -> None:
    print(f"=== Step {n}: {name} ===")


def main() -> None:
    rng = random.Random(2026)
    params = ToyDGHVParams(p_bits=21, q_bits=48, r_bound=2**6)

    _print_step_header(1, "Keygen + centered reduction")
    p = keygen_dghv(p_bits=params.p_bits, rng=rng)
    print(f"secret key p (odd, {params.p_bits} bits): {p}")
    print(f"centered_mod(-3, p) = {centered_mod(-3, p)}")
    print(f"centered_mod(p+3, p) = {centered_mod(p+3, p)}")
    print()

    _print_step_header(2, "Encrypt/decrypt a bit + measure noise")
    for m in (0, 1, 1, 0):
        c = encrypt_bit(p, m, q_bits=params.q_bits, r_bound=params.r_bound, rng=rng)
        m2 = decrypt_bit(p, c)
        n = ciphertext_noise(p, c)
        mu = centered_mod(c, p)
        print(f"m={m}  c={c}  (c mod p)={mu}  noise={n}  dec={m2}")
    print()

    _print_step_header(3, "Homomorphic XOR (add) and AND (mul)")
    m1, m2 = 1, 0
    c1 = encrypt_bit(p, m1, q_bits=params.q_bits, r_bound=params.r_bound, rng=rng)
    c2 = encrypt_bit(p, m2, q_bits=params.q_bits, r_bound=params.r_bound, rng=rng)
    c_xor = homomorphic_xor(c1, c2)
    c_and = homomorphic_and(c1, c2)
    print(f"m1={m1}, m2={m2}")
    print(f"xor dec={decrypt_bit(p, c_xor)}  noise={ciphertext_noise(p, c_xor)}")
    print(f"and dec={decrypt_bit(p, c_and)}  noise={ciphertext_noise(p, c_and)}")
    print()

    _print_step_header(4, "A tiny boolean circuit + depth limit + \"refresh\"")
    bits = (1, 1, 0)  # (a, b, c)
    c_bits = [
        encrypt_bit(p, bits[0], q_bits=params.q_bits, r_bound=params.r_bound, rng=rng),
        encrypt_bit(p, bits[1], q_bits=params.q_bits, r_bound=params.r_bound, rng=rng),
        encrypt_bit(p, bits[2], q_bits=params.q_bits, r_bound=params.r_bound, rng=rng),
    ]
    out = eval_circuit_xor_and(p, c_bits, q_bits=params.q_bits, r_bound=params.r_bound, rng=rng)
    plain = (bits[0] & bits[1]) ^ bits[2]
    print(f"circuit: (a AND b) XOR c")
    print(f"plain={plain}  dec(out)={decrypt_bit(p, out)}  noise={ciphertext_noise(p, out)}")

    params_depth = ToyDGHVParams(p_bits=15, q_bits=48, r_bound=2**8)
    p2 = keygen_dghv(p_bits=params_depth.p_bits, rng=rng)
    c = encrypt_bit(p2, 1, q_bits=params_depth.q_bits, r_bound=params_depth.r_bound, rng=rng)
    print()
    print("Depth demo: repeatedly AND with fresh encryptions of 1 (noise explodes).")
    print(f"(using a smaller p and larger noise: p_bits={params_depth.p_bits}, r_bound={params_depth.r_bound})")
    for depth in range(1, 9):
        c = homomorphic_and(
            c,
            encrypt_bit(p2, 1, q_bits=params_depth.q_bits, r_bound=params_depth.r_bound, rng=rng),
        )
        dec = decrypt_bit(p2, c)
        n = ciphertext_noise(p2, c)
        ok = noise_budget_ok(p2, c)
        print(f"depth={depth:2d}  dec={dec}  noise={n:6d}  budget_ok={ok}")


if __name__ == "__main__":
    main()
