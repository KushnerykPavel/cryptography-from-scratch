"""
Toy SPDZ-style MPC demo (authenticated additive sharing + Beaver triples).

This file is an educational, single-process simulation of the *math* inside SPDZ:
- secret values are additively shared over a prime field
- each shared value is authenticated with an information-theoretic MAC under a
  global key alpha (which no single party knows)
- multiplication uses preprocessed Beaver triples
- openings are verified via a MAC check that aborts on tampering

Run:
  python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Iterable, List, Sequence, Tuple


PRIME = 2_147_483_647  # 2^31 - 1 (prime)


def mod(x: int, p: int = PRIME) -> int:
    return x % p


def mod_add(a: int, b: int, p: int = PRIME) -> int:
    return (a + b) % p


def mod_sub(a: int, b: int, p: int = PRIME) -> int:
    return (a - b) % p


def mod_mul(a: int, b: int, p: int = PRIME) -> int:
    return (a * b) % p


class DeterministicRng:
    def __init__(self, seed: bytes):
        self._seed = seed
        self._ctr = 0

    def randbelow(self, n: int) -> int:
        if n <= 0:
            raise ValueError("n must be positive")
        h = hashlib.sha256(self._seed + self._ctr.to_bytes(8, "big")).digest()
        self._ctr += 1
        return int.from_bytes(h, "big") % n


def additive_share(secret: int, n: int, p: int, rng: DeterministicRng) -> List[int]:
    if n < 2:
        raise ValueError("need at least 2 parties")
    secret = mod(secret, p)
    shares = [rng.randbelow(p) for _ in range(n - 1)]
    last = mod(secret - sum(shares), p)
    return shares + [last]


def reconstruct(shares: Iterable[int], p: int) -> int:
    return mod(sum(shares), p)


def beaver_triple_shares(n: int, p: int, rng: DeterministicRng) -> Tuple[List[int], List[int], List[int]]:
    a = rng.randbelow(p)
    b = rng.randbelow(p)
    c = mod_mul(a, b, p)
    return (
        additive_share(a, n, p, rng),
        additive_share(b, n, p, rng),
        additive_share(c, n, p, rng),
    )


def beaver_multiply_shares(
    x_shares: Sequence[int],
    y_shares: Sequence[int],
    triple: Tuple[Sequence[int], Sequence[int], Sequence[int]],
    p: int,
) -> List[int]:
    n = len(x_shares)
    if len(y_shares) != n:
        raise ValueError("mismatched party counts")
    a_shares, b_shares, c_shares = triple
    if len(a_shares) != n or len(b_shares) != n or len(c_shares) != n:
        raise ValueError("triple party count mismatch")

    d = reconstruct((mod_sub(x_shares[i], a_shares[i], p) for i in range(n)), p)
    e = reconstruct((mod_sub(y_shares[i], b_shares[i], p) for i in range(n)), p)

    out = []
    for i in range(n):
        zi = c_shares[i]
        zi = mod_add(zi, mod_mul(d, b_shares[i], p), p)
        zi = mod_add(zi, mod_mul(e, a_shares[i], p), p)
        out.append(zi)
    out[0] = mod_add(out[0], mod_mul(d, e, p), p)
    return out


@dataclass(frozen=True)
class AuthShare:
    value: int
    mac: int


def spdz_setup_alpha_shares(n: int, p: int, rng: DeterministicRng) -> List[int]:
    alpha = rng.randbelow(p)
    return additive_share(alpha, n, p, rng)


def _auth_share_secret_dealer(secret: int, alpha_shares: Sequence[int], p: int, rng: DeterministicRng) -> List[AuthShare]:
    n = len(alpha_shares)
    alpha = reconstruct(alpha_shares, p)
    secret = mod(secret, p)
    mac_total = mod_mul(alpha, secret, p)
    v_shares = additive_share(secret, n, p, rng)
    m_shares = additive_share(mac_total, n, p, rng)
    return [AuthShare(value=v_shares[i], mac=m_shares[i]) for i in range(n)]


def auth_add(x: Sequence[AuthShare], y: Sequence[AuthShare], p: int) -> List[AuthShare]:
    if len(x) != len(y):
        raise ValueError("mismatched party counts")
    return [AuthShare(mod_add(x[i].value, y[i].value, p), mod_add(x[i].mac, y[i].mac, p)) for i in range(len(x))]


def auth_sub(x: Sequence[AuthShare], y: Sequence[AuthShare], p: int) -> List[AuthShare]:
    if len(x) != len(y):
        raise ValueError("mismatched party counts")
    return [AuthShare(mod_sub(x[i].value, y[i].value, p), mod_sub(x[i].mac, y[i].mac, p)) for i in range(len(x))]


def auth_mul_public(x: Sequence[AuthShare], k: int, p: int) -> List[AuthShare]:
    k = mod(k, p)
    return [AuthShare(mod_mul(s.value, k, p), mod_mul(s.mac, k, p)) for s in x]


def auth_add_public(
    x: Sequence[AuthShare],
    c: int,
    alpha_shares: Sequence[int],
    p: int,
    party_index: int = 0,
) -> List[AuthShare]:
    if len(x) != len(alpha_shares):
        raise ValueError("mismatched party counts")
    n = len(x)
    c = mod(c, p)
    out = []
    for i in range(n):
        dv = c if i == party_index else 0
        dm = mod_mul(alpha_shares[i], c, p)
        out.append(AuthShare(mod_add(x[i].value, dv, p), mod_add(x[i].mac, dm, p)))
    return out


def spdz_open(x: Sequence[AuthShare], alpha_shares: Sequence[int], p: int) -> int:
    if len(x) != len(alpha_shares):
        raise ValueError("mismatched party counts")
    opened = reconstruct((s.value for s in x), p)
    deltas = [mod_sub(x[i].mac, mod_mul(alpha_shares[i], opened, p), p) for i in range(len(x))]
    check = reconstruct(deltas, p)
    if check != 0:
        raise ValueError("MAC check failed (tampering detected)")
    return opened


def beaver_triple_auth_shares(
    alpha_shares: Sequence[int],
    p: int,
    rng: DeterministicRng,
) -> Tuple[List[AuthShare], List[AuthShare], List[AuthShare]]:
    n = len(alpha_shares)
    a = rng.randbelow(p)
    b = rng.randbelow(p)
    c = mod_mul(a, b, p)
    return (
        _auth_share_secret_dealer(a, alpha_shares, p, rng),
        _auth_share_secret_dealer(b, alpha_shares, p, rng),
        _auth_share_secret_dealer(c, alpha_shares, p, rng),
    )


def spdz_multiply(
    x: Sequence[AuthShare],
    y: Sequence[AuthShare],
    triple: Tuple[Sequence[AuthShare], Sequence[AuthShare], Sequence[AuthShare]],
    alpha_shares: Sequence[int],
    p: int,
) -> List[AuthShare]:
    a, b, c = triple
    d = spdz_open(auth_sub(x, a, p), alpha_shares, p)
    e = spdz_open(auth_sub(y, b, p), alpha_shares, p)

    out = list(c)
    out = auth_add(out, auth_mul_public(b, d, p), p)
    out = auth_add(out, auth_mul_public(a, e, p), p)
    out = auth_add_public(out, mod_mul(d, e, p), alpha_shares, p, party_index=0)
    return out


def _fmt_shares(xs: Sequence[int]) -> str:
    return "[" + ", ".join(str(x) for x in xs) + "]"


def _fmt_auth(xs: Sequence[AuthShare]) -> str:
    pairs = ", ".join(f"({s.value}, {s.mac})" for s in xs)
    return "[" + pairs + "]"


def main():
    p = PRIME
    rng = DeterministicRng(b"spdz-lesson-demo")
    n = 3

    print("=== Step 1: Prime-field arithmetic + deterministic RNG ===")
    a = 2_000_000_000
    b = 200_000_000
    print(f"mod_add({a}, {b}) mod p = {mod_add(a, b, p)}")
    print(f"mod_mul(123456, 654321) mod p = {mod_mul(123456, 654321, p)}")
    print()

    print("=== Step 2: Additive secret sharing ===")
    secret = 424242
    shares = additive_share(secret, n, p, rng)
    print(f"secret = {secret}")
    print(f"shares = {_fmt_shares(shares)}")
    print(f"reconstruct(shares) = {reconstruct(shares, p)}")
    print()

    print("=== Step 3: Multiply shares with Beaver triples (semi-honest) ===")
    x = 1234
    y = 5678
    x_sh = additive_share(x, n, p, rng)
    y_sh = additive_share(y, n, p, rng)
    triple = beaver_triple_shares(n, p, rng)
    prod_sh = beaver_multiply_shares(x_sh, y_sh, triple, p)
    print(f"x = {x}, y = {y}")
    print(f"x_shares = {_fmt_shares(x_sh)}")
    print(f"y_shares = {_fmt_shares(y_sh)}")
    print(f"reconstruct(x*y shares) = {reconstruct(prod_sh, p)} (expected {mod_mul(x, y, p)})")
    print()

    print("=== Step 4: Authenticated shares + MAC-checked opening ===")
    alpha_shares = spdz_setup_alpha_shares(n, p, rng)
    x_auth = _auth_share_secret_dealer(x, alpha_shares, p, rng)
    opened_x = spdz_open(x_auth, alpha_shares, p)
    print(f"alpha_shares = {_fmt_shares(alpha_shares)} (alpha is hidden as a sum)")
    print(f"authenticated x = {_fmt_auth(x_auth)}  # (value_share, mac_share)")
    print(f"spdz_open(x) = {opened_x}")
    print()

    print("=== Step 5: SPDZ-style multiplication + tamper detection ===")
    y_auth = _auth_share_secret_dealer(y, alpha_shares, p, rng)
    triple_auth = beaver_triple_auth_shares(alpha_shares, p, rng)
    xy_auth = spdz_multiply(x_auth, y_auth, triple_auth, alpha_shares, p)
    xy = spdz_open(xy_auth, alpha_shares, p)
    print(f"spdz_open(x*y) = {xy} (expected {mod_mul(x, y, p)})")

    try:
        tampered = list(x_auth)
        tampered[0] = AuthShare(value=mod_add(tampered[0].value, 1, p), mac=tampered[0].mac)
        _ = spdz_open(tampered, alpha_shares, p)
        print("unexpected: tampered opening passed")
    except ValueError as e:
        print(f"tampering detected: {e}")


if __name__ == "__main__":
    main()
