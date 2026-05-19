"""
Poseidon hash (educational, ZK-friendly hash over a prime field).

Run:
  python3 code/main.py

This script:
- Implements a Poseidon-style permutation (Hades strategy) over the BN254 prime field.
- Generates round constants and a Cauchy MDS matrix deterministically from a seed.
- Builds two sponge hashes:
  - an intentionally unsafe variant that allows trivial collisions via implicit zero padding
  - a safer variant that encodes length and uses padding

Educational implementation. Not constant-time. Not production-safe.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Sequence


BN254_PRIME = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)


@dataclass(frozen=True)
class PoseidonParams:
    p: int
    t: int
    rate: int
    alpha: int
    full_rounds: int
    partial_rounds: int
    mds: tuple[tuple[int, ...], ...]
    round_constants: tuple[int, ...]
    seed: bytes


def fe(x: int, p: int) -> int:
    if not isinstance(x, int):
        raise TypeError("field elements must be integers")
    if not isinstance(p, int) or p <= 2:
        raise ValueError("p must be an integer prime modulus > 2")
    return x % p


def fe_inv(x: int, p: int) -> int:
    a = fe(x, p)
    if a == 0:
        raise ValueError("0 has no inverse modulo p")
    return pow(a, p - 2, p)


class SHA256XOF:
    def __init__(self, seed: bytes):
        if not isinstance(seed, (bytes, bytearray, memoryview)):
            raise TypeError("seed must be bytes-like")
        self._seed = bytes(seed)
        self._ctr = 0

    def next_u256(self) -> int:
        c = self._ctr
        self._ctr += 1
        digest = hashlib.sha256(self._seed + c.to_bytes(4, "big")).digest()
        return int.from_bytes(digest, "big")

    def next_field(self, p: int) -> int:
        while True:
            x = self.next_u256()
            if x < p:
                return x


def _generate_distinct_field_elements(*, p: int, n: int, seed: bytes) -> list[int]:
    xof = SHA256XOF(seed)
    out: list[int] = []
    seen: set[int] = set()
    while len(out) < n:
        v = xof.next_field(p)
        if v == 0 or v in seen:
            continue
        out.append(v)
        seen.add(v)
    return out


def generate_cauchy_mds(*, p: int, t: int, seed: bytes) -> tuple[tuple[int, ...], ...]:
    if t < 2:
        raise ValueError("t must be >= 2")
    xs = _generate_distinct_field_elements(p=p, n=t, seed=seed + b"/x")
    ys = _generate_distinct_field_elements(p=p, n=t, seed=seed + b"/y")

    rows: list[tuple[int, ...]] = []
    for i in range(t):
        row: list[int] = []
        for j in range(t):
            denom = (xs[i] + ys[j]) % p
            if denom == 0:
                raise ValueError("bad Cauchy construction: x_i + y_j == 0")
            row.append(fe_inv(denom, p))
        rows.append(tuple(row))
    return tuple(rows)


def generate_round_constants(*, p: int, n: int, seed: bytes) -> tuple[int, ...]:
    if n <= 0:
        raise ValueError("n must be positive")
    xof = SHA256XOF(seed + b"/rc")
    return tuple(xof.next_field(p) for _ in range(n))


def poseidon_default_params() -> PoseidonParams:
    p = BN254_PRIME
    t = 3
    rate = 2
    alpha = 5
    full_rounds = 8
    partial_rounds = 57
    seed = b"CFSC-POSEIDON-v1"

    mds = generate_cauchy_mds(p=p, t=t, seed=seed)
    round_constants = generate_round_constants(
        p=p, n=(full_rounds + partial_rounds) * t, seed=seed
    )
    return PoseidonParams(
        p=p,
        t=t,
        rate=rate,
        alpha=alpha,
        full_rounds=full_rounds,
        partial_rounds=partial_rounds,
        mds=mds,
        round_constants=round_constants,
        seed=seed,
    )


def _mat_vec_mul(m: Sequence[Sequence[int]], v: Sequence[int], p: int) -> list[int]:
    t = len(v)
    if len(m) != t or any(len(row) != t for row in m):
        raise ValueError("matrix must be t x t")
    out = [0] * t
    for i in range(t):
        acc = 0
        for j in range(t):
            acc = (acc + m[i][j] * v[j]) % p
        out[i] = acc
    return out


def poseidon_permute(state: Sequence[int], *, params: PoseidonParams) -> list[int]:
    if not isinstance(state, (list, tuple)):
        raise TypeError("state must be a sequence of integers")
    if len(state) != params.t:
        raise ValueError(f"state must have length t={params.t}")

    p = params.p
    st = [fe(x, p) for x in state]

    rounds = params.full_rounds + params.partial_rounds
    full_half = params.full_rounds // 2
    rc = params.round_constants
    rc_idx = 0

    for r in range(rounds):
        for i in range(params.t):
            st[i] = (st[i] + rc[rc_idx]) % p
            rc_idx += 1

        if r < full_half or r >= full_half + params.partial_rounds:
            st = [pow(x, params.alpha, p) for x in st]
        else:
            st[0] = pow(st[0], params.alpha, p)

        st = _mat_vec_mul(params.mds, st, p)

    return st


def poseidon_sponge_hash_unsafe(
    inputs: Sequence[int], *, params: PoseidonParams, domain: int = 0
) -> int:
    if not isinstance(inputs, (list, tuple)):
        raise TypeError("inputs must be a sequence of integers")
    if params.t != 3 or params.rate != 2:
        raise ValueError("this educational sponge expects (t=3, rate=2)")

    p = params.p
    st = [fe(domain, p), 0, 0]

    i = 0
    while i < len(inputs):
        chunk = inputs[i : i + params.rate]
        for j, x in enumerate(chunk):
            st[1 + j] = (st[1 + j] + fe(x, p)) % p
        st = poseidon_permute(st, params=params)
        i += params.rate

    if len(inputs) == 0:
        st = poseidon_permute(st, params=params)

    return st[1]


def poseidon_sponge_hash(
    inputs: Sequence[int], *, params: PoseidonParams, domain: int = 0
) -> int:
    if not isinstance(inputs, (list, tuple)):
        raise TypeError("inputs must be a sequence of integers")
    if params.t != 3 or params.rate != 2:
        raise ValueError("this educational sponge expects (t=3, rate=2)")

    p = params.p
    iv = (fe(domain, p) + (len(inputs) << 64)) % p
    st = [iv, 0, 0]

    i = 0
    while i < len(inputs):
        chunk = inputs[i : i + params.rate]
        for j, x in enumerate(chunk):
            st[1 + j] = (st[1 + j] + fe(x, p)) % p
        if len(chunk) < params.rate:
            st[1 + len(chunk)] = (st[1 + len(chunk)] + 1) % p
        st = poseidon_permute(st, params=params)
        i += params.rate

    if len(inputs) % params.rate == 0:
        st[1] = (st[1] + 1) % p
        st = poseidon_permute(st, params=params)

    return st[1]


def _print_step(n: int, name: str) -> None:
    print(f"=== Step {n}: {name} ===")


def step1_prime_field_arithmetic() -> None:
    _print_step(1, "Prime field arithmetic (BN254)")
    p = BN254_PRIME
    print(f"p = {p}")
    print(f"(-1 mod p) = {fe(-1, p)}")
    x = 7
    inv = fe_inv(x, p)
    print(f"inv({x}) = {inv}")
    print(f"{x} * inv({x}) mod p = {(x * inv) % p}")


def step2_deterministic_params() -> None:
    _print_step(2, "Deterministic constants (seeded) + Cauchy MDS")
    params = poseidon_default_params()
    print(f"seed = {params.seed!r}")
    print(f"alpha = {params.alpha}, full_rounds = {params.full_rounds}, partial_rounds = {params.partial_rounds}")
    print(f"mds[0][0] = {params.mds[0][0]}")
    print(f"round_constants[0] = {params.round_constants[0]}")
    print(f"round_constants[-1] = {params.round_constants[-1]}")


def step3_poseidon_permutation() -> None:
    _print_step(3, "Poseidon permutation (Hades rounds)")
    params = poseidon_default_params()
    s1 = [0, 1, 2]
    s2 = [0, 1, 3]
    out1 = poseidon_permute(s1, params=params)
    out2 = poseidon_permute(s2, params=params)
    print(f"permute({s1}) = {out1}")
    print(f"permute({s2}) = {out2}")


def step4_unsafe_sponge_collision() -> None:
    _print_step(4, "Pitfall: implicit zero padding causes collisions")
    params = poseidon_default_params()
    a = 123
    h1 = poseidon_sponge_hash_unsafe([a], params=params)
    h2 = poseidon_sponge_hash_unsafe([a, 0], params=params)
    print(f"unsafe_hash([123])   = {h1}")
    print(f"unsafe_hash([123,0]) = {h2}")
    print(f"collision? {h1 == h2}")


def step5_safe_sponge_hashing() -> None:
    _print_step(5, "Safer sponge: length encoding + padding + domain separation")
    params = poseidon_default_params()
    print(f"hash([123])   = {poseidon_sponge_hash([123], params=params, domain=0)}")
    print(f"hash([123,0]) = {poseidon_sponge_hash([123, 0], params=params, domain=0)}")
    print(f"hash([123,456]) = {poseidon_sponge_hash([123, 456], params=params, domain=0)}")
    print(f"domain-separated hash([123,456], domain=1) = {poseidon_sponge_hash([123, 456], params=params, domain=1)}")


def main() -> None:
    step1_prime_field_arithmetic()
    print()
    step2_deterministic_params()
    print()
    step3_poseidon_permutation()
    print()
    step4_unsafe_sponge_collision()
    print()
    step5_safe_sponge_hashing()


if __name__ == "__main__":
    main()
