"""What zero-knowledge means, by building a tiny Schnorr Σ-protocol demo.

Run:
  python3 code/main.py

This script demonstrates the three core properties:
  - Completeness: honest prover convinces honest verifier.
  - Soundness / proof of knowledge intuition: two accepting transcripts with
    the same commit but different challenges let you extract the witness.
  - (Honest-verifier) zero-knowledge: a simulator can generate accepting
    transcripts without knowing the witness.

Educational implementation. Not constant-time. Not production-safe.
"""

from __future__ import annotations

from dataclasses import dataclass
import random


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended GCD: returns (g, x, y) such that a*x + b*y = g = gcd(a, b)."""
    if b == 0:
        return (abs(a), 1 if a >= 0 else -1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def mod_inv(a: int, mod: int) -> int:
    """Multiplicative inverse of a modulo mod. Raises ValueError if none."""
    a = a % mod
    if a == 0:
        raise ValueError("0 has no inverse modulo mod")
    g, x, _y = egcd(a, mod)
    if g != 1:
        raise ValueError("a and mod are not coprime")
    return x % mod


def mod_mul(a: int, b: int, mod: int) -> int:
    return (a % mod) * (b % mod) % mod


def mod_pow(base: int, exp: int, mod: int) -> int:
    return pow(base % mod, exp, mod)


@dataclass(frozen=True)
class SchnorrParams:
    p: int
    q: int
    g: int


def schnorr_public_key(params: SchnorrParams, x: int) -> int:
    x = x % params.q
    return mod_pow(params.g, x, params.p)


def schnorr_commit(params: SchnorrParams, r: int) -> int:
    r = r % params.q
    return mod_pow(params.g, r, params.p)


def schnorr_response(q: int, r: int, e: int, x: int) -> int:
    return (r + e * x) % q


def schnorr_verify(
    params: SchnorrParams, y: int, a: int, e: int, z: int
) -> bool:
    if not (0 <= e < params.q):
        return False
    if not (0 <= z < params.q):
        return False
    left = mod_pow(params.g, z, params.p)
    right = mod_mul(a, mod_pow(y, e, params.p), params.p)
    return left == right


def schnorr_simulate_hvz(
    params: SchnorrParams, y: int, e: int, z: int
) -> tuple[int, int, int]:
    """Honest-verifier ZK simulator for Schnorr transcripts.

    Picks (e, z) uniformly and computes a so that verification passes:
      g^z = a * y^e   =>   a = g^z * (y^e)^(-1)  (mod p)
    """
    e = e % params.q
    z = z % params.q
    y_to_e = mod_pow(y, e, params.p)
    a = mod_mul(mod_pow(params.g, z, params.p), mod_inv(y_to_e, params.p), params.p)
    return (a, e, z)


def schnorr_extract_witness(
    q: int, e1: int, z1: int, e2: int, z2: int
) -> int:
    """Extract x from two accepting transcripts with same commit and e1 != e2."""
    if e1 == e2:
        raise ValueError("need two different challenges to extract")
    num = (z1 - z2) % q
    den = (e1 - e2) % q
    return (num * mod_inv(den, q)) % q


def assert_schnorr_params(params: SchnorrParams, y: int) -> None:
    if params.p <= 2 or params.q <= 1:
        raise ValueError("bad group parameters")
    if mod_pow(params.g, params.q, params.p) != 1:
        raise ValueError("g does not have order q")
    if mod_pow(y, params.q, params.p) != 1:
        raise ValueError("y is not in the subgroup of order q")


def fmt_transcript(a: int, e: int, z: int) -> str:
    return f"(a={a}, e={e}, z={z})"


def step_1_mod_arithmetic() -> None:
    print("=== Step 1: Modular arithmetic (inverse) ===")
    mod = 23
    a = 7
    inv = mod_inv(a, mod)
    print(f"mod = {mod}")
    print(f"a = {a}")
    print(f"inv(a) mod mod = {inv}")
    print(f"a * inv(a) mod mod = {(a * inv) % mod}")


def step_2_completeness_demo(params: SchnorrParams, x: int) -> tuple[int, int, int, int]:
    print("=== Step 2: Completeness (real Schnorr transcript) ===")
    y = schnorr_public_key(params, x)
    assert_schnorr_params(params, y)

    r = 3
    e = 4
    a = schnorr_commit(params, r)
    z = schnorr_response(params.q, r, e, x)
    ok = schnorr_verify(params, y, a, e, z)

    print(f"params: p={params.p}, q={params.q}, g={params.g}")
    print(f"witness x = {x}")
    print(f"public y = g^x mod p = {y}")
    print(f"commit r = {r} -> a = {a}")
    print(f"challenge e = {e}")
    print(f"response z = {z}")
    print(f"verifier accepts: {ok}")
    print(f"transcript: {fmt_transcript(a, e, z)}")
    return (y, a, e, z)


def step_3_hvz_simulator_demo(params: SchnorrParams, y: int) -> None:
    print("=== Step 3: Zero-knowledge (HVZK simulator) ===")
    rng = random.Random(0)
    transcripts: list[tuple[int, int, int]] = []
    for _ in range(3):
        e = rng.randrange(0, params.q)
        z = rng.randrange(0, params.q)
        a, e, z = schnorr_simulate_hvz(params, y, e, z)
        transcripts.append((a, e, z))

    for i, (a, e, z) in enumerate(transcripts, start=1):
        ok = schnorr_verify(params, y, a, e, z)
        print(f"simulated #{i}: {fmt_transcript(a, e, z)} -> accepts={ok}")

    print("A simulator produced accepting transcripts without x.")


def step_4_extraction_demo(params: SchnorrParams, x: int, y: int) -> None:
    print("=== Step 4: Soundness intuition (extracting the witness) ===")
    r = 3
    a = schnorr_commit(params, r)
    e1, e2 = 4, 2
    z1 = schnorr_response(params.q, r, e1, x)
    z2 = schnorr_response(params.q, r, e2, x)
    ok1 = schnorr_verify(params, y, a, e1, z1)
    ok2 = schnorr_verify(params, y, a, e2, z2)
    extracted = schnorr_extract_witness(params.q, e1, z1, e2, z2)

    print(f"same commit a = {a} (same r)")
    print(f"transcript 1: {fmt_transcript(a, e1, z1)} -> accepts={ok1}")
    print(f"transcript 2: {fmt_transcript(a, e2, z2)} -> accepts={ok2}")
    print(f"extract(x) from (e,z) pairs -> x = {extracted}")
    print(f"matches real x: {extracted == (x % params.q)}")


def main() -> None:
    params = SchnorrParams(p=23, q=11, g=2)
    x = 7

    step_1_mod_arithmetic()
    y, _a, _e, _z = step_2_completeness_demo(params, x)
    step_3_hvz_simulator_demo(params, y)
    step_4_extraction_demo(params, x, y)


if __name__ == "__main__":
    main()
