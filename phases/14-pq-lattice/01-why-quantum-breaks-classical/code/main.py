"""
Why quantum breaks classical crypto (demo script).

Run:
  python3 code/main.py

This script demonstrates (with tiny, educational numbers) why:
- Shor's algorithm breaks RSA and discrete-log cryptography (public-key).
- Grover's algorithm halves the effective security of brute-force search.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from dataclasses import dataclass


def grover_effective_security_bits(classical_security_bits: int) -> float:
    if classical_security_bits < 0:
        raise ValueError("classical_security_bits must be >= 0")
    return classical_security_bits / 2.0


def grover_required_bits_for_target_security(target_security_bits: int) -> int:
    if target_security_bits < 0:
        raise ValueError("target_security_bits must be >= 0")
    return 2 * target_security_bits


def bht_effective_collision_security_bits(hash_output_bits: int) -> float:
    if hash_output_bits < 0:
        raise ValueError("hash_output_bits must be >= 0")
    return hash_output_bits / 3.0


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if a < 0 or b < 0:
        raise ValueError("egcd expects non-negative inputs")
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def modinv(a: int, m: int) -> int:
    if m <= 0:
        raise ValueError("m must be > 0")
    a = a % m
    g, x, _y = egcd(a, m)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % m


def rsa_keypair_from_primes(p: int, q: int, e: int = 65537) -> tuple[int, int, int]:
    if p <= 1 or q <= 1:
        raise ValueError("p and q must be > 1")
    if p == q:
        raise ValueError("p and q must be distinct")
    if e <= 1:
        raise ValueError("e must be > 1")
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    return n, e, d


def rsa_encrypt(m: int, n: int, e: int) -> int:
    if not (0 <= m < n):
        raise ValueError("message representative must be in [0, n)")
    return pow(m, e, n)


def rsa_decrypt(c: int, n: int, d: int) -> int:
    if not (0 <= c < n):
        raise ValueError("ciphertext representative must be in [0, n)")
    return pow(c, d, n)


@dataclass(frozen=True)
class TrialDivisionResult:
    factor: int | None
    steps: int


def trial_division_small_factor(n: int, max_divisor: int | None = None) -> TrialDivisionResult:
    if n <= 1:
        raise ValueError("n must be > 1")
    if n % 2 == 0:
        return TrialDivisionResult(2, 1)

    limit = int(math.isqrt(n))
    if max_divisor is not None:
        if max_divisor < 2:
            raise ValueError("max_divisor must be >= 2")
        limit = min(limit, max_divisor)

    steps = 0
    d = 3
    while d <= limit:
        steps += 1
        if n % d == 0:
            return TrialDivisionResult(d, steps)
        d += 2
    return TrialDivisionResult(None, steps)


def factor_semiprime_by_trial_division(n: int) -> tuple[int, int, int]:
    result = trial_division_small_factor(n)
    if result.factor is None:
        raise ValueError("n did not factor by trial division (maybe prime or too large?)")
    p = result.factor
    q = n // p
    if p * q != n:
        raise AssertionError("internal factoring invariant failed")
    return p, q, result.steps


def break_rsa_by_factoring(n: int, e: int) -> tuple[int, int, int]:
    p, q, _steps = factor_semiprime_by_trial_division(n)
    _n, _e, d = rsa_keypair_from_primes(p, q, e=e)
    return p, q, d


def sha256_prefix_bits(data: bytes, prefix_bits: int) -> int:
    if prefix_bits < 0:
        raise ValueError("prefix_bits must be >= 0")
    digest = hashlib.sha256(data).digest()
    digest_int = int.from_bytes(digest, byteorder="big")
    if prefix_bits == 0:
        return 0
    return digest_int >> (256 - prefix_bits)


def find_sha256_prefix_preimage(prefix_bits: int, target_prefix: int, max_tries: int) -> tuple[int, int]:
    if prefix_bits < 0:
        raise ValueError("prefix_bits must be >= 0")
    if max_tries < 0:
        raise ValueError("max_tries must be >= 0")
    if prefix_bits == 0:
        if target_prefix != 0:
            raise ValueError("for prefix_bits=0, target_prefix must be 0")
    else:
        if not (0 <= target_prefix < (1 << prefix_bits)):
            raise ValueError("target_prefix out of range for prefix_bits")

    for x in range(max_tries):
        prefix = sha256_prefix_bits(str(x).encode("utf-8"), prefix_bits)
        if prefix == target_prefix:
            return x, x + 1
    raise ValueError("no preimage found within max_tries")


def pqc_replacement_for(primitive: str) -> str:
    key = primitive.strip().lower()
    mapping = {
        "rsa": "Replace with ML-KEM (Kyber) for KEM; keep RSA only for legacy, behind crypto-agility.",
        "ecdh": "Replace with hybrid key exchange: X25519 + ML-KEM (draft/standard TLS hybrid patterns).",
        "dh": "Replace with hybrid key exchange: (EC)DH + ML-KEM; prefer X25519 for the classical half.",
        "ecdsa": "Replace with ML-DSA (Dilithium) or a hybrid signature (classical + ML-DSA) during migration.",
        "ed25519": "Replace with ML-DSA or hybrid Ed25519 + ML-DSA, depending on protocol and ecosystem support.",
        "sha-256": "Keep SHA-256; quantum changes security margins (preimage ~halves), but 256-bit outputs remain strong.",
        "aes-128": "Prefer AES-256 if you want ~128-bit security against Grover-style key search.",
    }
    if key not in mapping:
        raise ValueError(f"unknown primitive: {primitive!r}")
    return mapping[key]


def _format_two_power(bits: float) -> str:
    if bits < 0:
        raise ValueError("bits must be >= 0")
    if bits == 0:
        return "2^0 = 1"
    log10 = bits * math.log10(2)
    if log10 < 6:
        return f"≈ {2 ** bits:.0f} (2^{bits:g})"
    return f"≈ 10^{log10:.1f} (2^{bits:g})"


def _print_header(step: int, name: str) -> None:
    print(f"=== Step {step}: {name} ===")


def main() -> None:
    _print_header(1, "Quantify Grover's impact (key search)")
    classical = 128
    quantum = grover_effective_security_bits(classical)
    print(f"Classical {classical}-bit brute-force cost -> quantum effective ≈ {quantum:g} bits")
    print(f"To target {classical} bits against Grover, use key/hash preimage size ≈ {grover_required_bits_for_target_security(classical)} bits")
    print(f"SHA-256 collision security under BHT-style quantum collision search ≈ {bht_effective_collision_security_bits(256):g} bits")
    print()

    _print_header(2, "Toy hash-prefix preimage search (brute force)")
    prefix_bits = 16
    target_prefix = 0
    max_tries = 200_000
    x, queries = find_sha256_prefix_preimage(prefix_bits, target_prefix, max_tries=max_tries)
    print(f"Found x={x} such that sha256(str(x)) starts with {prefix_bits} zero bits in {queries} queries")
    print(f"Classical expected queries ≈ {_format_two_power(prefix_bits)}")
    print(f"Grover-style expected queries ≈ {_format_two_power(prefix_bits / 2)}")
    print()

    _print_header(3, "RSA break: once you can factor n, you can recover d")
    p, q = 4099, 4201
    n, e, d = rsa_keypair_from_primes(p, q, e=65537)
    m = 123456
    c = rsa_encrypt(m, n, e)
    recovered_m = rsa_decrypt(c, n, d)
    print(f"RSA public key: n={n}, e={e}")
    print(f"Encrypt m={m} -> c={c} -> decrypt -> {recovered_m}")
    ap, aq, ad = break_rsa_by_factoring(n, e)
    attacker_m = rsa_decrypt(c, n, ad)
    print(f"Attacker factors n into p={ap}, q={aq} and recovers d={ad}")
    print(f"Attacker decrypts c -> {attacker_m}")
    _, _, steps = factor_semiprime_by_trial_division(n)
    print(f"Trial-division steps to find a factor (toy n): {steps}")
    print()

    _print_header(4, "Migration mapping (what to replace, and with what)")
    for primitive in ["RSA", "ECDH", "ECDSA", "AES-128", "SHA-256"]:
        print(f"- {primitive}: {pqc_replacement_for(primitive)}")
    print()


if __name__ == "__main__":
    main()
