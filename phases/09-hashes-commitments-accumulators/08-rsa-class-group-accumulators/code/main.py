"""
RSA accumulators (and the same API idea used by class group accumulators).

Run:
  python3 code/main.py

This is an educational, toy-parameter implementation:
- Deterministic hash-to-prime representatives for set elements
- RSA accumulator value for a set
- Membership witnesses and updates
- Non-membership proofs (Bezout-based) for RSA accumulators
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Iterable


def is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2

    bases = [2, 325, 9375, 28178, 450775, 9780504, 1795265022]
    for a in bases:
        a %= n
        if a == 0:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def hash_to_prime(message: bytes, *, domain: str = "rsa-accum", bits: int = 32) -> int:
    if bits < 8:
        raise ValueError("bits must be >= 8")

    counter = 0
    while True:
        h = hashlib.sha256(
            domain.encode("utf-8")
            + b"\x00"
            + counter.to_bytes(4, "big")
            + b"\x00"
            + message
        ).digest()
        x = int.from_bytes(h, "big")
        candidate = (x & ((1 << bits) - 1)) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate
        counter += 1


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a: int, m: int) -> int:
    g, x, _y = egcd(a, m)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % m


def pow_mod_signed(base: int, exponent: int, modulus: int) -> int:
    if exponent >= 0:
        return pow(base, exponent, modulus)
    return pow(modinv(base, modulus), -exponent, modulus)


def qr_base(modulus: int, seed: bytes) -> int:
    x = int.from_bytes(hashlib.sha256(seed).digest(), "big") % modulus
    if x == 0:
        x = 2
    while math.gcd(x, modulus) != 1:
        x = (x + 1) % modulus
        if x == 0:
            x = 2
    return pow(x, 2, modulus)


def rsa_accumulate(prime_reps: Iterable[int], *, modulus: int, base: int) -> int:
    acc = base % modulus
    for p in prime_reps:
        if p <= 1:
            raise ValueError("prime representatives must be > 1")
        acc = pow(acc, p, modulus)
    return acc


def rsa_add(acc_value: int, prime_rep: int, *, modulus: int) -> int:
    if prime_rep <= 1:
        raise ValueError("prime representative must be > 1")
    return pow(acc_value % modulus, prime_rep, modulus)


def rsa_membership_witness(
    all_prime_reps: list[int],
    member_prime_rep: int,
    *,
    modulus: int,
    base: int,
) -> int:
    if member_prime_rep not in all_prime_reps:
        raise ValueError("member_prime_rep must be in the set")
    witness = base % modulus
    skipped = False
    for p in all_prime_reps:
        if not skipped and p == member_prime_rep:
            skipped = True
            continue
        witness = pow(witness, p, modulus)
    return witness


def rsa_update_witness_on_add(witness: int, added_prime_rep: int, *, modulus: int) -> int:
    if added_prime_rep <= 1:
        raise ValueError("prime representative must be > 1")
    return pow(witness % modulus, added_prime_rep, modulus)


def rsa_verify_membership(
    acc_value: int, witness: int, member_prime_rep: int, *, modulus: int
) -> bool:
    if member_prime_rep <= 1:
        return False
    return pow(witness % modulus, member_prime_rep, modulus) == (acc_value % modulus)


def rsa_nonmembership_proof(
    all_prime_reps: Iterable[int],
    nonmember_prime_rep: int,
    *,
    modulus: int,
    base: int,
) -> tuple[int, int]:
    if nonmember_prime_rep <= 1:
        raise ValueError("prime representative must be > 1")

    s = 1
    for p in all_prime_reps:
        if p <= 1:
            raise ValueError("prime representatives must be > 1")
        if p == nonmember_prime_rep:
            raise ValueError("nonmember_prime_rep must not be in the set")
        s *= p

    if math.gcd(s, nonmember_prime_rep) != 1:
        raise ValueError("nonmember_prime_rep must be coprime to the set product")

    _g, a, b = egcd(s, nonmember_prime_rep)
    d = pow_mod_signed(base % modulus, b, modulus)
    return (a, d)


def rsa_verify_nonmembership(
    acc_value: int,
    nonmember_prime_rep: int,
    proof_a: int,
    proof_d: int,
    *,
    modulus: int,
    base: int,
) -> bool:
    if nonmember_prime_rep <= 1:
        return False
    left = (
        pow_mod_signed(acc_value % modulus, proof_a, modulus)
        * pow(proof_d % modulus, nonmember_prime_rep, modulus)
    ) % modulus
    return left == (base % modulus)


@dataclass(frozen=True)
class DemoParams:
    modulus: int
    base: int


def main() -> None:
    params = DemoParams(modulus=101 * 113, base=qr_base(101 * 113, b"demo-base"))

    print("=== Step 1: Prime representatives (hash-to-prime) ===")
    elements = [b"alice", b"bob", b"carol"]
    prime_reps = [hash_to_prime(e) for e in elements]
    for e, p in zip(elements, prime_reps, strict=True):
        print(f"{e.decode('utf-8')!r} -> {p}")

    print("\n=== Step 2: Accumulate a set into one value ===")
    print(f"N = {params.modulus} (toy; real systems use 2048+ bits)")
    print(f"g = {params.base} (quadratic residue mod N)")
    acc = rsa_accumulate(prime_reps, modulus=params.modulus, base=params.base)
    print(f"Accumulator A = {acc}")

    print("\n=== Step 3: Membership witnesses + updates ===")
    member = elements[1]
    member_p = prime_reps[1]
    w = rsa_membership_witness(prime_reps, member_p, modulus=params.modulus, base=params.base)
    ok = rsa_verify_membership(acc, w, member_p, modulus=params.modulus)
    print(f"Membership proof for {member.decode('utf-8')!r}: witness={w}, verifies={ok}")

    added = b"dave"
    added_p = hash_to_prime(added)
    acc2 = rsa_add(acc, added_p, modulus=params.modulus)
    w2 = rsa_update_witness_on_add(w, added_p, modulus=params.modulus)
    ok2 = rsa_verify_membership(acc2, w2, member_p, modulus=params.modulus)
    print(f"After adding {added.decode('utf-8')!r}: A'={acc2}, updated witness verifies={ok2}")

    print("\n=== Step 4: Non-membership proofs (RSA-specific) ===")
    (a, d) = rsa_nonmembership_proof(
        prime_reps, added_p, modulus=params.modulus, base=params.base
    )
    ok_nm = rsa_verify_nonmembership(
        acc, added_p, a, d, modulus=params.modulus, base=params.base
    )
    print(
        f"Non-membership proof for {added.decode('utf-8')!r}: (a={a}, d={d}), verifies={ok_nm}"
    )


if __name__ == "__main__":
    main()
