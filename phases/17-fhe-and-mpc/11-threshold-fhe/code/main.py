"""
Threshold FHE (toy) via threshold decryption on an additively-homomorphic scheme.

This script builds a small, runnable demo of:
1) Paillier (toy parameters) for additive homomorphic encryption, and
2) Shamir secret sharing to require t-of-n parties to decrypt.

Run:
  python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import secrets
from typing import Iterable, Sequence


SHAMIR_PRIME_127 = (1 << 127) - 1


@dataclass(frozen=True)
class PaillierPublicKey:
    n: int
    g: int
    n_sq: int


@dataclass(frozen=True)
class PaillierPrivateKey:
    lam: int
    mu: int


@dataclass(frozen=True)
class Share:
    x: int
    y: int


@dataclass(frozen=True)
class ThresholdPaillierShare:
    x: int
    lam_y: int
    mu_y: int


def egcd(a: int, b: int) -> tuple[int, int, int]:
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
    a %= m
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("no modular inverse")
    return x % m


def lcm(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return abs(a // math.gcd(a, b) * b)


def L(u: int, n: int) -> int:
    if (u - 1) % n != 0:
        raise ValueError("L(u) undefined: u != 1 (mod n)")
    return (u - 1) // n


def paillier_keygen_from_primes(p: int, q: int) -> tuple[PaillierPublicKey, PaillierPrivateKey]:
    if p <= 2 or q <= 2 or p == q:
        raise ValueError("p and q must be distinct primes > 2")
    n = p * q
    n_sq = n * n
    g = n + 1
    lam = lcm(p - 1, q - 1)
    u = pow(g, lam, n_sq)
    lu = L(u, n)
    mu = modinv(lu, n)
    return PaillierPublicKey(n=n, g=g, n_sq=n_sq), PaillierPrivateKey(lam=lam, mu=mu)


def paillier_encrypt(m: int, pub: PaillierPublicKey, r: int | None = None) -> int:
    if not (0 <= m < pub.n):
        raise ValueError("message out of range")
    if r is None:
        r = paillier_sample_r(pub.n)
    if math.gcd(r, pub.n) != 1:
        raise ValueError("r must be in Z*_n")
    return (pow(pub.g, m, pub.n_sq) * pow(r, pub.n, pub.n_sq)) % pub.n_sq


def paillier_decrypt(c: int, pub: PaillierPublicKey, priv: PaillierPrivateKey) -> int:
    if not (0 <= c < pub.n_sq):
        raise ValueError("ciphertext out of range")
    u = pow(c, priv.lam, pub.n_sq)
    return (L(u, pub.n) * priv.mu) % pub.n


def paillier_hom_add(c1: int, c2: int, pub: PaillierPublicKey) -> int:
    return (c1 * c2) % pub.n_sq


def paillier_hom_scalar_mul(c: int, k: int, pub: PaillierPublicKey) -> int:
    if k < 0:
        raise ValueError("k must be non-negative in this toy demo")
    return pow(c, k, pub.n_sq)


def paillier_sample_r(n: int) -> int:
    while True:
        r = secrets.randbelow(n - 1) + 1
        if math.gcd(r, n) == 1:
            return r


def poly_eval(coeffs: Sequence[int], x: int, prime: int) -> int:
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % prime
    return acc


def shamir_split(
    secret: int,
    n_shares: int,
    threshold: int,
    prime: int,
    *,
    coefficients: Sequence[int] | None = None,
) -> list[Share]:
    if not (1 <= threshold <= n_shares):
        raise ValueError("invalid threshold")
    if not (0 <= secret < prime):
        raise ValueError("secret out of field range")
    if coefficients is None:
        coeffs = [secret] + [secrets.randbelow(prime) for _ in range(threshold - 1)]
    else:
        if len(coefficients) != threshold - 1:
            raise ValueError("wrong number of coefficients")
        if any((c < 0 or c >= prime) for c in coefficients):
            raise ValueError("coefficients out of field range")
        coeffs = [secret, *coefficients]
    return [Share(x=i, y=poly_eval(coeffs, i, prime)) for i in range(1, n_shares + 1)]


def shamir_reconstruct_at_zero(shares: Sequence[Share], prime: int) -> int:
    if len(shares) == 0:
        raise ValueError("need at least one share")
    xs = [s.x % prime for s in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate x coordinates")

    secret = 0
    for j, share_j in enumerate(shares):
        xj = xs[j]
        num = 1
        den = 1
        for m, xm in enumerate(xs):
            if m == j:
                continue
            num = (num * xm) % prime
            den = (den * (xm - xj)) % prime
        lj = num * modinv(den, prime) % prime
        secret = (secret + share_j.y * lj) % prime
    return secret


def threshold_split_paillier_private_key(
    priv: PaillierPrivateKey,
    *,
    n_shares: int,
    threshold: int,
    prime: int,
    lam_coefficients: Sequence[int] | None = None,
    mu_coefficients: Sequence[int] | None = None,
) -> list[ThresholdPaillierShare]:
    lam_shares = shamir_split(priv.lam, n_shares, threshold, prime, coefficients=lam_coefficients)
    mu_shares = shamir_split(priv.mu, n_shares, threshold, prime, coefficients=mu_coefficients)
    combined: list[ThresholdPaillierShare] = []
    for ls, ms in zip(lam_shares, mu_shares, strict=True):
        combined.append(ThresholdPaillierShare(x=ls.x, lam_y=ls.y, mu_y=ms.y))
    return combined


def threshold_decrypt_paillier(
    c: int,
    pub: PaillierPublicKey,
    shares: Sequence[ThresholdPaillierShare],
    *,
    threshold: int,
    prime: int,
) -> int:
    if len(shares) < threshold:
        raise ValueError("not enough shares to decrypt")
    used = shares[:threshold]
    lam = shamir_reconstruct_at_zero([Share(s.x, s.lam_y) for s in used], prime)
    mu = shamir_reconstruct_at_zero([Share(s.x, s.mu_y) for s in used], prime)
    return paillier_decrypt(c, pub, PaillierPrivateKey(lam=lam, mu=mu))


def _header(step: int, name: str) -> None:
    print(f"=== Step {step}: {name} ===")


def main() -> None:
    _header(1, "Toy Paillier (additive HE)")
    pub, priv = paillier_keygen_from_primes(101, 113)
    m = 1234
    c = paillier_encrypt(m, pub, r=2)
    m_dec = paillier_decrypt(c, pub, priv)
    print(f"n={pub.n}")
    print(f"m={m} -> c={c} -> decrypt(c)={m_dec}")

    _header(2, "Homomorphic evaluation (add, scalar mul)")
    m1, m2 = 20, 7
    c1 = paillier_encrypt(m1, pub, r=3)
    c2 = paillier_encrypt(m2, pub, r=5)
    c_sum = paillier_hom_add(c1, c2, pub)
    c_scaled = paillier_hom_scalar_mul(c1, 10, pub)
    print(f"decrypt(Enc({m1}) * Enc({m2})) = {paillier_decrypt(c_sum, pub, priv)}")
    print(f"decrypt(Enc({m1})^10) = {paillier_decrypt(c_scaled, pub, priv)}")

    _header(3, "Shamir secret sharing (t-of-n)")
    secret = 4242
    shares = shamir_split(secret, n_shares=5, threshold=3, prime=SHAMIR_PRIME_127, coefficients=[1, 2])
    recovered = shamir_reconstruct_at_zero(shares[:3], SHAMIR_PRIME_127)
    recovered_with_2 = shamir_reconstruct_at_zero(shares[:2], SHAMIR_PRIME_127)
    print(f"secret={secret}, recovered_from_3={recovered}")
    print(f"recovered_from_2={recovered_with_2} (wrong without a 3rd share)")

    _header(4, "Threshold decryption (reconstruct-and-decrypt)")
    tshares = threshold_split_paillier_private_key(
        priv,
        n_shares=5,
        threshold=3,
        prime=SHAMIR_PRIME_127,
        lam_coefficients=[10, 20],
        mu_coefficients=[30, 40],
    )
    m_vote_total = 0
    vote_ciphertexts: list[int] = []
    for vote, r in [(1, 7), (0, 11), (1, 13), (1, 17)]:
        m_vote_total += vote
        vote_ciphertexts.append(paillier_encrypt(vote, pub, r=r))
    c_total = 1
    for vc in vote_ciphertexts:
        c_total = paillier_hom_add(c_total, vc, pub)

    print(f"votes sum (plaintext) = {m_vote_total}")
    try:
        threshold_decrypt_paillier(c_total, pub, tshares[:2], threshold=3, prime=SHAMIR_PRIME_127)
        print("unexpected: decrypted with only 2 shares")
    except ValueError as e:
        print(f"as expected: cannot decrypt with 2 shares ({e})")
    m_total_dec = threshold_decrypt_paillier(c_total, pub, tshares[:3], threshold=3, prime=SHAMIR_PRIME_127)
    print(f"votes sum (threshold decrypted) = {m_total_dec}")


if __name__ == "__main__":
    main()
