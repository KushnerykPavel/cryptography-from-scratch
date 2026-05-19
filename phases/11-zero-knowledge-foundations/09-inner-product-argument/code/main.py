"""
Inner Product Argument (IPA) from scratch (educational).

This file implements a small, runnable version of the Bulletproofs-style inner
product argument over a toy additive group Z_p.

Run:
  python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Iterable, Sequence


P: int = 2_147_483_647  # 2^31 - 1 (prime)


def is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def modinv(x: int, p: int = P) -> int:
    x %= p
    if x == 0:
        raise ValueError("inverse of 0 does not exist")
    return pow(x, p - 2, p)


def inner_product(a: Sequence[int], b: Sequence[int], p: int = P) -> int:
    if len(a) != len(b):
        raise ValueError("inner_product: length mismatch")
    acc = 0
    for ai, bi in zip(a, b):
        acc = (acc + (ai % p) * (bi % p)) % p
    return acc


def msm(scalars: Sequence[int], bases: Sequence[int], p: int = P) -> int:
    if len(scalars) != len(bases):
        raise ValueError("msm: length mismatch")
    acc = 0
    for s, g in zip(scalars, bases):
        acc = (acc + (s % p) * (g % p)) % p
    return acc


def commit_pprime(
    a: Sequence[int],
    b: Sequence[int],
    G: Sequence[int],
    H: Sequence[int],
    Q: int,
    p: int = P,
) -> int:
    if not (len(a) == len(b) == len(G) == len(H)):
        raise ValueError("commit_pprime: length mismatch")
    c = inner_product(a, b, p)
    return (msm(a, G, p) + msm(b, H, p) + (c * (Q % p)) % p) % p


def fold_scalars(lo: Sequence[int], hi: Sequence[int], u: int, u_inv: int, p: int = P) -> list[int]:
    if len(lo) != len(hi):
        raise ValueError("fold_scalars: length mismatch")
    return [((x % p) * u + (y % p) * u_inv) % p for x, y in zip(lo, hi)]


def fold_generators_G(
    lo: Sequence[int], hi: Sequence[int], u: int, u_inv: int, p: int = P
) -> list[int]:
    if len(lo) != len(hi):
        raise ValueError("fold_generators_G: length mismatch")
    return [((g0 % p) * u_inv + (g1 % p) * u) % p for g0, g1 in zip(lo, hi)]


def fold_generators_H(
    lo: Sequence[int], hi: Sequence[int], u: int, u_inv: int, p: int = P
) -> list[int]:
    if len(lo) != len(hi):
        raise ValueError("fold_generators_H: length mismatch")
    return [((h0 % p) * u + (h1 % p) * u_inv) % p for h0, h1 in zip(lo, hi)]


def _i2b(x: int) -> bytes:
    return int(x).to_bytes(32, "big", signed=False)


def hash_to_nonzero_scalar(msg: bytes, p: int = P) -> int:
    counter = 0
    while True:
        digest = hashlib.sha256(msg + counter.to_bytes(1, "big")).digest()
        x = int.from_bytes(digest, "big") % p
        if x != 0:
            return x
        counter = (counter + 1) % 256


class Transcript:
    def __init__(self, label: bytes):
        self._state = hashlib.sha256(b"transcript:" + label).digest()

    def append_bytes(self, label: str, data: bytes) -> None:
        h = hashlib.sha256()
        h.update(self._state)
        h.update(b"append:")
        h.update(label.encode("utf-8"))
        h.update(len(data).to_bytes(4, "big"))
        h.update(data)
        self._state = h.digest()

    def append_int(self, label: str, x: int) -> None:
        self.append_bytes(label, _i2b(x))

    def append_vector(self, label: str, xs: Sequence[int]) -> None:
        self.append_bytes(label + ".len", len(xs).to_bytes(4, "big"))
        for i, x in enumerate(xs):
            self.append_int(f"{label}[{i}]", x)

    def challenge_scalar(self, label: str, p: int = P) -> int:
        return hash_to_nonzero_scalar(self._state + b"challenge:" + label.encode("utf-8"), p)


@dataclass(frozen=True)
class InnerProductProof:
    Ls: list[int]
    Rs: list[int]
    a: int
    b: int


def _absorb_statement(transcript: Transcript, P_prime: int, G: Sequence[int], H: Sequence[int], Q: int) -> None:
    transcript.append_int("P'", P_prime)
    transcript.append_int("Q", Q)
    transcript.append_vector("G", G)
    transcript.append_vector("H", H)


def ipa_prove(
    a: Sequence[int],
    b: Sequence[int],
    G: Sequence[int],
    H: Sequence[int],
    Q: int,
    p: int = P,
    *,
    transcript_label: bytes = b"ipa-v1",
) -> tuple[int, InnerProductProof]:
    if not (len(a) == len(b) == len(G) == len(H)):
        raise ValueError("ipa_prove: length mismatch")
    if not is_power_of_two(len(a)):
        raise ValueError("ipa_prove: vector length must be a power of two")
    if Q % p == 0:
        raise ValueError("ipa_prove: Q must be nonzero")

    a_cur = [x % p for x in a]
    b_cur = [x % p for x in b]
    G_cur = [x % p for x in G]
    H_cur = [x % p for x in H]

    P_prime = commit_pprime(a_cur, b_cur, G_cur, H_cur, Q, p)

    transcript = Transcript(transcript_label)
    _absorb_statement(transcript, P_prime, G_cur, H_cur, Q)

    Ls: list[int] = []
    Rs: list[int] = []

    while len(a_cur) > 1:
        n = len(a_cur)
        n2 = n // 2
        a_lo, a_hi = a_cur[:n2], a_cur[n2:]
        b_lo, b_hi = b_cur[:n2], b_cur[n2:]
        G_lo, G_hi = G_cur[:n2], G_cur[n2:]
        H_lo, H_hi = H_cur[:n2], H_cur[n2:]

        L = (msm(a_lo, G_hi, p) + msm(b_hi, H_lo, p) + inner_product(a_lo, b_hi, p) * (Q % p)) % p
        R = (msm(a_hi, G_lo, p) + msm(b_lo, H_hi, p) + inner_product(a_hi, b_lo, p) * (Q % p)) % p

        Ls.append(L)
        Rs.append(R)

        transcript.append_int("L", L)
        transcript.append_int("R", R)
        u = transcript.challenge_scalar("u", p)
        u_inv = modinv(u, p)

        a_cur = fold_scalars(a_lo, a_hi, u, u_inv, p)
        b_cur = fold_scalars(b_lo, b_hi, u_inv, u, p)
        G_cur = fold_generators_G(G_lo, G_hi, u, u_inv, p)
        H_cur = fold_generators_H(H_lo, H_hi, u, u_inv, p)

    proof = InnerProductProof(Ls=Ls, Rs=Rs, a=a_cur[0], b=b_cur[0])
    return P_prime, proof


def ipa_verify(
    P_prime: int,
    G: Sequence[int],
    H: Sequence[int],
    Q: int,
    proof: InnerProductProof,
    p: int = P,
    *,
    transcript_label: bytes = b"ipa-v1",
) -> bool:
    if not (len(G) == len(H)):
        raise ValueError("ipa_verify: length mismatch")
    if not is_power_of_two(len(G)):
        raise ValueError("ipa_verify: vector length must be a power of two")
    if len(proof.Ls) != len(proof.Rs):
        raise ValueError("ipa_verify: malformed proof")
    if len(proof.Ls) != (len(G).bit_length() - 1):
        raise ValueError("ipa_verify: wrong proof length for vector size")
    if Q % p == 0:
        raise ValueError("ipa_verify: Q must be nonzero")

    P_cur = P_prime % p
    G_cur = [x % p for x in G]
    H_cur = [x % p for x in H]

    transcript = Transcript(transcript_label)
    _absorb_statement(transcript, P_prime % p, G_cur, H_cur, Q % p)

    for L, R in zip(proof.Ls, proof.Rs):
        transcript.append_int("L", L)
        transcript.append_int("R", R)
        u = transcript.challenge_scalar("u", p)
        u_inv = modinv(u, p)

        u2 = (u * u) % p
        u_inv2 = (u_inv * u_inv) % p

        P_cur = (P_cur + (L % p) * u2 + (R % p) * u_inv2) % p

        n2 = len(G_cur) // 2
        G_cur = fold_generators_G(G_cur[:n2], G_cur[n2:], u, u_inv, p)
        H_cur = fold_generators_H(H_cur[:n2], H_cur[n2:], u, u_inv, p)

    if len(G_cur) != 1 or len(H_cur) != 1:
        return False

    expected = ((proof.a % p) * G_cur[0] + (proof.b % p) * H_cur[0] + ((proof.a % p) * (proof.b % p)) * (Q % p)) % p
    return P_cur == expected


def derive_generators(seed: bytes, n: int, p: int = P) -> list[int]:
    if n <= 0:
        raise ValueError("derive_generators: n must be positive")
    out: list[int] = []
    for i in range(n):
        out.append(hash_to_nonzero_scalar(seed + i.to_bytes(4, "big"), p))
    return out


def demo_instance(p: int = P) -> tuple[list[int], list[int], list[int], list[int], int]:
    a = [3, 1, 4, 1, 5, 9, 2, 6]
    b = [2, 7, 1, 8, 2, 8, 1, 8]
    n = len(a)
    G = derive_generators(b"G", n, p)
    H = derive_generators(b"H", n, p)
    Q = hash_to_nonzero_scalar(b"Q", p)
    return a, b, G, H, Q


def _print_vec(label: str, xs: Sequence[int], max_len: int = 8) -> None:
    shown = list(xs[:max_len])
    suffix = "" if len(xs) <= max_len else f" ... (+{len(xs) - max_len} more)"
    print(f"{label} = {shown}{suffix}")


def main() -> None:
    a, b, G, H, Q = demo_instance(P)

    print("=== Step 1: Field + vector helpers ===")
    print(f"p = {P}")
    print(f"modinv(17) mod p = {modinv(17, P)}")
    print(f"<a,b> mod p = {inner_product(a, b, P)}")

    print("\n=== Step 2: Commit to (a,b) and <a,b> ===")
    _print_vec("a", a)
    _print_vec("b", b)
    print(f"Q = {Q}")
    P_prime, proof = ipa_prove(a, b, G, H, Q, P)
    print(f"P' = {P_prime}")

    print("\n=== Step 3: Fiat-Shamir challenges (transcript) ===")
    tr = Transcript(b"ipa-v1")
    _absorb_statement(tr, P_prime, G, H, Q)
    print(f"u0 = {tr.challenge_scalar('u', P)}  (first challenge if L,R were empty)")

    print("\n=== Step 4: Prove (log n transcript) ===")
    print(f"rounds = {len(proof.Ls)}  (n = {len(a)})")
    _print_vec("L", proof.Ls, max_len=4)
    _print_vec("R", proof.Rs, max_len=4)
    print(f"final a = {proof.a}")
    print(f"final b = {proof.b}")

    print("\n=== Step 5: Verify + tamper test ===")
    ok = ipa_verify(P_prime, G, H, Q, proof, P)
    print(f"verify(proof) = {ok}")
    tampered = InnerProductProof(Ls=[(proof.Ls[0] + 1) % P] + proof.Ls[1:], Rs=proof.Rs, a=proof.a, b=proof.b)
    ok2 = ipa_verify(P_prime, G, H, Q, tampered, P)
    print(f"verify(tampered) = {ok2}")


if __name__ == "__main__":
    main()
