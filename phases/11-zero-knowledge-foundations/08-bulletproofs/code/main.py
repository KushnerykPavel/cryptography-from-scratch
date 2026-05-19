"""Bulletproofs core from scratch: a toy Inner Product Argument (IPA).

Run:
  python3 code/main.py

This lesson implements the logarithmic-size inner product proof that powers
Bulletproofs range proofs. We use a *toy* prime-order additive group:

  - Scalars are in Z_q (a prime field).
  - "Group elements" are also integers mod q (so scalar-mul is just multiply).

This keeps the code stdlib-only and focuses on the protocol structure:
halving + Fiat–Shamir challenges => O(log n) group elements in the proof.

Educational implementation. Not constant-time. Not production-safe.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Iterable, TypeVar


DEFAULT_Q = 2**255 - 19


def is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def mod_q(x: int, q: int) -> int:
    return x % q


def inv_q(x: int, q: int) -> int:
    x = x % q
    if x == 0:
        raise ValueError("0 has no inverse in Z_q")
    return pow(x, q - 2, q)


def inner_product(q: int, a: list[int], b: list[int]) -> int:
    if len(a) != len(b):
        raise ValueError("inner product requires equal-length vectors")
    return sum((ai % q) * (bi % q) for ai, bi in zip(a, b, strict=True)) % q


def msm(q: int, scalars: Iterable[int], points: Iterable[int]) -> int:
    acc = 0
    for s, P in zip(scalars, points, strict=True):
        acc = (acc + (s % q) * (P % q)) % q
    return acc


def _i2osp(x: int) -> bytes:
    if x < 0:
        raise ValueError("cannot encode negative integers")
    return x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")


class Transcript:
    def __init__(self) -> None:
        self._state = bytearray()

    def append_message(self, label: bytes, message: bytes) -> None:
        self._state.extend(len(label).to_bytes(4, "big"))
        self._state.extend(label)
        self._state.extend(len(message).to_bytes(8, "big"))
        self._state.extend(message)

    def append_int(self, label: bytes, x: int) -> None:
        self.append_message(label, _i2osp(x))

    def innerproduct_domain_sep(self, n: int) -> None:
        self.append_message(b"dom-sep", b"ipp-toy v1")
        self.append_int(b"n", n)

    def challenge_scalar(self, label: bytes, q: int) -> int:
        h = sha256()
        h.update(bytes(self._state))
        h.update(b"\x00")
        h.update(label)
        digest = h.digest()
        x = int.from_bytes(digest, "big") % q
        if x == 0:
            x = 1
        self.append_int(label, x)
        return x


def derive_generators(n: int, q: int, seed: bytes) -> list[int]:
    if n <= 0:
        raise ValueError("n must be positive")
    out: list[int] = []
    for i in range(n):
        h = sha256()
        h.update(seed)
        h.update(b"\x00")
        h.update(i.to_bytes(4, "big"))
        x = int.from_bytes(h.digest(), "big") % q
        if x == 0:
            x = 1
        out.append(x)
    return out


def assert_ipa_params(q: int, G: list[int], H: list[int], Q: int) -> None:
    if q <= 2:
        raise ValueError("q must be a prime > 2 (not validated here)")
    if len(G) != len(H):
        raise ValueError("G and H must have the same length")
    if not is_power_of_two(len(G)):
        raise ValueError("vector length must be a power of two")
    if any((g % q) == 0 for g in G):
        raise ValueError("G contains identity point (0)")
    if any((h % q) == 0 for h in H):
        raise ValueError("H contains identity point (0)")
    if (Q % q) == 0:
        raise ValueError("Q must be non-identity")


def ipa_commit(q: int, G: list[int], H: list[int], Q: int, a: list[int], b: list[int]) -> int:
    if len(a) != len(G) or len(b) != len(H):
        raise ValueError("vector length mismatch")
    c = inner_product(q, a, b)
    return (msm(q, a, G) + msm(q, b, H) + c * (Q % q)) % q


@dataclass(frozen=True)
class InnerProductProof:
    """Bulletproofs-style inner product proof: (L_k, R_k, ..., L_1, R_1, a, b)."""

    Ls: list[int]
    Rs: list[int]
    a: int
    b: int


T = TypeVar("T")


def _split_half(v: list[T]) -> tuple[list[T], list[T]]:
    mid = len(v) // 2
    return (v[:mid], v[mid:])


def ipa_prove(q: int, G: list[int], H: list[int], Q: int, a: list[int], b: list[int]) -> tuple[int, InnerProductProof]:
    """Produce a non-interactive inner product proof (toy Fiat–Shamir).

    Returns (P_prime, proof) where:
      P_prime = <a,G> + <b,H> + <a,b>*Q
    """
    assert_ipa_params(q, G, H, Q)
    if len(a) != len(G) or len(b) != len(H):
        raise ValueError("vector length mismatch")

    n = len(a)
    transcript = Transcript()
    transcript.innerproduct_domain_sep(n)

    P_prime = ipa_commit(q, G, H, Q, a, b)
    transcript.append_int(b"P", P_prime)
    transcript.append_int(b"Q", Q % q)

    G_round = [g % q for g in G]
    H_round = [h % q for h in H]
    a_round = [x % q for x in a]
    b_round = [x % q for x in b]

    Ls: list[int] = []
    Rs: list[int] = []

    while len(a_round) > 1:
        a_lo, a_hi = _split_half(a_round)
        b_lo, b_hi = _split_half(b_round)
        G_lo, G_hi = _split_half(G_round)
        H_lo, H_hi = _split_half(H_round)

        c_L = inner_product(q, a_lo, b_hi)
        c_R = inner_product(q, a_hi, b_lo)

        L = (msm(q, a_lo, G_hi) + msm(q, b_hi, H_lo) + c_L * (Q % q)) % q
        R = (msm(q, a_hi, G_lo) + msm(q, b_lo, H_hi) + c_R * (Q % q)) % q

        Ls.append(L)
        Rs.append(R)

        transcript.append_int(b"L", L)
        transcript.append_int(b"R", R)
        u = transcript.challenge_scalar(b"u", q)
        u_inv = inv_q(u, q)

        a_round = [(alo * u + ahi * u_inv) % q for alo, ahi in zip(a_lo, a_hi, strict=True)]
        b_round = [(blo * u_inv + bhi * u) % q for blo, bhi in zip(b_lo, b_hi, strict=True)]
        G_round = [(glo * u_inv + ghi * u) % q for glo, ghi in zip(G_lo, G_hi, strict=True)]
        H_round = [(hlo * u + hhi * u_inv) % q for hlo, hhi in zip(H_lo, H_hi, strict=True)]

    proof = InnerProductProof(Ls=Ls, Rs=Rs, a=a_round[0], b=b_round[0])
    return (P_prime, proof)


def _u_challenges(q: int, n: int, P_prime: int, Q: int, proof: InnerProductProof) -> list[int]:
    transcript = Transcript()
    transcript.innerproduct_domain_sep(n)
    transcript.append_int(b"P", P_prime)
    transcript.append_int(b"Q", Q % q)

    us: list[int] = []
    for L, R in zip(proof.Ls, proof.Rs, strict=True):
        transcript.append_int(b"L", L % q)
        transcript.append_int(b"R", R % q)
        us.append(transcript.challenge_scalar(b"u", q))
    return us


def _s_vector(q: int, us: list[int]) -> list[int]:
    k = len(us)
    n = 1 << k
    inv_us = [inv_q(u, q) for u in us]

    s: list[int] = []
    for i in range(n):
        si = 1
        for idx in range(k):
            bit_index = k - 1 - idx
            if ((i >> bit_index) & 1) == 1:
                si = (si * us[idx]) % q
            else:
                si = (si * inv_us[idx]) % q
        s.append(si)
    return s


def ipa_verify(q: int, G: list[int], H: list[int], Q: int, P_prime: int, proof: InnerProductProof) -> bool:
    try:
        assert_ipa_params(q, G, H, Q)
    except ValueError:
        return False
    n = len(G)
    if len(proof.Ls) != len(proof.Rs):
        return False
    if n != (1 << len(proof.Ls)):
        return False

    try:
        us = _u_challenges(q, n, P_prime, Q, proof)
    except ValueError:
        return False

    u2 = [(u * u) % q for u in us]
    uinv2 = [inv_q(x, q) for x in u2]

    s = _s_vector(q, us)
    inv_s = [inv_q(x, q) for x in s]

    a = proof.a % q
    b = proof.b % q

    rhs = (msm(q, [(a * si) % q for si in s], G) + msm(q, [(b * isi) % q for isi in inv_s], H)) % q
    rhs = (rhs + (a * b) % q * (Q % q)) % q

    for L, R, uu2, uui2 in zip(proof.Ls, proof.Rs, u2, uinv2, strict=True):
        rhs = (rhs - (L % q) * uu2) % q
        rhs = (rhs - (R % q) * uui2) % q

    return (P_prime % q) == rhs


def main() -> None:
    q = DEFAULT_Q
    n = 8

    G = derive_generators(n, q, b"G")
    H = derive_generators(n, q, b"H")
    Q = derive_generators(1, q, b"Q")[0]

    a = [1, 2, 3, 4, 5, 6, 7, 8]
    b = [8, 7, 6, 5, 4, 3, 2, 1]

    print("=== Step 1: Vector commitments and inner products ===")
    c = inner_product(q, a, b)
    P_prime = ipa_commit(q, G, H, Q, a, b)
    print(f"n={n}, q≈2^255, <a,b>={c}")
    print(f"P' = <a,G> + <b,H> + <a,b>*Q  ->  {P_prime}")

    print("\n=== Step 2: Proof size intuition (naive vs logarithmic) ===")
    naive_scalars = 2 * n
    k = n.bit_length() - 1
    ipa_group_elements = 2 * k
    ipa_scalars = 2
    print(f"Naive opening sends {naive_scalars} scalars (a and b).")
    print(f"IPA sends {ipa_group_elements} group elements (L/R) + {ipa_scalars} scalars (a,b).")

    print("\n=== Step 3: Prove (Fiat–Shamir) ===")
    P_prime2, proof = ipa_prove(q, G, H, Q, a, b)
    assert P_prime2 == P_prime
    print(f"proof rounds k={len(proof.Ls)}")
    print(f"L[0]={proof.Ls[0]}")
    print(f"R[0]={proof.Rs[0]}")
    print(f"final a={proof.a}")
    print(f"final b={proof.b}")

    print("\n=== Step 4: Verify and show tampering fails ===")
    ok = ipa_verify(q, G, H, Q, P_prime, proof)
    print(f"verify(proof) -> {ok}")
    bad = InnerProductProof(Ls=proof.Ls[:], Rs=proof.Rs[:], a=(proof.a + 1) % q, b=proof.b)
    ok_bad = ipa_verify(q, G, H, Q, P_prime, bad)
    print(f"verify(tampered a) -> {ok_bad}")
    if not ok or ok_bad:
        raise RuntimeError("unexpected verification result")


if __name__ == "__main__":
    main()
