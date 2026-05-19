"""
Toy BLS signatures + aggregation (stdlib-only).

This lesson implements the *protocol logic* of BLS signatures (sign/verify, aggregation,
and proof-of-possession) using a tiny pedagogical model of a bilinear pairing.

It is intentionally not cryptographically realistic:
- It is not constant-time.
- It does not implement real elliptic curves or pairings (see the Use It section in docs).

Run:
  python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Iterable, Sequence

TOY_Q = 2**127 - 1

DST_KEYGEN = b"BLS_TOY_KEYGEN_V1"
DST_H2G1 = b"BLS_TOY_H2G1_V1"
DST_POP_H2G1 = b"BLS_TOY_POP_H2G1_V1"


def _mod_q(x: int) -> int:
    return x % TOY_Q


def hash_to_scalar(msg: bytes, dst: bytes) -> int:
    x = int.from_bytes(hashlib.sha256(dst + b"|" + msg).digest(), "big") % TOY_Q
    return x if x != 0 else 1


@dataclass(frozen=True)
class G1:
    exp: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "exp", _mod_q(self.exp))

    def __add__(self, other: "G1") -> "G1":
        return G1(self.exp + other.exp)

    def __rmul__(self, k: int) -> "G1":
        return G1(self.exp * _mod_q(k))


@dataclass(frozen=True)
class G2:
    exp: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "exp", _mod_q(self.exp))

    def __add__(self, other: "G2") -> "G2":
        return G2(self.exp + other.exp)

    def __rmul__(self, k: int) -> "G2":
        return G2(self.exp * _mod_q(k))


@dataclass(frozen=True)
class GT:
    exp: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "exp", _mod_q(self.exp))

    def __mul__(self, other: "GT") -> "GT":
        return GT(self.exp + other.exp)

    def __pow__(self, k: int) -> "GT":
        return GT(self.exp * _mod_q(k))


G1_GEN = G1(1)
G2_GEN = G2(1)
GT_GEN = GT(1)


def pairing(p: G1, q: G2) -> GT:
    return GT(p.exp * q.exp)


def keygen(seed: bytes) -> int:
    return hash_to_scalar(seed, DST_KEYGEN)


def sk_to_pk(sk: int) -> G2:
    sk = _mod_q(sk)
    if sk == 0:
        raise ValueError("secret key must be nonzero mod q")
    return sk * G2_GEN


def hash_to_g1(message: bytes) -> G1:
    return hash_to_scalar(message, DST_H2G1) * G1_GEN


def bls_sign(sk: int, message: bytes) -> G1:
    sk = _mod_q(sk)
    if sk == 0:
        raise ValueError("secret key must be nonzero mod q")
    return sk * hash_to_g1(message)


def bls_verify(pk: G2, message: bytes, signature: G1) -> bool:
    left = pairing(signature, G2_GEN)
    right = pairing(hash_to_g1(message), pk)
    return left == right


def aggregate_signatures(signatures: Sequence[G1]) -> G1:
    if not signatures:
        raise ValueError("need at least one signature")
    agg = G1(0)
    for s in signatures:
        agg = agg + s
    return agg


def aggregate_verify(pks: Sequence[G2], messages: Sequence[bytes], signature: G1) -> bool:
    if len(pks) != len(messages):
        raise ValueError("pks and messages must have the same length")
    if not pks:
        raise ValueError("need at least one (pk, message)")
    if len(set(messages)) != len(messages):
        return False

    left = pairing(signature, G2_GEN)
    right = GT(0)
    for pk, msg in zip(pks, messages, strict=True):
        right = right * pairing(hash_to_g1(msg), pk)
    return left == right


def pop_prove(sk: int) -> G1:
    pk = sk_to_pk(sk)
    pk_bytes = pk.exp.to_bytes(32, "big")
    return sk * (hash_to_scalar(pk_bytes, DST_POP_H2G1) * G1_GEN)


def pop_verify(pk: G2, proof: G1) -> bool:
    pk_bytes = pk.exp.to_bytes(32, "big")
    h = hash_to_scalar(pk_bytes, DST_POP_H2G1) * G1_GEN
    return pairing(proof, G2_GEN) == pairing(h, pk)


def fast_aggregate_verify_same_message(pks: Sequence[G2], message: bytes, signature: G1) -> bool:
    if not pks:
        raise ValueError("need at least one public key")
    pk_agg = G2(0)
    for pk in pks:
        pk_agg = pk_agg + pk
    return pairing(signature, G2_GEN) == pairing(hash_to_g1(message), pk_agg)


def fast_aggregate_verify_same_message_with_pops(
    pks: Sequence[G2], pops: Sequence[G1], message: bytes, signature: G1
) -> bool:
    if len(pks) != len(pops):
        raise ValueError("pks and pops must have the same length")
    if not pks:
        raise ValueError("need at least one public key")
    for pk, pop in zip(pks, pops, strict=True):
        if not pop_verify(pk, pop):
            return False
    return fast_aggregate_verify_same_message(pks, message, signature)


def _fmt_exp(x: int) -> str:
    return hex(_mod_q(x))[2:].rjust(32, "0")


def main():
    print("=== Step 1: A toy bilinear pairing ===")
    a = keygen(b"Alice")
    b = keygen(b"Bob")
    p = a * G1_GEN
    q = b * G2_GEN
    e_pq = pairing(p, q)
    e_gen = pairing(G1_GEN, G2_GEN)
    print(f"a={_fmt_exp(a)}")
    print(f"b={_fmt_exp(b)}")
    print(f"e(a·G1, b·G2)={_fmt_exp(e_pq.exp)}")
    print(f"e(G1, G2)^(a·b)={_fmt_exp((e_gen ** (a * b)).exp)}")
    print()

    print("=== Step 2: Core BLS sign/verify ===")
    sk = keygen(b"signer-1")
    pk = sk_to_pk(sk)
    msg = b"hello bls"
    sig = bls_sign(sk, msg)
    print(f"sk={_fmt_exp(sk)}")
    print(f"pk.exp={_fmt_exp(pk.exp)}")
    print(f"H(msg).exp={_fmt_exp(hash_to_g1(msg).exp)}")
    print(f"sig.exp={_fmt_exp(sig.exp)}")
    print(f"verify(pk, msg, sig)={bls_verify(pk, msg, sig)}")
    print(f"verify(pk, msg||0, sig)={bls_verify(pk, msg + b'\\x00', sig)}")
    print()

    print("=== Step 3: Aggregate signatures (distinct messages) ===")
    seeds = [b"v1", b"v2", b"v3"]
    msgs = [b"m1", b"m2", b"m3"]
    sks = [keygen(s) for s in seeds]
    pks = [sk_to_pk(sk_i) for sk_i in sks]
    sigs = [bls_sign(sk_i, m_i) for sk_i, m_i in zip(sks, msgs, strict=True)]
    agg_sig = aggregate_signatures(sigs)
    print(f"agg_sig.exp={_fmt_exp(agg_sig.exp)}")
    print(f"aggregate_verify(distinct msgs)={aggregate_verify(pks, msgs, agg_sig)}")
    print(f"aggregate_verify(duplicate msgs)={aggregate_verify([pks[0], pks[1]], [b'x', b'x'], aggregate_signatures([sigs[0], sigs[1]]))}")
    print()

    print("=== Step 4: Fast aggregation + proof of possession ===")
    common_msg = b"same message"
    sks2 = [keygen(b"a"), keygen(b"b"), keygen(b"c")]
    pks2 = [sk_to_pk(sk_i) for sk_i in sks2]
    sigs2 = [bls_sign(sk_i, common_msg) for sk_i in sks2]
    agg_sig2 = aggregate_signatures(sigs2)
    pops2 = [pop_prove(sk_i) for sk_i in sks2]
    print(f"fast_aggregate_verify_same_message={fast_aggregate_verify_same_message(pks2, common_msg, agg_sig2)}")
    print(
        "fast_aggregate_verify_same_message_with_pops="
        f"{fast_aggregate_verify_same_message_with_pops(pks2, pops2, common_msg, agg_sig2)}"
    )


if __name__ == "__main__":
    main()
