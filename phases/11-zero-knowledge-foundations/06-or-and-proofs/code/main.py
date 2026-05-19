"""
OR/AND proofs for Schnorr (discrete-log) sigma protocols.

This script demonstrates:
- A Schnorr non-interactive proof of knowledge (Fiat–Shamir).
- An AND-composition proof (prove both statements with one challenge).
- An OR-composition proof (prove one of two statements without revealing which).

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass
from typing import Iterable, Union


Label = Union[str, bytes]


def inv_mod(a: int, m: int) -> int:
    a %= m
    if a == 0:
        raise ValueError("0 has no inverse modulo m")

    t0, t1 = 0, 1
    r0, r1 = m, a
    while r1 != 0:
        q = r0 // r1
        t0, t1 = t1, t0 - q * t1
        r0, r1 = r1, r0 - q * r1

    if r0 != 1:
        raise ValueError("a is not invertible modulo m")
    return t0 % m


def _int_to_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def _as_bytes(label: Label) -> bytes:
    if isinstance(label, bytes):
        return label
    if isinstance(label, str):
        return label.encode("utf-8")
    raise TypeError(f"unsupported label type: {type(label)!r}")


def hash_to_scalar(q: int, items: Iterable[object]) -> int:
    h = hashlib.sha256()
    for item in items:
        if isinstance(item, int):
            b = _int_to_bytes(item)
            h.update(b"I")
            h.update(len(b).to_bytes(4, "big"))
            h.update(b)
        elif isinstance(item, bytes):
            h.update(b"B")
            h.update(len(item).to_bytes(4, "big"))
            h.update(item)
        elif isinstance(item, str):
            b = item.encode("utf-8")
            h.update(b"S")
            h.update(len(b).to_bytes(4, "big"))
            h.update(b)
        else:
            raise TypeError(f"unsupported item type: {type(item)!r}")
    return int.from_bytes(h.digest(), "big") % q


def toy_group() -> tuple[int, int, int]:
    p = 467
    q = 233
    g = 3
    if pow(g, q, p) != 1 or g % p in (0, 1):
        raise ValueError("bad toy group parameters")
    return p, q, g


@dataclass(frozen=True)
class SchnorrProof:
    t: int
    c: int
    s: int


def schnorr_prove_nizk(*, p: int, q: int, g: int, y: int, x: int, label: Label, rng: random.Random) -> SchnorrProof:
    r = rng.randrange(0, q)
    t = pow(g, r, p)
    c = hash_to_scalar(q, [_as_bytes(label), p, q, g, y, t])
    s = (r + c * x) % q
    return SchnorrProof(t=t, c=c, s=s)


def schnorr_verify_nizk(*, p: int, q: int, g: int, y: int, proof: SchnorrProof, label: Label) -> bool:
    c_expected = hash_to_scalar(q, [_as_bytes(label), p, q, g, y, proof.t])
    if proof.c != c_expected:
        return False
    left = pow(g, proof.s, p)
    right = (proof.t * pow(y, proof.c, p)) % p
    return left == right


@dataclass(frozen=True)
class AndProof:
    t1: int
    t2: int
    c: int
    s1: int
    s2: int


def and_prove_nizk(
    *,
    p: int,
    q: int,
    g: int,
    y1: int,
    x1: int,
    y2: int,
    x2: int,
    label: Label,
    rng: random.Random,
) -> AndProof:
    r1 = rng.randrange(0, q)
    r2 = rng.randrange(0, q)
    t1 = pow(g, r1, p)
    t2 = pow(g, r2, p)
    c = hash_to_scalar(q, [_as_bytes(label), p, q, g, y1, y2, t1, t2])
    s1 = (r1 + c * x1) % q
    s2 = (r2 + c * x2) % q
    return AndProof(t1=t1, t2=t2, c=c, s1=s1, s2=s2)


def and_verify_nizk(*, p: int, q: int, g: int, y1: int, y2: int, proof: AndProof, label: Label) -> bool:
    c_expected = hash_to_scalar(q, [_as_bytes(label), p, q, g, y1, y2, proof.t1, proof.t2])
    if proof.c != c_expected:
        return False
    left1 = pow(g, proof.s1, p)
    right1 = (proof.t1 * pow(y1, proof.c, p)) % p
    left2 = pow(g, proof.s2, p)
    right2 = (proof.t2 * pow(y2, proof.c, p)) % p
    return left1 == right1 and left2 == right2


def schnorr_simulate_commitment(*, p: int, g: int, y: int, c: int, s: int) -> int:
    y_inv = inv_mod(y, p)
    return (pow(g, s, p) * pow(y_inv, c, p)) % p


@dataclass(frozen=True)
class OrProof:
    t1: int
    t2: int
    c1: int
    c2: int
    s1: int
    s2: int


def or_prove_nizk(
    *,
    p: int,
    q: int,
    g: int,
    y1: int,
    y2: int,
    x1: int | None,
    x2: int | None,
    label: Label,
    rng: random.Random,
) -> OrProof:
    if (x1 is None) == (x2 is None):
        raise ValueError("provide exactly one witness (x1 or x2)")

    if x1 is not None:
        c2 = rng.randrange(0, q)
        s2 = rng.randrange(0, q)
        t2 = schnorr_simulate_commitment(p=p, g=g, y=y2, c=c2, s=s2)
        r1 = rng.randrange(0, q)
        t1 = pow(g, r1, p)
        c = hash_to_scalar(q, [_as_bytes(label), p, q, g, y1, y2, t1, t2])
        c1 = (c - c2) % q
        s1 = (r1 + c1 * x1) % q
        return OrProof(t1=t1, t2=t2, c1=c1, c2=c2, s1=s1, s2=s2)

    c1 = rng.randrange(0, q)
    s1 = rng.randrange(0, q)
    t1 = schnorr_simulate_commitment(p=p, g=g, y=y1, c=c1, s=s1)
    r2 = rng.randrange(0, q)
    t2 = pow(g, r2, p)
    c = hash_to_scalar(q, [_as_bytes(label), p, q, g, y1, y2, t1, t2])
    c2 = (c - c1) % q
    s2 = (r2 + c2 * x2) % q
    return OrProof(t1=t1, t2=t2, c1=c1, c2=c2, s1=s1, s2=s2)


def or_verify_nizk(*, p: int, q: int, g: int, y1: int, y2: int, proof: OrProof, label: Label) -> bool:
    c = hash_to_scalar(q, [_as_bytes(label), p, q, g, y1, y2, proof.t1, proof.t2])
    if (proof.c1 + proof.c2) % q != c:
        return False
    left1 = pow(g, proof.s1, p)
    right1 = (proof.t1 * pow(y1, proof.c1, p)) % p
    left2 = pow(g, proof.s2, p)
    right2 = (proof.t2 * pow(y2, proof.c2, p)) % p
    return left1 == right1 and left2 == right2


def _proof_to_dict(obj: object) -> dict[str, int]:
    if hasattr(obj, "__dict__"):
        return {k: int(v) for k, v in obj.__dict__.items()}
    raise TypeError("unsupported proof object")


def main() -> None:
    p, q, g = toy_group()

    x1 = 42
    x2 = 99
    y1 = pow(g, x1, p)
    y2 = pow(g, x2, p)

    print("=== Step 1: Hash-to-scalar challenges ===")
    demo_c = hash_to_scalar(q, [b"demo", p, q, g, y1])
    print(f"p={p} q={q} g={g}")
    print(f"y1=g^x1 mod p = {y1}")
    print(f"H(... ) mod q = {demo_c}")

    print("\n=== Step 2: Schnorr NIZK (Fiat–Shamir) ===")
    rng = random.Random(0)
    schnorr = schnorr_prove_nizk(p=p, q=q, g=g, y=y1, x=x1, label="schnorr", rng=rng)
    print("proof:", _proof_to_dict(schnorr))
    print("verify:", schnorr_verify_nizk(p=p, q=q, g=g, y=y1, proof=schnorr, label="schnorr"))

    print("\n=== Step 3: AND proof (know x1 AND x2) ===")
    rng = random.Random(0)
    and_proof = and_prove_nizk(p=p, q=q, g=g, y1=y1, x1=x1, y2=y2, x2=x2, label="or-demo", rng=rng)
    print("proof:", _proof_to_dict(and_proof))
    print("verify:", and_verify_nizk(p=p, q=q, g=g, y1=y1, y2=y2, proof=and_proof, label="or-demo"))

    print("\n=== Step 4: OR proof (know x1 OR x2, without revealing which) ===")
    rng = random.Random(0)
    or_know_x1 = or_prove_nizk(p=p, q=q, g=g, y1=y1, y2=y2, x1=x1, x2=None, label="or-demo", rng=rng)
    print("prove with x1:", _proof_to_dict(or_know_x1))
    print("verify:", or_verify_nizk(p=p, q=q, g=g, y1=y1, y2=y2, proof=or_know_x1, label="or-demo"))

    rng = random.Random(0)
    or_know_x2 = or_prove_nizk(p=p, q=q, g=g, y1=y1, y2=y2, x1=None, x2=x2, label="or-demo", rng=rng)
    print("prove with x2:", _proof_to_dict(or_know_x2))
    print("verify:", or_verify_nizk(p=p, q=q, g=g, y1=y1, y2=y2, proof=or_know_x2, label="or-demo"))


if __name__ == "__main__":
    main()
