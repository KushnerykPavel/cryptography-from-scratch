"""
Range proofs via bit-decomposition and OR-proofs (toy implementation).

This script builds a classic (inefficient) range proof for Pedersen commitments:
- Commit to a value v with Pedersen commitment C = g^v * h^r (mod p).
- Decompose v into bits and commit to each bit.
- Prove each committed bit is in {0,1} using a Schnorr OR-proof.
- Prove the bit commitments recombine to the original commitment (without revealing v).

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


def toy_group() -> tuple[int, int, int, int]:
    p = 467
    q = 233
    g = 3
    h = 4
    if pow(g, q, p) != 1 or g % p in (0, 1):
        raise ValueError("bad toy generator g")
    if pow(h, q, p) != 1 or h % p in (0, 1) or h == g:
        raise ValueError("bad toy generator h")
    return p, q, g, h


@dataclass(frozen=True)
class SchnorrProof:
    t: int
    c: int
    s: int


def schnorr_prove_nizk(*, p: int, q: int, g: int, y: int, x: int, label: Label, rng: random.Random) -> SchnorrProof:
    r = rng.randrange(0, q)
    t = pow(g, r, p)
    c = hash_to_scalar(q, [_as_bytes(label), p, q, g, y, t])
    s = (r + c * (x % q)) % q
    return SchnorrProof(t=t, c=c, s=s)


def schnorr_verify_nizk(*, p: int, q: int, g: int, y: int, proof: SchnorrProof, label: Label) -> bool:
    c_expected = hash_to_scalar(q, [_as_bytes(label), p, q, g, y, proof.t])
    if proof.c != c_expected:
        return False
    left = pow(g, proof.s, p)
    right = (proof.t * pow(y, proof.c, p)) % p
    return left == right


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
        s1 = (r1 + c1 * (x1 % q)) % q
        return OrProof(t1=t1, t2=t2, c1=c1, c2=c2, s1=s1, s2=s2)

    c1 = rng.randrange(0, q)
    s1 = rng.randrange(0, q)
    t1 = schnorr_simulate_commitment(p=p, g=g, y=y1, c=c1, s=s1)

    r2 = rng.randrange(0, q)
    t2 = pow(g, r2, p)

    c = hash_to_scalar(q, [_as_bytes(label), p, q, g, y1, y2, t1, t2])
    c2 = (c - c1) % q
    s2 = (r2 + c2 * (x2 % q)) % q
    return OrProof(t1=t1, t2=t2, c1=c1, c2=c2, s1=s1, s2=s2)


def or_verify_nizk(*, p: int, q: int, g: int, y1: int, y2: int, proof: OrProof, label: Label) -> bool:
    c = hash_to_scalar(q, [_as_bytes(label), p, q, g, y1, y2, proof.t1, proof.t2])
    if (proof.c1 + proof.c2) % q != c:
        return False

    left1 = pow(g, proof.s1, p)
    right1 = (proof.t1 * pow(y1, proof.c1, p)) % p
    if left1 != right1:
        return False

    left2 = pow(g, proof.s2, p)
    right2 = (proof.t2 * pow(y2, proof.c2, p)) % p
    if left2 != right2:
        return False

    return True


def pedersen_commit(*, p: int, q: int, g: int, h: int, m: int, r: int) -> int:
    if not (0 <= m < q):
        raise ValueError("message must be in [0, q)")
    r %= q
    return (pow(g, m, p) * pow(h, r, p)) % p


def decompose_bits(value: int, n_bits: int) -> list[int]:
    if n_bits <= 0:
        raise ValueError("n_bits must be positive")
    if value < 0 or value >= (1 << n_bits):
        raise ValueError("value is out of range for n_bits")
    return [(value >> i) & 1 for i in range(n_bits)]


def compose_bits(bits: Iterable[int]) -> int:
    out = 0
    for i, b in enumerate(bits):
        if b not in (0, 1):
            raise ValueError("bits must be 0/1")
        out |= int(b) << i
    return out


def combine_bit_commitments(*, p: int, q: int, bit_commitments: Iterable[int]) -> int:
    out = 1
    for i, Ci in enumerate(bit_commitments):
        e = (1 << i) % q
        out = (out * pow(Ci, e, p)) % p
    return out


def bit_commitment_prove_nizk(
    *,
    p: int,
    q: int,
    g: int,
    h: int,
    bit_commitment: int,
    bit: int,
    r: int,
    label: Label,
    rng: random.Random,
) -> OrProof:
    if bit not in (0, 1):
        raise ValueError("bit must be 0 or 1")
    y0 = bit_commitment
    y1 = (bit_commitment * inv_mod(g, p)) % p
    if bit == 0:
        return or_prove_nizk(p=p, q=q, g=h, y1=y0, y2=y1, x1=r, x2=None, label=label, rng=rng)
    return or_prove_nizk(p=p, q=q, g=h, y1=y0, y2=y1, x1=None, x2=r, label=label, rng=rng)


def bit_commitment_verify_nizk(
    *,
    p: int,
    q: int,
    g: int,
    h: int,
    bit_commitment: int,
    proof: OrProof,
    label: Label,
) -> bool:
    y0 = bit_commitment
    y1 = (bit_commitment * inv_mod(g, p)) % p
    return or_verify_nizk(p=p, q=q, g=h, y1=y0, y2=y1, proof=proof, label=label)


@dataclass(frozen=True)
class RangeProof:
    n_bits: int
    bit_commitments: tuple[int, ...]
    bit_proofs: tuple[OrProof, ...]
    link_proof: SchnorrProof


def range_prove_nizk(
    *,
    p: int,
    q: int,
    g: int,
    h: int,
    value: int,
    n_bits: int,
    label: Label,
    rng: random.Random,
) -> tuple[int, RangeProof]:
    if (1 << n_bits) >= q:
        raise ValueError("choose n_bits so that 2^n_bits < q (avoid wrap-around)")

    bits = decompose_bits(value, n_bits)
    r_value = rng.randrange(0, q)
    commitment = pedersen_commit(p=p, q=q, g=g, h=h, m=value, r=r_value)

    bit_commitments: list[int] = []
    bit_proofs: list[OrProof] = []
    bit_blindings: list[int] = []

    for i, bit in enumerate(bits):
        r_i = rng.randrange(0, q)
        bit_blindings.append(r_i)
        C_i = pedersen_commit(p=p, q=q, g=g, h=h, m=bit, r=r_i)
        bit_commitments.append(C_i)
        bit_proofs.append(
            bit_commitment_prove_nizk(
                p=p,
                q=q,
                g=g,
                h=h,
                bit_commitment=C_i,
                bit=bit,
                r=r_i,
                label=f"{label}|bit|{i}",
                rng=rng,
            )
        )

    recomposed = combine_bit_commitments(p=p, q=q, bit_commitments=bit_commitments)

    r_recomposed = 0
    for i, r_i in enumerate(bit_blindings):
        r_recomposed = (r_recomposed + ((1 << i) * r_i)) % q

    delta_r = (r_recomposed - r_value) % q
    ratio = (recomposed * inv_mod(commitment, p)) % p
    link_proof = schnorr_prove_nizk(p=p, q=q, g=h, y=ratio, x=delta_r, label=f"{label}|link", rng=rng)

    proof = RangeProof(
        n_bits=n_bits,
        bit_commitments=tuple(bit_commitments),
        bit_proofs=tuple(bit_proofs),
        link_proof=link_proof,
    )
    return commitment, proof


def range_verify_nizk(*, p: int, q: int, g: int, h: int, commitment: int, proof: RangeProof, label: Label) -> bool:
    if proof.n_bits <= 0:
        return False
    if (1 << proof.n_bits) >= q:
        return False
    if len(proof.bit_commitments) != proof.n_bits:
        return False
    if len(proof.bit_proofs) != proof.n_bits:
        return False
    if pow(commitment, q, p) != 1:
        return False

    for i, (C_i, pi) in enumerate(zip(proof.bit_commitments, proof.bit_proofs)):
        if pow(C_i, q, p) != 1:
            return False
        if not bit_commitment_verify_nizk(p=p, q=q, g=g, h=h, bit_commitment=C_i, proof=pi, label=f"{label}|bit|{i}"):
            return False

    recomposed = combine_bit_commitments(p=p, q=q, bit_commitments=proof.bit_commitments)
    ratio = (recomposed * inv_mod(commitment, p)) % p
    if not schnorr_verify_nizk(p=p, q=q, g=h, y=ratio, proof=proof.link_proof, label=f"{label}|link"):
        return False
    return True


def _fmt_int(x: int) -> str:
    return f"{x} (0x{x:x})"


def main():
    p, q, g, h = toy_group()
    rng = random.Random(0)

    print("=== Step 1: Schnorr + OR proofs (building block) ===")
    x1 = 42
    y1 = pow(h, x1, p)
    x2 = 99
    y2 = pow(h, x2, p)
    or_proof = or_prove_nizk(p=p, q=q, g=h, y1=y1, y2=y2, x1=x1, x2=None, label="or-demo", rng=rng)
    print("Statement: know log_h(y1) OR log_h(y2)")
    print("y1 =", _fmt_int(y1))
    print("y2 =", _fmt_int(y2))
    print("verify =", or_verify_nizk(p=p, q=q, g=h, y1=y1, y2=y2, proof=or_proof, label="or-demo"))

    print("\n=== Step 2: Pedersen commitments + bit decomposition ===")
    value = 13
    n_bits = 4
    r_value = rng.randrange(0, q)
    C = pedersen_commit(p=p, q=q, g=g, h=h, m=value, r=r_value)
    bits = decompose_bits(value, n_bits)
    print("value =", value, "bits(L->H) =", bits)
    print("Commitment C =", _fmt_int(C))

    print("\n=== Step 3: Prove a committed value is a bit (0/1) ===")
    bit = bits[0]
    r_bit = rng.randrange(0, q)
    C_bit = pedersen_commit(p=p, q=q, g=g, h=h, m=bit, r=r_bit)
    bit_proof = bit_commitment_prove_nizk(
        p=p, q=q, g=g, h=h, bit_commitment=C_bit, bit=bit, r=r_bit, label="bit-demo", rng=rng
    )
    print("Committed bit =", bit, "C_bit =", _fmt_int(C_bit))
    print("verify =", bit_commitment_verify_nizk(p=p, q=q, g=g, h=h, bit_commitment=C_bit, proof=bit_proof, label="bit-demo"))
    tampered = OrProof(t1=bit_proof.t1, t2=bit_proof.t2, c1=bit_proof.c1, c2=bit_proof.c2, s1=bit_proof.s1, s2=(bit_proof.s2 + 1) % q)
    print("tampered verify =", bit_commitment_verify_nizk(p=p, q=q, g=g, h=h, bit_commitment=C_bit, proof=tampered, label="bit-demo"))

    print("\n=== Step 4: Full range proof for a Pedersen commitment ===")
    rng = random.Random(0)
    C_range, rp = range_prove_nizk(p=p, q=q, g=g, h=h, value=value, n_bits=n_bits, label="range-demo", rng=rng)
    print("Commitment C =", _fmt_int(C_range))
    print("verify =", range_verify_nizk(p=p, q=q, g=g, h=h, commitment=C_range, proof=rp, label="range-demo"))
    print("wrong label verify =", range_verify_nizk(p=p, q=q, g=g, h=h, commitment=C_range, proof=rp, label="range-demo-wrong"))


if __name__ == "__main__":
    main()
