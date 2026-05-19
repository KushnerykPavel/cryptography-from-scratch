# Range Proofs — From Naive to Bulletproofs
> Prove “it’s in range” without revealing the value.

**Type:** Build
**Languages:** Python
**Prerequisites:** `../05-chaum-pedersen/docs/en.md`, `../06-or-and-proofs/docs/en.md`
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why Pedersen commitments need range proofs (negatives / overflow / wrap-around)
- **Compute** how bit decomposition and commitment homomorphism reconstruct a committed value
- **Implement** a classic bit-decomposition range proof using Schnorr OR-proofs
- **Distinguish** “prove it’s a bit” (set membership) from “prove it recomposes” (linking proof)
- **Apply** statement binding (labels + transcript hashing) so proofs can’t be replayed across contexts

## The Problem
You can hide a value `v` inside a Pedersen commitment `C = g^v · h^r` and still add commitments together. This is exactly what confidential transaction systems do: amounts are hidden, but everyone can still verify conservation of value by checking commitment sums.

But commitments live in a *modular* group. If `v` is interpreted modulo the group order `q`, then “-5” is just “q-5”. Without an extra proof, a malicious prover can commit to a value that *looks* like a valid amount under modular arithmetic, but is actually out of the intended real-world range. In token systems that turns into inflation bugs; in ZK circuits it turns into silent constraint bypasses (“range checks” that don’t actually check a range).

Range proofs fix this: they let the prover convince everyone that the committed value is in a public range (e.g. `[0, 2^64)`) **without revealing** the value.

## The Concept
We work in a prime-order subgroup of a group where discrete log is assumed hard. A Pedersen commitment (multiplicative notation) is:

`Commit(v; r) = g^v · h^r (mod p)`

where:
- `v` is the hidden value,
- `r` is a random blinding factor,
- `g, h` are generators (in real protocols, the prover must not know `log_g(h)`).

The classic “linear” range proof for `v ∈ [0, 2^n)` uses **bit decomposition**:

`v = Σ_{i=0}^{n-1} 2^i · b_i` with each `b_i ∈ {0, 1}`.

Then the prover publishes:
1) commitments to each bit: `C_i = Commit(b_i; r_i)`, and proves each `b_i` is a bit, and
2) a **linking proof** that the product of bit commitments recomposes to the original commitment:

`Π C_i^{2^i} = g^v · h^{Σ 2^i r_i}`.

If we call that product `D`, then `D / C = h^{(Σ 2^i r_i) - r}`. So linking reduces to a Schnorr proof of knowledge of the discrete log of `D/C` to base `h`.

What you get:
- bit proofs: “each committed digit is 0 or 1” (set membership via OR-proofs),
- link proof: “the digits recombine to the committed value” (consistency).

This lesson implements the classical construction (linear in `n`) and sets you up for Bulletproofs (logarithmic-sized proofs) in the next lesson.

## Build It

### Step 1: Schnorr + OR proofs (building block)
```python
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
```
This is the same OR-proof idea from the previous lesson: simulate one branch, make challenges add up to the transcript-derived challenge, and verify both Schnorr equations.

### Step 2: Pedersen commitments + bit decomposition
```python
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
```
We can decompose `value` into bits, commit to each bit, and “recompose” by exponentiating each bit-commitment by `2^i` and multiplying them together.

### Step 3: Prove a committed value is a bit (0/1)
```python
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
```
If `C = g^b · h^r`, then either `C = h^r` (when `b=0`) or `C/g = h^r` (when `b=1`). So “`b ∈ {0,1}`” becomes an OR-proof about two Schnorr statements under base `h`.

### Step 4: Full range proof for a Pedersen commitment
```python
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
```
The proof is “bit proofs + one link proof”. The verifier recomposes the bits’ commitments and checks they match the original commitment up to an `h^Δ` factor proven by Schnorr.

Run it:
python3 code/main.py

## Use It
Production-grade range proofs are almost always Bulletproofs-style (or a circuit-based proof system with a range-check gadget).

Examples to look at:
- **Rust:** `dalek-cryptography/bulletproofs` (`RangeProof`, `PedersenGens`, `BulletproofGens`)
- **C / bindings:** `secp256k1-zkp` (Pedersen commitments + range proofs)
- **ZK circuits:** range checks via bit decomposition / limb decomposition inside PLONK-ish or STARK-ish systems (implementation varies by framework)

## Pitfalls
- **No range proof, just a commitment:** negative / overflow values become valid modulo `q`, enabling inflation or constraint bypass.
- **Wrap-around confusion:** if your intended range reaches `q`, the statement “`v ∈ [0, 2^n)`” stops being meaningful because `v` is inherently modulo `q`.
- **Transcript not bound to the statement:** computing challenges without hashing the full statement (or without domain separation labels) enables replay / transplant attacks.
- **Missing group membership / subgroup checks:** invalid-group / small-subgroup attacks can break soundness in real curve implementations.
- **Reusing randomness:** Schnorr-style protocols are fragile under nonce reuse; it can leak witnesses or enable forgeries.

## Ship It
Save and reuse the checklist in `outputs/zk-range-proof-review-checklist.md`.

Use it when you:
- review code that claims “range proof” or “range check”
- design a protocol around Pedersen commitments
- integrate Bulletproofs / circuit range checks and want to sanity-check statement binding and edge cases

## Exercises
1. Easy. Run `python3 code/main.py`. Observe that verification fails when you change the `label` (`wrong label verify = False`).
2. Medium. Change `value` and `n_bits` in `main()` and verify: when `value` is within `[0, 2^n_bits)`, the proof verifies; when it’s out of range, the prover should raise.
3. Hard. Replace the toy group with a real prime-order elliptic curve group and a proper hash-to-group generator for `h` (no known discrete log between `g` and `h`). Keep the API the same.

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Range proof | “Proof that amount is positive” | A ZK proof that a committed value lies in an agreed interval |
| Bit decomposition | “Write it in binary” | Represent `v` as `Σ 2^i b_i` and prove each `b_i` is a bit |
| Pedersen commitment | “Hiding commitment” | `C = g^v · h^r`, perfectly hiding and computationally binding (under assumptions) |
| OR-proof | “Prove A or B” | Prove knowledge of *one* witness without revealing which branch |
| Statement binding | “Hash the transcript” | Ensure `c = H(context, statement, commitments, ...)` so proofs can’t be replayed elsewhere |

## Further Reading
- Bünz et al., *Bulletproofs: Short Proofs for Confidential Transactions and More* (2018) — range proofs with logarithmic size via inner-product arguments.
- ZKDocs, *Pedersen Commitments* — a readable overview of commitment properties and common proof patterns.
- Monero Research Lab, *RingCT and range proofs* — why range proofs are necessary for hidden-amount systems.
