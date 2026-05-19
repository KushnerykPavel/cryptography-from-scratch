# OR Proofs & AND Proofs
> Compose proofs: prove more with less, and leak less while doing it.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** `../02-sigma-protocols/docs/en.md`, `../03-schnorr-id-protocol/docs/en.md`, `../04-fiat-shamir/docs/en.md`  
**Time:** ~70 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why AND/OR proof composition matters for privacy and efficiency
- **Compute** the Schnorr verification equation and challenge split conditions
- **Implement** an AND-proof and an OR-proof for Schnorr discrete-log statements
- **Distinguish** soundness vs. witness indistinguishability in OR-proofs
- **Apply** “statement binding” rules (hash transcript + statement) to prevent replay/malleability

## The Problem
You often need to prove *compound* statements, not single facts. Example: “I control the secret key for this account **and** I control the recovery key,” or “I control **either** device key A **or** device key B.” If you run two separate proofs, you leak structure (which key path you took) and you pay double the overhead.

Worse, if you try to “hack together” compound proofs by mixing transcripts incorrectly, you can accidentally create proofs that are replayable, malleable, or not actually bound to the statement you intended to prove. In real systems this shows up as privacy leaks (linkability), broken access-control (“prove one-of-two” becomes “prove nothing”), or subtle bugs during Fiat–Shamir transforms.

## The Concept
We start from a Schnorr proof of knowledge for a discrete log:

Statement: `y = g^x (mod p)` where `x` is the witness.

Schnorr (Fiat–Shamir NIZK flavor) uses:

- Commitment: `t = g^r (mod p)`
- Challenge: `c = H(label, p, q, g, y, t) mod q`
- Response: `s = r + c·x (mod q)`

Verifier checks:

`g^s ?= t · y^c (mod p)`

Now composition:

**AND proof (know x1 AND x2).**  
Use one shared challenge `c` for both statements. Intuition: the prover must answer one challenge consistently for both sub-proofs.

**OR proof (know x1 OR x2).**  
The prover *simulates* a valid-looking transcript for the statement they don’t know, then chooses the real sub-proof so that `c1 + c2 = c (mod q)`. This gives **witness indistinguishability**: the verifier learns that *at least one witness exists*, but not which one was used.

Quick comparison:

| Goal | What you prove | Key condition |
|------|----------------|---------------|
| AND | “I know both witnesses” | one `c` shared across sub-proofs |
| OR | “I know at least one witness” | `c1 + c2 = c (mod q)` and one sub-proof may be simulated |

## Build It

### Step 1: Hash-to-scalar challenges
```python
import hashlib
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
```
This gives us (1) an inverse for the simulation equation in OR-proofs and (2) a deterministic Fiat–Shamir challenge `c ∈ Z_q` that is *bound* to the full statement and transcript.

### Step 2: Schnorr NIZK (Fiat–Shamir)
```python
import random
from dataclasses import dataclass


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
```
This is our “atomic” building block. AND and OR compositions are built by carefully coordinating challenges and responses across multiple Schnorr-like sub-proofs.

### Step 3: AND proof (same challenge for both)
```python
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
```
AND composition is the “easy” case: you keep one challenge `c` and answer it for every sub-statement. If the prover doesn’t know one witness, they can’t answer consistently.

### Step 4: OR proof (simulate one branch, adjust challenges)
```python
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
```
The simulation trick is the core: without knowing a witness, you can still produce a “valid” Schnorr transcript if you choose `(c, s)` first and back-compute `t`. The OR proof works by simulating exactly one branch and then forcing the sum-of-challenges condition.

Run it:

`python3 code/main.py`

## Use It
In production ZK systems, you rarely hand-roll OR/AND sigma proofs directly; you usually:

- Encode OR/AND logic inside a circuit (R1CS / PLONK-ish), then use a SNARK/STARK library to prove the circuit.
- Use a protocol library that provides *combinators* for sigma protocols (AND, OR, repetition, Fiat–Shamir), plus group validation and transcript domain separation.

Where you’ll see OR/AND sigma proofs in the wild:

- Ring signatures and “one-of-many” membership proofs (OR over many public keys)
- Anonymous credentials and privacy-preserving authentication flows (“I’m one of these members”)
- Protocol glue: proving multiple relations with one transcript challenge (AND composition)

## Pitfalls
- **Not binding the statement into the hash.** If `c = H(t)` instead of `H(statement, t)`, transcripts can be replayed/moved between statements.
- **Using the wrong modulus for challenges/responses.** Challenges live in `Z_q` (the subgroup order), not `Z_p`.
- **Reusing randomness `r`.** If `r` repeats across proofs, you can leak the witness (classic Schnorr failure mode).
- **Skipping subgroup / input validation.** If `y` isn’t in the right subgroup, soundness and zero-knowledge arguments can break.
- **Forgetting OR ordering.** OR proofs are order-sensitive: swapping `(y1, y2)` should invalidate the proof unless your transcript explicitly canonicalizes ordering.

## Ship It
Save the reusable review checklist from `outputs/zk-or-and-proof-review-checklist.md` somewhere you can paste it into:

- a protocol design doc (“are we composing proofs safely?”)
- a PR review (“is the challenge bound to the statement and domain-separated?”)
- an audit notes doc (“what assumptions does the OR proof rely on?”)

## Exercises
1. Easy. Run `python3 code/main.py`. Observe that both OR proofs verify, but their transcripts differ.
2. Medium. Extend `or_prove_nizk` to support a 3-way OR: prove knowledge of `x1 OR x2 OR x3` by simulating two branches.
3. Hard. Production integration: replace `toy_group()` with a real prime-order group (e.g., Ristretto255) using an audited library, and keep the transcript hashing rules identical (domain separation + statement binding).

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Sigma protocol | “3-move proof” | Commit → challenge → respond protocol with special soundness / HVZK |
| Fiat–Shamir | “make it non-interactive” | Replace verifier challenge with `H(transcript)` in the random oracle model |
| AND proof | “prove two things at once” | One challenge `c` shared across multiple relations |
| OR proof | “prove one of these” | A proof that at least one statement holds, with one branch simulated |
| Witness indistinguishability | “doesn’t reveal which witness” | Verifier can’t tell which witness branch the prover used |

## Further Reading
- Cramer, Damgård, Schoenmakers, *Proofs of Partial Knowledge and Simplified Design of Witness Hiding Protocols* (1994) — classic OR-proof construction for sigma protocols.
- Goldreich, *Foundations of Cryptography, Vol. 1* (2001) — sigma protocols, simulation, and composition basics.
- Bünz et al., *Bulletproofs: Short Proofs for Confidential Transactions and More* (2018) — shows how OR-like logic appears inside modern proof systems.
