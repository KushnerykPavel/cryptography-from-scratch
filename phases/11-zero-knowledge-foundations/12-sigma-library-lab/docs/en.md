# ZK Foundations Lab — Build a Σ-Protocol Library
> Don’t “implement a proof” — implement the transcript, the checks, and the binding.

**Type:** Build
**Languages:** Python
**Prerequisites:** `phases/11-zero-knowledge-foundations/02-sigma-protocols`, `phases/11-zero-knowledge-foundations/03-schnorr-id-protocol`, `phases/11-zero-knowledge-foundations/04-fiat-shamir`, `phases/11-zero-knowledge-foundations/05-chaum-pedersen`
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain what a “Σ-protocol library” must get right (types, checks, binding), not just the algebra.
- Compute accepting transcripts for Schnorr (DLog) and DLEQ (Chaum–Pedersen) in a toy subgroup.
- Implement `prove`, `verify`, `simulate_hvz`, and `extract_witness` helpers as reusable building blocks.
- Distinguish interactive challenges from Fiat–Shamir challenges (and what must be hashed).
- Apply the nonce-reuse extractor to recover a witness and recognize the corresponding real-world bug class.

## The Problem

In real systems, Σ-protocols rarely live alone. They get wrapped into
authentication flows, turned into non-interactive proofs via Fiat–Shamir, and
composed into larger statements (AND/OR proofs). The algebra is usually the
easy part.

What ships bugs is the “library glue”: missing subgroup checks, reusing a
nonce, forgetting domain separation, hashing the wrong transcript fields, or
serializing the transcript ambiguously so prover and verifier hash different
bytes. These failures don’t look like math mistakes — they look like normal
engineering mistakes.

This lab forces you to build the minimal set of *reusable* pieces you need to
implement multiple Σ-protocol instances safely, and to demonstrate the two
core meta-properties you should always test: **HVZK simulation** and **nonce
reuse extraction**.

## The Concept

A Σ-protocol transcript is always:

`(commitment a, challenge c, response s)`

Everything else is policy:

1. What type is `a` (single group element? a tuple of elements?)
2. What is the statement being proved (what must be bound into the challenge)?
3. What are the validity checks (ranges, group membership)?
4. How do we generate `c`?
   - Interactive: verifier samples `c`.
   - Fiat–Shamir: `c = H(domain_sep || statement || commitment || context) mod q`.

Two sanity tools make Σ-protocol code reviewable:

- **Special HVZK simulator:** pick `(c, s)` first, then back-compute `a` so verification passes.
- **Special soundness extractor:** two accepting transcripts with the same `a` and `c1 != c2` reveal the witness.

## Build It

### Step 1: Shared types + toy group
```python
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import secrets
from typing import Any


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return (abs(a), 1 if a >= 0 else -1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def mod_inv(a: int, mod: int) -> int:
    a = a % mod
    if a == 0:
        raise ValueError("0 has no inverse modulo mod")
    g, x, _y = egcd(a, mod)
    if g != 1:
        raise ValueError("a and mod are not coprime")
    return x % mod


def mod_mul(a: int, b: int, mod: int) -> int:
    return (a % mod) * (b % mod) % mod


def mod_pow(base: int, exp: int, mod: int) -> int:
    return pow(base % mod, exp, mod)


class DeterministicRNG:
    def __init__(self, seed: bytes):
        if seed == b"":
            raise ValueError("seed must be non-empty")
        self._seed = seed
        self._counter = 0

    def randbelow(self, n: int) -> int:
        if n <= 0:
            raise ValueError("n must be positive")
        h = hashlib.sha256(self._seed + self._counter.to_bytes(4, "big")).digest()
        self._counter += 1
        return int.from_bytes(h, "big") % n


def rand_zq(q: int, rng: DeterministicRNG | None = None) -> int:
    if q <= 1:
        raise ValueError("q must be > 1")
    if rng is None:
        return secrets.randbelow(q)
    return rng.randbelow(q)


@dataclass(frozen=True)
class SchnorrParams:
    """Toy subgroup parameters for Schnorr-style protocols."""

    p: int
    q: int
    g: int


def schnorr_params_toy() -> SchnorrParams:
    return SchnorrParams(p=23, q=11, g=2)


def assert_prime_order_subgroup(params: SchnorrParams, *, elements: list[int]) -> None:
    if params.p <= 2 or params.q <= 1:
        raise ValueError("bad group parameters")
    if (params.p - 1) % params.q != 0:
        raise ValueError("q must divide p-1")
    if not (1 < params.g < params.p):
        raise ValueError("g must satisfy 1 < g < p")
    if mod_pow(params.g, params.q, params.p) != 1:
        raise ValueError("g does not have order q")

    for el in elements:
        if not (1 <= el < params.p):
            raise ValueError("element out of range")
        if mod_pow(el, params.q, params.p) != 1:
            raise ValueError("element not in subgroup of order q")


@dataclass(frozen=True)
class SigmaTranscript:
    """A Σ-protocol transcript: (commitment, challenge, response)."""

    commitment: Any
    challenge: int
    response: int
```
This is the “library core”: shared math helpers, a deterministic RNG for
vectors, subgroup validation, and a transcript type that can hold either a
single commitment or a tuple of commitments.

### Step 2: Schnorr Σ-protocol (prove/verify)
```python
def schnorr_public_key(params: SchnorrParams, x: int) -> int:
    x = x % params.q
    return mod_pow(params.g, x, params.p)


def schnorr_commit(params: SchnorrParams, r: int) -> int:
    r = r % params.q
    return mod_pow(params.g, r, params.p)


def schnorr_respond(q: int, r: int, c: int, x: int) -> int:
    return (r + (c % q) * (x % q)) % q


def schnorr_prove(params: SchnorrParams, x: int, *, c: int, rng: DeterministicRNG | None = None) -> SigmaTranscript:
    r = rand_zq(params.q, rng=rng)
    a = schnorr_commit(params, r)
    s = schnorr_respond(params.q, r, c, x)
    return SigmaTranscript(commitment=a, challenge=c % params.q, response=s)


def schnorr_verify(params: SchnorrParams, y: int, a: int, c: int, s: int) -> bool:
    if not (0 <= c < params.q):
        return False
    if not (0 <= s < params.q):
        return False
    if not (0 <= a < params.p):
        return False
    left = mod_pow(params.g, s, params.p)
    right = mod_mul(a, mod_pow(y, c, params.p), params.p)
    return left == right
```
This is the reusable “shape” of Schnorr: one commitment `a = g^r`, one response
`s = r + c·x (mod q)`, and one verification equation.

### Step 3: Simulate (HVZK) + extract (nonce reuse)
```python
def schnorr_simulate_hvz(params: SchnorrParams, y: int, c: int, s: int) -> SigmaTranscript:
    c = c % params.q
    s = s % params.q
    y_to_c = mod_pow(y, c, params.p)
    a = mod_mul(mod_pow(params.g, s, params.p), mod_inv(y_to_c, params.p), params.p)
    return SigmaTranscript(commitment=a, challenge=c, response=s)


def schnorr_extract_witness(q: int, c1: int, s1: int, c2: int, s2: int) -> int:
    c1 = c1 % q
    c2 = c2 % q
    s1 = s1 % q
    s2 = s2 % q
    if c1 == c2:
        raise ValueError("need two different challenges to extract")
    num = (s1 - s2) % q
    den = (c1 - c2) % q
    return (num * mod_inv(den, q)) % q
```
These two functions are your “proof sanity harness”:

- Simulation checks you can produce accepting transcripts without the witness.
- Extraction shows the exact reason nonce reuse is a key leak.

### Step 4: DLEQ (Chaum–Pedersen) + Fiat–Shamir proofs
```python
def hash_to_int_sha256(data: bytes, mod: int) -> int:
    if mod <= 0:
        raise ValueError("mod must be positive")
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, "big") % mod


def encode_fs_context(domain_sep: str, items: list[tuple[str, int]]) -> bytes:
    if domain_sep == "":
        raise ValueError("domain_sep must be non-empty")
    msg = domain_sep
    for k, v in items:
        msg += f"|{k}={v}"
    return msg.encode("utf-8")


def fiat_shamir_challenge(q: int, *, domain_sep: str, items: list[tuple[str, int]]) -> int:
    return hash_to_int_sha256(encode_fs_context(domain_sep, items), q)


def schnorr_prove_fs(
    params: SchnorrParams,
    x: int,
    *,
    statement_y: int,
    domain_sep: str,
    rng: DeterministicRNG | None = None,
) -> SigmaTranscript:
    r = rand_zq(params.q, rng=rng)
    a = schnorr_commit(params, r)
    c = fiat_shamir_challenge(params.q, domain_sep=domain_sep, items=[("y", statement_y), ("a", a)])
    s = schnorr_respond(params.q, r, c, x)
    return SigmaTranscript(commitment=a, challenge=c, response=s)


def schnorr_verify_fs(
    params: SchnorrParams,
    y: int,
    proof: SigmaTranscript,
    *,
    domain_sep: str,
) -> bool:
    if not isinstance(proof.commitment, int):
        return False
    a = proof.commitment
    expected_c = fiat_shamir_challenge(params.q, domain_sep=domain_sep, items=[("y", y), ("a", a)])
    if proof.challenge % params.q != expected_c:
        return False
    return schnorr_verify(params, y, a, expected_c, proof.response)


@dataclass(frozen=True)
class DLEQStatement:
    """Chaum–Pedersen statement: y1 = g1^x and y2 = g2^x in the same group."""

    params: SchnorrParams
    g1: int
    g2: int
    y1: int
    y2: int


def dleq_commit(stmt: DLEQStatement, r: int) -> tuple[int, int]:
    r = r % stmt.params.q
    a1 = mod_pow(stmt.g1, r, stmt.params.p)
    a2 = mod_pow(stmt.g2, r, stmt.params.p)
    return (a1, a2)


def dleq_respond(q: int, r: int, c: int, x: int) -> int:
    return (r + (c % q) * (x % q)) % q


def dleq_verify(stmt: DLEQStatement, a: tuple[int, int], c: int, s: int) -> bool:
    if not (0 <= c < stmt.params.q):
        return False
    if not (0 <= s < stmt.params.q):
        return False
    a1, a2 = a
    if not (0 <= a1 < stmt.params.p) or not (0 <= a2 < stmt.params.p):
        return False

    left1 = mod_pow(stmt.g1, s, stmt.params.p)
    right1 = mod_mul(a1, mod_pow(stmt.y1, c, stmt.params.p), stmt.params.p)
    left2 = mod_pow(stmt.g2, s, stmt.params.p)
    right2 = mod_mul(a2, mod_pow(stmt.y2, c, stmt.params.p), stmt.params.p)
    return left1 == right1 and left2 == right2


def dleq_simulate_hvz(stmt: DLEQStatement, c: int, s: int) -> SigmaTranscript:
    c = c % stmt.params.q
    s = s % stmt.params.q
    y1_to_c = mod_pow(stmt.y1, c, stmt.params.p)
    y2_to_c = mod_pow(stmt.y2, c, stmt.params.p)
    a1 = mod_mul(mod_pow(stmt.g1, s, stmt.params.p), mod_inv(y1_to_c, stmt.params.p), stmt.params.p)
    a2 = mod_mul(mod_pow(stmt.g2, s, stmt.params.p), mod_inv(y2_to_c, stmt.params.p), stmt.params.p)
    return SigmaTranscript(commitment=(a1, a2), challenge=c, response=s)


def dleq_extract_witness(q: int, c1: int, s1: int, c2: int, s2: int) -> int:
    return schnorr_extract_witness(q, c1, s1, c2, s2)


def dleq_prove(
    stmt: DLEQStatement, x: int, *, c: int, rng: DeterministicRNG | None = None
) -> SigmaTranscript:
    r = rand_zq(stmt.params.q, rng=rng)
    a1, a2 = dleq_commit(stmt, r)
    s = dleq_respond(stmt.params.q, r, c, x)
    return SigmaTranscript(commitment=(a1, a2), challenge=c % stmt.params.q, response=s)


def dleq_prove_fs(
    stmt: DLEQStatement,
    x: int,
    *,
    domain_sep: str,
    rng: DeterministicRNG | None = None,
) -> SigmaTranscript:
    r = rand_zq(stmt.params.q, rng=rng)
    a1, a2 = dleq_commit(stmt, r)
    c = fiat_shamir_challenge(
        stmt.params.q,
        domain_sep=domain_sep,
        items=[("g1", stmt.g1), ("g2", stmt.g2), ("y1", stmt.y1), ("y2", stmt.y2), ("a1", a1), ("a2", a2)],
    )
    s = dleq_respond(stmt.params.q, r, c, x)
    return SigmaTranscript(commitment=(a1, a2), challenge=c, response=s)


def dleq_verify_fs(stmt: DLEQStatement, proof: SigmaTranscript, *, domain_sep: str) -> bool:
    if not (isinstance(proof.commitment, tuple) and len(proof.commitment) == 2):
        return False
    a1, a2 = proof.commitment
    if not (isinstance(a1, int) and isinstance(a2, int)):
        return False
    expected_c = fiat_shamir_challenge(
        stmt.params.q,
        domain_sep=domain_sep,
        items=[("g1", stmt.g1), ("g2", stmt.g2), ("y1", stmt.y1), ("y2", stmt.y2), ("a1", a1), ("a2", a2)],
    )
    if proof.challenge % stmt.params.q != expected_c:
        return False
    return dleq_verify(stmt, (a1, a2), expected_c, proof.response)
```
Chaum–Pedersen (DLEQ) demonstrates why a transcript type must allow multiple
commitments, and Fiat–Shamir demonstrates the most common real-world wrapper.

Run it:
```
python3 code/main.py
```

## Use It

Where you’ll see the “real version” of what you built:

- **Schnorr proofs / signatures:** implemented over elliptic curves (e.g., in modern signature schemes), not `Z_p*`.
- **DLEQ (Chaum–Pedersen):** used to prove “same exponent” across two bases (common in mixnets, credential systems, and some key-derivation proofs).
- **Fiat–Shamir:** used to make proofs non-interactive *in the random oracle model*; also the backbone of Schnorr-style signatures.

In production, you typically rely on an audited ZK/proof framework (or an audited ECC library + well-reviewed proof constructions) rather than rolling your own.

## Pitfalls

1. **Nonce reuse:** if the same commitment randomness is used twice, extraction recovers the witness.
2. **No subgroup validation:** if statement elements aren’t in the intended subgroup, “verification” can be meaningless or exploitable.
3. **Weak or biased challenges:** soundness error is about `1/|C|`; small `q` or biased hashes break security arguments.
4. **Bad Fiat–Shamir binding:** if you don’t hash *all* statement fields + commitment(s) + domain separator, proofs can be replayed or transplanted.
5. **Ambiguous transcript encoding:** if prover and verifier serialize differently, they compute different challenges and either fail or accept unintended statements.

## Ship It

This lesson ships a practical review prompt:

- `outputs/prompt-sigma-library-review.md`

Paste it into your reviewer assistant when a PR claims to implement Schnorr/DLEQ
proofs, “Σ-protocols”, or Fiat–Shamir proofs. Use it to force the author to
specify the exact statement, transcript, binding, and validation rules.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that (a) the simulated transcript verifies and (b) nonce reuse extracts `x`.
2. Medium. Extend `code/main.py` to run `dleq_simulate_hvz` for many `(c, s)` choices and assert all simulated transcripts verify.
3. Hard. Add a second Fiat–Shamir domain separator string and demonstrate that the same `(statement, commitment)` yields different challenges across domains; write down why this prevents cross-protocol replay.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Σ-protocol | “A 3-step ZK proof” | A 3-move PoK transcript `(a,c,s)` with HVZK simulation and special soundness extraction. |
| HVZK simulator | “Proof is zero-knowledge” | An algorithm that outputs accepting transcripts without the witness for any challenge `c`. |
| Special soundness | “Hard to fake” | Two accepting transcripts with same `a` but different challenges reveal the witness. |
| Fiat–Shamir | “Make it non-interactive” | Replace verifier challenge with `c = H(context) mod q` (random oracle assumption). |
| Domain separation | “Different hash prefix” | A unique protocol id/version included in hashing to prevent cross-protocol transcript reuse. |

## Further Reading

- Bellare, Goldwasser, Micciancio, “Fiat–Shamir: From Practice to Theory” (1998) — formalizes Fiat–Shamir security in the random oracle model.
- Cramer, Damgård, Schoenmakers, “Proofs of Partial Knowledge and Simplified Design of Witness Hiding Protocols” (1994) — OR-composition ideas for Σ-protocols.
- Chaum, Pedersen, “Wallet Databases with Observers” (1992) — introduces the DLEQ-style proof of equality of discrete logs.
