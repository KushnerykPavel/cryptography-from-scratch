# Knowledge Soundness — Extractors

> If you can answer two challenges for the same commitment, you know the witness.

**Type:** Learn
**Languages:** Python
**Prerequisites:** `02-sigma-protocols`, `03-schnorr-id-protocol`, `06-or-and-proofs`
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain what a knowledge extractor is and why PoKs need one.
- Distinguish soundness (“can’t prove false”) from knowledge soundness (“can’t prove without witness”).
- Implement a special-soundness extractor for Schnorr transcripts.
- Apply rewinding to obtain two challenges for the same commitment.
- Compute which branch is “real” in an OR proof by extracting a witness.

## The Problem

You’re reviewing a ZK protocol in a system that actually *uses* the witness: an
anonymous credential should let you log in, a shielded transaction should let you
spend, a proof in a rollup should correspond to a real state transition. If the
proof isn’t a *proof of knowledge*, a malicious prover might still convince the
verifier while not knowing any witness — and the downstream system breaks (e.g.,
you “prove” you own an account you can’t actually authenticate as).

The security proof you want to see is not only “false statements are hard to
prove”, but “if someone can make the verifier accept, there exists an algorithm
that can *extract* the witness by interacting with that prover.” This extractor
is what turns the word “knowledge” into something testable and formal.

## The Concept

In a 3-move sigma protocol, the transcript is:

1. Prover sends a **commitment** `t`
2. Verifier sends a **challenge** `c`
3. Prover sends a **response** `s`

For Schnorr (discrete-log relation `y = g^x mod p`):

- Prover picks random `r`, sends `t = g^r`
- Verifier samples `c`
- Prover replies `s = r + c·x (mod q)`
- Verifier checks `g^s == t · y^c (mod p)`

Why does this prove *knowledge*? The key property is **special soundness**:

If you have two accepting transcripts that reuse the same commitment `t` but have
different challenges `c != c'`, then you can compute the witness:

`s  = r + c·x   (mod q)`

`s' = r + c'·x  (mod q)`

Subtract:

`s - s' = (c - c')·x (mod q)`

So:

`x = (s - s') · (c - c')^{-1} (mod q)`

An **extractor** is the algorithm that manufactures those two transcripts. In
interactive proofs, this is usually done by **rewinding**: run the prover up to
the commitment, send a challenge, get a response, rewind to the post-commitment
state, send a different challenge, get a second response.

For an OR proof (“I know `x1` OR `x2`”), extraction still works: from two
accepting OR transcripts with the same commitments and different *global*
challenges, at least one branch must have two different challenges, so we can
run the underlying extractor on that branch and obtain one witness.

## Build It

### Step 1: Implement Schnorr transcripts + a simulator
This gives us a concrete object to talk about: a transcript and a verifier that
accepts or rejects it. The simulator is the “HVZK trick”: choose `(c, s)` first,
then compute a commitment `t` that makes verification pass.

```python
from __future__ import annotations

import random
from dataclasses import dataclass


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


def toy_group() -> tuple[int, int, int]:
    p = 467
    q = 233
    g = 3
    if pow(g, q, p) != 1 or g % p in (0, 1):
        raise ValueError("bad toy group parameters")
    return p, q, g


@dataclass(frozen=True)
class SchnorrTranscript:
    t: int
    c: int
    s: int


def schnorr_commit(*, p: int, g: int, r: int) -> int:
    return pow(g, r, p)


def schnorr_respond(*, q: int, r: int, x: int, c: int) -> int:
    return (r + c * x) % q


def schnorr_verify(*, p: int, q: int, g: int, y: int, transcript: SchnorrTranscript) -> bool:
    if not (0 <= transcript.c < q and 0 <= transcript.s < q):
        return False
    left = pow(g, transcript.s, p)
    right = (transcript.t * pow(y, transcript.c, p)) % p
    return left == right


def schnorr_simulate_commitment(*, p: int, g: int, y: int, c: int, s: int) -> int:
    y_inv = inv_mod(y, p)
    return (pow(g, s, p) * pow(y_inv, c, p)) % p


def schnorr_simulate_transcript(*, p: int, q: int, g: int, y: int, c: int, s: int) -> SchnorrTranscript:
    t = schnorr_simulate_commitment(p=p, g=g, y=y, c=c, s=s)
    return SchnorrTranscript(t=t, c=c % q, s=s % q)
```

### Step 2: Implement the special-soundness extractor
This is the “two challenges” equation turned into code. If `t` is the same and
both transcripts verify, we can compute `x` in one line of modular arithmetic.

```python
def schnorr_extract_witness(*, q: int, transcript1: SchnorrTranscript, transcript2: SchnorrTranscript) -> int:
    if transcript1.t != transcript2.t:
        raise ValueError("extractor requires the same commitment t in both transcripts")
    if transcript1.c == transcript2.c:
        raise ValueError("extractor requires two different challenges")

    num = (transcript1.s - transcript2.s) % q
    den = (transcript1.c - transcript2.c) % q
    return (num * inv_mod(den, q)) % q
```

### Step 3: Rewinding = force two challenges for one commitment
In the security proof, the extractor is “just” a verifier that can rewind the
prover after it sends `t`. In `code/main.py`, Step 3 fixes a commitment `t`,
asks for two responses under challenges `c1` and `c2`, and then calls
`schnorr_extract_witness(...)`.

### Step 4: OR proof extraction (extract one witness)
An OR proof transcript is “two Schnorr transcripts glued together” plus a rule
that their challenges add to the global challenge. With two accepting OR
transcripts (same commitments, different global challenges), at least one branch
must have different per-branch challenges — and then Schnorr extraction works on
that branch.

```python
@dataclass(frozen=True)
class OrCommitment:
    t1: int
    t2: int


@dataclass(frozen=True)
class OrResponse:
    c1: int
    c2: int
    s1: int
    s2: int


def or_verify(
    *,
    p: int,
    q: int,
    g: int,
    y1: int,
    y2: int,
    commitment: OrCommitment,
    challenge: int,
    response: OrResponse,
) -> bool:
    if (response.c1 + response.c2) % q != (challenge % q):
        return False
    ok1 = schnorr_verify(p=p, q=q, g=g, y=y1, transcript=SchnorrTranscript(commitment.t1, response.c1 % q, response.s1 % q))
    ok2 = schnorr_verify(p=p, q=q, g=g, y=y2, transcript=SchnorrTranscript(commitment.t2, response.c2 % q, response.s2 % q))
    return ok1 and ok2


def or_extract_witness_from_two_transcripts(
    *,
    p: int,
    q: int,
    g: int,
    y1: int,
    y2: int,
    commitment: OrCommitment,
    challenge1: int,
    response1: OrResponse,
    challenge2: int,
    response2: OrResponse,
) -> tuple[int, int]:
    if not or_verify(p=p, q=q, g=g, y1=y1, y2=y2, commitment=commitment, challenge=challenge1, response=response1):
        raise ValueError("first transcript is not accepting")
    if not or_verify(p=p, q=q, g=g, y1=y1, y2=y2, commitment=commitment, challenge=challenge2, response=response2):
        raise ValueError("second transcript is not accepting")
    if (challenge1 % q) == (challenge2 % q):
        raise ValueError("extractor requires different global challenges")

    if (response1.c1 % q) != (response2.c1 % q):
        x1 = schnorr_extract_witness(
            q=q,
            transcript1=SchnorrTranscript(commitment.t1, response1.c1 % q, response1.s1 % q),
            transcript2=SchnorrTranscript(commitment.t1, response2.c1 % q, response2.s1 % q),
        )
        if pow(g, x1, p) != (y1 % p):
            raise ValueError("extracted witness does not match statement y1")
        return 1, x1

    if (response1.c2 % q) != (response2.c2 % q):
        x2 = schnorr_extract_witness(
            q=q,
            transcript1=SchnorrTranscript(commitment.t2, response1.c2 % q, response1.s2 % q),
            transcript2=SchnorrTranscript(commitment.t2, response2.c2 % q, response2.s2 % q),
        )
        if pow(g, x2, p) != (y2 % p):
            raise ValueError("extracted witness does not match statement y2")
        return 2, x2

    raise ValueError("no branch had two different challenges (unexpected for different global challenges)")
```

Run it:

`python3 code/main.py`

## Use It

- When you see “argument of knowledge”, ask: what extractor model is assumed (black-box rewinding, straight-line, simulation-extractability, random-oracle forking, …)?
- IETF: RFC 8235 specifies Schnorr non-interactive ZK proofs (Fiat–Shamir style) and highlights the danger of nonce reuse.
- CFRG drafts: `draft-irtf-cfrg-sigma-protocols` and `draft-irtf-cfrg-fiat-shamir` discuss standardizing sigma protocols and their Fiat–Shamir transform.
- Engineering reality: many libraries expose only `prove()`/`verify()`. Extractors live in *security proofs*, not in production code — but you still audit that the proof’s extractor assumptions match your threat model.

## Pitfalls
- Confusing “soundness” with “knowledge soundness”: acceptance alone is not proof of having the witness.
- Forgetting the “same commitment” requirement: extraction needs the exact same `t`, not just the same statement.
- Getting the modulus wrong: Schnorr’s response arithmetic is mod `q`, but group operations are mod `p`.
- Reusing the nonce `r` (or producing two responses for the same `t`): this *leaks the witness* via the extractor formula.
- Treating Fiat–Shamir as “no rewinding needed”: non-interactive extraction typically relies on random-oracle style arguments (forking) rather than a literal rewind of a live prover.

## Ship It

Save `outputs/zk-knowledge-soundness-extractor-checklist.md` and use it as:
- A PR review checklist for “this is a proof of knowledge” claims.
- A protocol-design decision guide: what extractor do we need, and what assumptions does it force?
- A vendor-questionnaire template when evaluating ZK systems.

## Exercises

1. Easy: run `python3 code/main.py` and observe that the extractor recovers `x` from two accepting transcripts.
2. Medium: modify Step 2 in `code/main.py` so the two transcripts use different commitments `t`. Confirm `schnorr_extract_witness` rejects.
3. Hard: take the OR extractor idea and generalize it to an `n`-way OR proof (prove knowledge of one of `n` discrete logs). What needs to change in the “which branch differs?” logic?

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Soundness | “You can’t prove false statements” | A cheating prover can’t make the verifier accept when the statement is false (except with small probability). |
| Knowledge soundness | “You must know the secret” | If you can make the verifier accept, there exists an efficient extractor that can output a witness. |
| Extractor | “An algorithm that pulls the witness out” | A proof technique: a hypothetical algorithm used in the security proof, often using rewinding/forking. |
| Special soundness | “Two transcripts leak the witness” | From two accepting transcripts with same commitment and different challenges, compute the witness. |
| Rewinding | “Run it twice” | The extractor resets the prover to a previous internal state to obtain two different challenges for the same commitment. |

## Further Reading

- C. P. Schnorr, *Efficient Signature Generation by Smart Cards* (1991) — origin of Schnorr identification/signatures and the sigma protocol view.
- R. Cramer, I. Damgård, B. Schoenmakers, *Proofs of Partial Knowledge and Simplified Design of Witness Hiding Protocols* (1994) — OR composition as a first-class construction.
- IETF RFC 8235, *Schnorr Non-interactive Zero-Knowledge Proof* (2017) — a practical spec with engineering guidance and pitfalls.
