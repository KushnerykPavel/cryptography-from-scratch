# The Simulator — How Security Proofs Work

> If a simulator can fake the transcript without seeing the secret, the protocol leaks zero knowledge.

**Type:** Learn
**Languages:** Python
**Prerequisites:** Phase 05 · 04 (Computational Indistinguishability) · 05 (Hybrid Argument) · 07 (Random Oracle Model)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- State the simulation paradigm: Real view ≈_c Ideal view produced by simulator S(x) without the witness.
- Explain the Schnorr simulator's reversed-order trick: pick c and s first, back-compute R = g^s · pk^{-c}.
- Verify that both real and simulated transcripts satisfy g^s ≡ R · pk^c (mod p).
- Apply special soundness to extract a discrete-log witness from two accepting transcripts with different challenges.
- Explain why parallel composition breaks basic Schnorr ZK and how the simulator fails in that setting.

## The Problem

You will encounter the phrase "by simulation" in virtually every security proof
for interactive protocols, zero-knowledge proofs, and secure computation. It
means: the adversary (or verifier) cannot extract useful information because
a simulator can produce an identical-looking conversation without having access
to the secret.

Without understanding the simulator:
- You cannot read a zero-knowledge proof paper.
- You cannot verify that a sigma-protocol actually leaks nothing.
- You cannot design or review MPC protocols that require simulation-based security.
- You cannot understand why replaying transcripts, parallel composition, or
  signing without randomness can destroy zero-knowledge.

The simulator is the bridge between the informal claim ("the verifier learns
nothing") and the formal proof ("for every verifier V*, there exists a PPT
simulator S such that the verifier's view is computationally indistinguishable
from S's output").

## The Concept

### The simulation paradigm

Security proofs for interactive protocols follow this template:

```
Real world:  Prover P(x, w)  ↔  Verifier V(x)
             (w = witness, x = statement)

Ideal world: Simulator S(x)  →  View_V
             (no witness — only the statement)

Security claim: View_V(Real) ≈_c View_V(Ideal)
```

If such a simulator exists, the verifier's view contains no information about
`w` — because everything in that view could have been produced without `w`.

### Sigma protocols

A **sigma protocol** (Σ-protocol) is a 3-move protocol:

```
Prover                              Verifier
  R = g^r  ─────── commitment ──►
           ◄──── challenge c ──────  c ← random
  s = r + c·x  ── response ──►
                                     verify: g^s == R · pk^c
```

Where `pk = g^x` is the public key and `x` is the secret. Used in: Schnorr
identification, EdDSA signing, Pedersen commitments, zkSNARK sub-protocols.

### Why real transcripts verify

The honest prover computes:
- `R = g^r` (commitment)
- `s = r + c·x` (response)

Verification: `g^s = g^{r + cx} = g^r · g^{cx} = R · (g^x)^c = R · pk^c` ✓

### The simulator's trick — reversing the order

The honest prover fixes `R` first, then sees `c`, then computes `s`. The
simulator does the opposite:

```python
# Pick c and s freely (uniformly at random)
c = random()
s = random()
# Back-compute R so the equation holds
R = g^s · pk^{-c}
```

Verification: `g^s == R · pk^c = g^s · pk^{-c} · pk^c = g^s` ✓

The simulated transcript `(R, c, s)` satisfies the same equation. Both `c` and
`s` are uniformly distributed in both real and simulated transcripts. The only
structural difference: in the real case, `R` is fixed first and `s` is
derived; in the simulation, `s` is fixed first and `R` is derived.

### Indistinguishability of real and simulated transcripts

In the real transcript: `c` and `s` are uniformly distributed (c is a random
challenge; s = r + cx is uniform because r is uniform and independent of c).
In the simulated transcript: `c` and `s` are explicitly chosen uniformly.
Therefore `(c, s)` have the same distribution in both cases. Since `R` is
determined by `(c, s, pk)` via the same equation, `R` also has the same
distribution. The transcripts are **identically distributed**.

This is **perfect zero-knowledge** for a random challenge c. With a hash-based
challenge (Fiat-Shamir transform), it becomes **computational ZK** (the hash
models a random oracle).

### What simulation proves

If you have a simulator that produces indistinguishable transcripts:

1. **Zero-knowledge**: the verifier learns nothing — whatever it can compute
   from the transcript, it could have computed itself without the proof.
2. **Security of the reduction**: in a ROM proof, the reduction programs
   `H(R || pk || m) = c` after choosing `c` first — exactly the simulator's trick.
3. **Soundness is separate**: a cheating prover with `s`, `c` chosen freely
   cannot fake a proof unless they know `x`. (Extraction: given two valid
   responses `s1, s2` to different challenges `c1, c2` for the same `R`, you
   can solve for `x`.)

### Special soundness and the knowledge extractor

Sigma protocols are **specially sound**: given two valid transcripts
`(R, c1, s1)` and `(R, c2, s2)` with `c1 ≠ c2`:

```
g^s1 = R · pk^c1   and   g^s2 = R · pk^c2
=> g^{s1-s2} = pk^{c1-c2}
=> x = (s1 - s2) · (c1 - c2)^{-1}  mod order
```

This is the **knowledge extractor**: it proves the prover "knows" `x`. Special
soundness + simulation = zero-knowledge proof of knowledge.

## Build It

### Step 1: group arithmetic and transcript verification

```python
@dataclass
class Transcript:
    commitment: int   # R = g^r
    challenge:  int   # c (random)
    response:   int   # s = r + c·x  (or freely chosen in simulation)

    def verify(self, pk, group) -> bool:
        lhs = group.exp(group.g, self.response)
        rhs = group.mul(self.commitment, group.exp(pk, self.challenge))
        return lhs == rhs              # g^s == R · pk^c
```

### Step 2: real transcript (requires secret)

```python
def real_transcript(secret, pk, group, *, rng=None) -> Transcript:
    r = rng.randrange(1, group.order)
    R = group.exp(group.g, r)          # commit first
    c = rng.randrange(1, group.order)  # then receive challenge
    s = (r + c * secret) % group.order
    return Transcript(R, c, s)
```

### Step 3: simulated transcript (no secret needed)

```python
def simulated_transcript(pk, group, *, rng=None) -> Transcript:
    c = rng.randrange(1, group.order)
    s = rng.randrange(1, group.order)
    # back-compute R so g^s == R · pk^c holds
    R = group.mul(group.exp(group.g, s),
                  group.inv(group.exp(pk, c)))
    return Transcript(R, c, s, simulated=True)
```

Reversed order: `s` is chosen *before* `R`, not after. Both verify; neither reveals `x`.

### Step 4: measure simulation quality

```python
def transcript_advantage(distinguisher, reals, sims) -> float:
    pr_real = sum(distinguisher(t) == 1 for t in reals) / len(reals)
    pr_sim  = sum(distinguisher(t) == 1 for t in sims)  / len(sims)
    return abs(pr_real - pr_sim)
```

Run it:

```
python3 code/main.py
```

## Use It

The simulator pattern appears everywhere:

- **EdDSA / Schnorr signing**: the ROM signature proof programs the hash oracle
  with a simulated transcript's `(R, c)` — the exact simulator trick.
- **zkSNARKs**: the trusted setup simulator programs the structured reference
  string; the proof verifier's view is perfectly simulated.
- **Oblivious Transfer**: the receiver's simulator fakes OT messages without
  the sender knowing which message was chosen.
- **TLS 1.3 handshake**: the security proof simulates the server's key exchange
  transcript for a corrupted client using the simulator paradigm.

## Attack It

**Attack: parallel composition breaks ZK.**

Run two instances of the Schnorr protocol in parallel (two challenges `c1, c2`
at the same time). If the prover uses the same randomness `r` for both:

```
s1 = r + c1·x,  s2 = r + c2·x
=> s1 - s2 = (c1 - c2)·x
=> x = (s1 - s2) / (c1 - c2)
```

The verifier extracts the secret! The simulator cannot fix this because it
cannot program two independent challenges to the same commitment. This is why
Schnorr-based ZK is **only 1-out-of-1 composable**: it requires fresh randomness
per invocation. Use a proper proof system (Sigma-OR, Bulletproofs) for
parallel composition.

**Attack: deterministic challenge breaks ZK.**

If `c = H(R || pk || m)` (Fiat-Shamir) and the hash is modelled as a random
oracle, the simulator works by programming `H(R_sim || pk || m) = c_sim`
before committing to `R_sim`. But if the hash is a *weak* hash that an adversary
can invert or control, the simulator's programming may be detectable — breaking
ZK and potentially soundness.

## Ship It

This lesson ships a reusable review prompt:

- `outputs/prompt-simulator-audit.md`

Use it when reviewing sigma-protocol proofs, ZK argument constructions, or any
security proof that claims "by simulation".

## Exercises

1. Easy: for the toy group `p=23, g=5, x=3`, manually generate a real transcript
   with `r=2, c=5`. Verify. Then build the simulated transcript for the same
   `c=5, s=12`. Verify. Show they produce the same `(R, c, s)` distribution.

2. Medium: implement the knowledge extractor for special soundness. Given two
   valid transcripts `(R, c1, s1)` and `(R, c2, s2)` with `c1 ≠ c2`, extract
   the secret `x`. Verify that the extracted `x` satisfies `g^x == pk`.

3. Hard: implement a parallel composition attack. Run two Schnorr rounds
   simultaneously with the same commitment `R` (same `r`). Show that seeing
   both responses `(s1, s2)` with different challenges `(c1, c2)` reveals `x`.
   Then explain why the simulator cannot produce both transcripts simultaneously
   (it would need to solve discrete log).

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| simulator | "fake it" | PPT algorithm that produces the verifier's view without the witness |
| sigma protocol | "3-move ZK" | commitment → challenge → response, with special soundness + HVZK |
| special soundness | "extractable" | two valid responses to different challenges reveals the witness |
| HVZK | "honest verifier ZK" | simulator exists when the verifier follows the protocol |
| knowledge extractor | "prove you know" | algorithm that extracts witness from two valid transcripts |
| Fiat-Shamir | "ROM signature" | replace interactive challenge with hash; simulator programs the hash |
| parallel composition | "two at once" | running two ZK protocols together can break ZK (reusing randomness) |

## Test Vectors

Source: toy Schnorr sigma-protocol with p=23, g=5, order=22. Vectors verify
the equation g^s == R·pk^c mod 23 for both real and simulated transcripts.

Code must pass all vectors in `tests/vectors.json`.

## Further Reading

- [Goldreich, *Foundations of Cryptography, Vol. 1*, §4.3](https://www.wisdom.weizmann.ac.il/~oded/foc-vol1.html) — simulation-based security
- [Boneh & Shoup, *A Graduate Course in Applied Cryptography*, Ch. 19](https://toc.cryptobook.us/) — sigma protocols, Fiat-Shamir, ZK proofs
- [Lindell, "How to Simulate It"](https://eprint.iacr.org/2016/046.pdf) — accessible guide to simulation-based security proofs
- [Katz & Lindell, *Introduction to Modern Cryptography*, Ch. 13](https://www.cs.umd.edu/~jkatz/imc.html) — zero-knowledge proofs
