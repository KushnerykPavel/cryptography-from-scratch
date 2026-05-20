# Recursive Proofs

> One proof that verifies another — O(1) size regardless of steps.

**Type:** Build
**Languages:** Python
**Prerequisites:** `12-zk-proof-systems/05-groth16`, `12-zk-proof-systems/07-plonk-implement`, `12-zk-proof-systems/13-deep-fri` (hash commitments, polynomial proofs, field arithmetic)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** what Incrementally Verifiable Computation (IVC) is and why proof size stays O(1) as the number of steps grows.
- **Implement** a hash-accumulator IVC toy over a prime field using a fixed quadratic step function.
- **Distinguish** O(1) step verification from O(n) full verification and articulate when each is appropriate.
- **Identify** what the accumulator binds and why tampering with any field of the proof tuple is detectable.
- **Describe** how real systems (Nova, Groth16 recursion, Plonky2) replace the hash accumulator with a folding or proof-composition scheme.

## The Problem

Suppose you need to convince a verifier that you ran a computation for one million steps: each step applies the same transition function `F` to a state, and the final state is correct. A naive approach generates one proof per step — but that means the verifier must check one million proofs. Even if each proof is small, the verifier's work scales linearly with the number of steps.

You could instead aggregate all steps into a single SNARK over a circuit that encodes all one million steps. But that circuit is enormous: the prover's memory and time grow with `n`, and compiling the circuit alone can be prohibitive. For streaming or online settings — where new steps arrive continuously and you need to produce a proof *right now*, not after buffering — neither approach works.

IVC solves this by maintaining a single "running proof" that grows by a constant amount per step regardless of `n`. After step `k`, the prover holds a proof `π_k` whose size never changes. Adding step `k+1` costs O(1) work, and the verifier at any point only checks the current proof tuple — not the entire history. The key insight is that the proof for step `k+1` *embeds a verification of π_k* inside the new proof, folding the history into a fixed-size object.

## The Concept

### What IVC is

IVC (Incrementally Verifiable Computation), introduced by Valiant (2008), defines a scheme where:

- A *prover* maintains a proof `π_n = (n, z_n, acc_n)` after `n` steps.
- To extend: compute `z_{n+1} = F(z_n)` and update the accumulator `acc_{n+1} = H(n+1, z_{n+1}, acc_n)`.
- A *step verifier* checks only the local transition in O(1): did `z_{n+1}` come from `z_n` via `F`, and is the accumulator consistent?
- A *full verifier* can replay from `z_0` in O(n) to confirm the whole chain, or trust an O(1) cryptographic binding if the accumulator is a collision-resistant commitment.

### Why proof size is O(1)

The proof tuple `(n, z_n, acc_n)` always has exactly 3 field elements — three integers. No matter how many steps `n` becomes, the proof never grows. The accumulator `acc_n` is a hash that chains all prior states together; it collapses the entire history into one value. Adding another step replaces `acc_n` with `acc_{n+1} = H(n+1, z_{n+1}, acc_n)` — a constant-time operation that produces the same-sized output.

### Hash accumulator as toy model

In this lesson we use a SHA-256-based hash over field elements as the accumulator. While not a zero-knowledge accumulator (it reveals step count and current state), it demonstrates the structural property: the verifier can check a single transition in O(1), and the full chain is bound by the collision resistance of the hash function.

```
acc_0 = H(0, z_0, 0)          # initial seed
acc_1 = H(1, z_1, acc_0)      # after step 1
acc_2 = H(2, z_2, acc_1)      # after step 2
...
acc_n = H(n, z_n, acc_{n-1})  # after step n
```

Each accumulator value commits to the entire prefix of the computation. If any step is altered, the final accumulator will differ from the honest value with overwhelming probability (hash collision resistance).

### Real systems: Nova, Groth16 recursion, cycle of curves

In production, the hash is replaced by a cryptographic accumulator that is itself verifiable inside a circuit:

- **Nova (Kothapalli et al., 2021):** Uses *relaxed R1CS* and a Pedersen-commitment-based folding scheme. The "accumulator" is a running instance of a relaxed constraint system that folds in one new step per round. The final folded instance is verified with a single SNARK.
- **Groth16 recursion / Halo2:** Recursively verifies a Groth16 (or Plonk) proof *inside* another Groth16 circuit. Requires pairing-friendly curves where the scalar field of one curve equals the base field of another — known as a "cycle of curves" (e.g., Pallas/Vesta used by Zcash/Halo2).
- **Plonky2:** Uses FRI-based SNARKs over the Goldilocks field (the same prime used in this lesson) to achieve fast recursion without pairings. Proof verification circuits are small enough that recursive composition is practical.

The toy model here uses `fhash` (SHA-256 mod p) as the accumulator. The structural API — `ivc_init`, `ivc_extend`, `ivc_verify_step`, `ivc_verify_full` — maps directly onto what a real IVC library exposes.

## Build It

### Step 1: field hash and step function

```python
import hashlib
from typing import Tuple

MODULUS = 18446744069414584321  # Goldilocks prime: 2^64 - 2^32 + 1


def fhash(*vals: int, p: int = MODULUS) -> int:
    """Hash field elements into F_p.

    data = concat of each val as 8 big-endian bytes.
    return int.from_bytes(sha256(data).digest(), 'big') % p
    """
    data = b"".join(int(v).to_bytes(8, "big") for v in vals)
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % p


def step_fn(z: int, a: int, b: int, c: int, p: int = MODULUS) -> int:
    """F(z) = (a*z*z + b*z + c) % p"""
    return (a * z * z + b * z + c) % p
```

`fhash` serializes each integer as exactly 8 bytes (matching the 64-bit Goldilocks elements) and reduces the SHA-256 digest modulo `p`. The 8-byte encoding gives a deterministic, unambiguous byte representation. `step_fn` is the quadratic transition — any computable function would work; this one is easy to test.

### Step 2: initialize and extend the proof

```python
def ivc_init(z0: int, p: int = MODULUS) -> Tuple[int, int, int]:
    """Return (0, z0, fhash(0, z0, 0, p=p))."""
    acc = fhash(0, z0, 0, p=p)
    return (0, z0, acc)


def ivc_extend(proof: Tuple[int, int, int], a: int, b: int, c: int, p: int = MODULUS) -> Tuple[int, int, int]:
    """Given (n, zn, acc), return (n+1, F(zn), fhash(n+1, F(zn), acc, p=p)). O(1)."""
    n, zn, acc = proof
    zn1 = step_fn(zn, a, b, c, p=p)
    n1 = n + 1
    new_acc = fhash(n1, zn1, acc, p=p)
    return (n1, zn1, new_acc)
```

`ivc_init` seeds the chain: the initial accumulator is `H(0, z_0, 0)`, where the trailing `0` acts as a domain separator distinguishing the genesis state from a real step. `ivc_extend` is the O(1) update: apply `F`, increment `n`, and chain-hash the new state into the accumulator.

### Step 3: O(1) step verifier

```python
def ivc_verify_step(prev: Tuple[int, int, int], curr: Tuple[int, int, int], a: int, b: int, c: int, p: int = MODULUS) -> bool:
    """Check curr extends prev by one valid F step. O(1)."""
    n, zn, acc = prev
    n1, zn1, acc1 = curr
    if n1 != n + 1:
        return False
    if zn1 != step_fn(zn, a, b, c, p=p):
        return False
    if acc1 != fhash(n1, zn1, acc, p=p):
        return False
    return True
```

This checks three things in O(1): (1) the step counter advanced by exactly 1, (2) the new state is the correct application of `F`, and (3) the new accumulator is the correct hash of `(n+1, z_{n+1}, acc_n)`. Any of these three checks failing means the transition is invalid.

### Step 4: O(n) full verifier

```python
def ivc_verify_full(z0: int, proof: Tuple[int, int, int], a: int, b: int, c: int, p: int = MODULUS) -> bool:
    """Rebuild accumulator from z0 in O(n) and compare to proof. Returns bool."""
    n, zn, acc = proof
    curr = ivc_init(z0, p=p)
    for _ in range(n):
        curr = ivc_extend(curr, a, b, c, p=p)
    return curr == proof
```

The full verifier replays the entire chain from `z_0` and checks that it arrives at exactly the claimed `(n, z_n, acc_n)`. This is O(n) but requires no trust in any prior step — it independently validates the complete computation history. In a real system you would use this once at the end; thereafter the O(1) step verifier suffices.

### Step 5: proof size

```python
def proof_size(proof: Tuple[int, int, int]) -> int:
    """Return 3 (always — n, zn, acc)."""
    return 3
```

Always 3. The proof tuple `(n, z_n, acc_n)` contains exactly three field elements regardless of how many steps have been executed. This is the defining property of IVC.

Run it:

`python3 code/main.py`

## Use It

In production you would reach for one of these:

- **Nova** (`microsoft/Nova` on GitHub): the canonical folding-scheme IVC. Uses relaxed R1CS over the Pallas/Vesta cycle of curves. The API closely mirrors `ivc_init`/`ivc_extend`: you call `RecursiveSNARK::new` then `RecursiveSNARK::prove_step` in a loop, then compress with `CompressedSNARK::prove` for the final O(1) proof.
- **Groth16 + Halo2 recursion**: embed a Groth16 verifier circuit inside a Plonk/Halo2 circuit. Each layer's proof verifies the previous layer. The Halo2 `RecursionConfig` / `EccChip` handles the curve arithmetic needed to check pairings inside a circuit.
- **Plonky2** (`0xPolygonZero/plonky2`): FRI-based recursive SNARKs over the Goldilocks prime (the same `p` used here). Fast proof generation without pairings; widely used in zkEVM circuits.

## Pitfalls

- **Missing genesis binding:** if `acc_0` does not include `z_0`, a prover can swap `z_0` after the chain is built while keeping all other accumulators valid. Always hash the initial state into the seed.
- **Step counter forgery:** omitting the step counter `n` from the hash allows a prover to skip steps — they can jump from step `k` to step `k+5` and produce a valid accumulator. Include `n` in every `fhash` call.
- **Wrong field for hash reduction:** if you reduce the SHA-256 digest modulo a non-prime or use a different byte width, the distribution of accumulators changes and collision probability increases. Always reduce mod a prime `p` with enough bits.
- **O(1) step verifier does not check the full history:** `ivc_verify_step` only checks that *one* transition is locally consistent. A proof chain with a corrupt step buried deep in the middle will pass `ivc_verify_step` on every *adjacent* pair except the corrupt one — use `ivc_verify_full` when you need end-to-end assurance.
- **Accumulator is not zero-knowledge:** the hash accumulator in this toy leaks `n` and `z_n` directly. Real IVC systems use Pedersen commitments or inner-product arguments so that intermediate states remain hidden. This lesson is about structure, not privacy.

## Ship It

This lesson ships a reusable review checklist:

- `outputs/recursive-proof-review-checklist.md`

Use it when evaluating an IVC or recursive SNARK implementation to check: genesis binding, step counter inclusion, accumulator field reduction, O(1) vs O(n) verification mode, and zero-knowledge properties of the accumulator.

## Exercises

1. **Easy.** Run `python3 code/main.py`. Confirm the step verifier returns `True` for honest transitions and `False` for each tampered variant. Trace through the accumulator values by hand for the first two steps using `p=101`.
2. **Medium.** Replace `step_fn` with a different transition: `F(z) = (z^3 + 1) % p`. Rerun `ivc_verify_full` and confirm the chain still verifies correctly. What changes in the `proof_size`?
3. **Hard.** Implement a "split verify" mode: given a proof `π_n` and a claimed intermediate state `π_k` (for `k < n`), verify that `π_k` is a valid prefix of `π_n` by (a) checking `π_n` is reachable from `π_k` in `n-k` steps and (b) checking `π_k` is reachable from `z_0` in `k` steps. How does this compare to running `ivc_verify_full` once?

## Key Terms

| Term | What people say | What it actually means |
|------|-----------------|------------------------|
| IVC | "Incrementally Verifiable Computation" | A scheme where each new proof step produces a constant-size proof that implicitly verifies all prior steps. |
| Accumulator | "The running hash / folded instance" | A fixed-size value that cryptographically binds the entire computation history up to step `n`. |
| Folding scheme | "Nova-style recursion" | A technique that merges two constraint-system instances into one relaxed instance without generating a full proof per step, enabling O(1) IVC without expensive recursive SNARK verification. |
| Cycle of curves | "Pallas/Vesta, MNT curves" | A pair of elliptic curves where the scalar field of each equals the base field of the other, enabling recursive proof verification inside arithmetic circuits. |
| Step verifier | "Local consistency check" | A verifier that checks only one transition `(π_n, π_{n+1})` in O(1), without replaying the full history from `z_0`. |

## Further Reading

- Valiant, *Incrementally Verifiable Computation or Proofs of Knowledge Imply Time/Space Efficiency* (TCC 2008) — the original IVC definition and construction.
- Kothapalli, Setty, Tzialla, *Nova: Recursive Zero-Knowledge Arguments from Folding Schemes* (CRYPTO 2022) — the folding-scheme approach that makes IVC practical without pairing-based recursion.
- Boneh, Drake, Fisch, Gabizon, *Halo Infinite: Proof-Carrying Data from Additive Polynomial Commitments* (CRYPTO 2021) — how accumulation schemes generalize IVC to arbitrary proof systems.
