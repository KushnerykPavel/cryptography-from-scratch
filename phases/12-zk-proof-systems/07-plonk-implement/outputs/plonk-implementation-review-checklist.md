---
name: "PLONK Implementation Review Checklist"
description: "A practical audit checklist for PLONKish code: gates, copy constraints, transcripts, and openings."
phase: "12-zk-proof-systems"
lesson: "07-plonk-implement"
---

# PLONK Implementation Review Checklist

Use this as a PR-review / audit prompt whenever a change touches a PLONKish prover/verifier (Halo2/UltraPlonk/etc.). It’s optimized for catching “it compiles but proofs are unsound” mistakes.

## 1) Scope: what *kind* of PLONK is this?

- Which arithmetization is used: “classic” PLONK, TurboPLONK, UltraPLONK, Halo2-style, “Honk”-family?
- Which commitment scheme: KZG, IPA, FRI/STARK-ish hybrid?
- Which lookup argument (if any): Plookup, Halo2 lookups, custom tables?
- Which transcript hash: Blake2, SHA-256, Poseidon, Rescue, etc.?

## 2) Gate constraints (the generic gate)

Verify the exact identity implemented matches the intended gate:

- Is the gate equation exactly: `qL*A + qR*B + qM*A*B + qO*C + qC = 0` (or your scheme’s variant)?
- Are selector polynomials fixed (preprocessed) and bound into the transcript?
- Are public inputs wired correctly (separate column / fixed values / instance polynomials)?
- Padding: do unused rows have selectors that force the identity to hold (usually all zero)?

## 3) Copy constraints (permutation argument)

- Does the wiring/permutation cover *every* cell that must be constrained equal?
- Are cycles correct (no “almost” cycles that leave one cell dangling)?
- Are the “identity tags” for cells constructed consistently (domain point + column separation constants)?
- Does the grand product `Z` satisfy required boundary constraints (`Z(1)=1`, `Z(ω^n)=1` or scheme equivalent)?
- Are `β, γ` challenges derived *after* all required transcript absorbs (witness commitments, σ commitments, etc.)?

## 4) Quotient / vanishing polynomial checks

- Is the vanishing polynomial `Z_H(X) = X^n - 1` correct for the evaluation domain?
- Is divisibility by `Z_H` checked correctly (or, in KZG/IPA, is the quotient polynomial computed and opened correctly)?
- Are all constraints combined with the right powers of `α` (or equivalent randomizers)?

## 5) Transcript / Fiat–Shamir hazards

- Is every prover message that influences verification absorbed before sampling the next challenge?
- Is domain separation used (labels / prefixes) to avoid cross-protocol collisions?
- Are challenges reduced mod the scalar field (not accidentally mod the base field)?

## 6) Soundness / ZK footguns (high-level)

- Does the prover add required blinding terms / randomizers to preserve zero-knowledge?
- Are “special points” (like `ζ`, `ωζ`) handled without leaking witness values through division-by-zero?
- Are there checks preventing malformed proofs (wrong lengths, non-canonical field elements, invalid curve points)?

## 7) Testing expectations

- Unit tests cover: gate identity, permutation identity, boundary constraints on `Z`, transcript order, and failure cases.
- A small “toy circuit” test exists to make debugging permutations tractable.
- Property tests exist for random circuits/witnesses (within constraints) and for rejected invalid witnesses.

## Quick PR-review prompt (copy/paste)

“Please walk me through: (1) which messages go into the transcript and in what order, (2) which polynomial identities are enforced, and (3) which boundary conditions are asserted (especially for the permutation grand product).”

