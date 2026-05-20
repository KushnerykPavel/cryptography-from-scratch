---
name: skill-pinocchio-review
description: Review Pinocchio/Groth16-style (QAP-based) SNARK implementations and designs
phase: 12
lesson: 4
---

You are reviewing code or a design doc that claims to implement a Pinocchio/Groth16-style SNARK (R1CS → QAP → pairing-based verification).

Your goal: catch “it seems to work” bugs that silently destroy soundness or zero-knowledge.

## Fast mental model (keep in working memory)

1. The circuit becomes R1CS constraints: `(A_i·w) * (B_i·w) = (C_i·w)` over a prime field.
2. R1CS columns become polynomials `A_j(x),B_j(x),C_j(x)` via interpolation over constraint indices.
3. A witness `w` defines `A(x),B(x),C(x)` as linear combinations using the same coefficients `w_j`.
4. Correctness becomes divisibility: `P(x) = A(x)B(x) − C(x)` must be divisible by `Z(x)` (the vanishing polynomial for the constraint domain).
5. The verifier can’t see polynomials, so the prover commits to evaluations at a hidden point `τ` and proves:
   - the divisibility check holds “in the exponent”
   - the committed `A(τ),B(τ),C(τ)` are consistent with the same witness coefficients (the anti-forgery part)

If a design doesn’t explicitly cover both divisibility and consistency-binding, it’s incomplete.

## Review checklist

### Arithmetization correctness
- Are all computations performed in a field `F_p` (or `F_r` for curve order), not integers?
- Is there an explicit constant wire `1` in the witness so constants and equalities can be expressed?
- Are public inputs/outputs separated from private witness values, with a clear order and indexing rule?
- Are constraints exhaustive (no “unused” wires that can float unconstrained)?

### R1CS → QAP reduction
- Is the interpolation domain specified (e.g., points `1..m` or roots of unity), and consistent everywhere?
- Is the vanishing polynomial `Z(x)` built for the same domain used for interpolation?
- Is `P(x)` defined consistently (`A·B − C` vs `C − A·B`), and does the division match that convention?
- Are degrees bounded as expected (polynomials should be degree `< m` before multiplication)?

### Proof soundness (the “you can’t fake it” part)
- Does the verifier check more than a single equality at `τ`?
  - A prover can always fabricate `A(τ),B(τ),C(τ),H(τ)` that satisfy `A(τ)B(τ)−C(τ)=H(τ)Z(τ)` unless they are bound to a witness.
- Is there an explicit mechanism that binds *the same witness coefficients* across `A,B,C` (KoE/KoC-style consistency checks or equivalent)?
- Are public input polynomials checked against the verifier’s claimed inputs/outputs (so the prover can’t “prove a different statement”)?

### Zero-knowledge (the “you don’t learn w” part)
- Are witness-dependent terms blinded (random scalars) per proof, not per circuit?
- Is there a clear statement of what information is leaked by the proof elements (size, metadata, deterministic structure)?
- Are RNG requirements explicit and tested (CSPRNG, seeding rules, deterministic mode for tests)?

### Setup / CRS / ceremony
- Is this a trusted setup SNARK? If yes:
  - Is the toxic waste story explicit (what secrets must be destroyed)?
  - Are CRS elements labeled and derived from a single trapdoor `τ` (and possibly α/β/δ/… depending on the variant)?
  - Is the CRS domain-separated per circuit (so you can’t reuse parameters across different circuits unless intended)?
- If the design claims “universal” setup, does it actually match a universal/updatable SRS model (and not a per-circuit CRS)?

### Engineering pitfalls that break real systems
- Serialization: are group elements checked for subgroup membership and correct encoding?
- Hash-to-field / Fiat–Shamir: are transcripts domain-separated and stable across languages?
- Constraint counting: off-by-one errors in domain size and vanishing polynomial roots.
- “Helper optimizations” that accidentally skip constraints when generating QAP polynomials.
- Inconsistent indexing between prover and verifier for the public input vector.

## What to ask for in a PR

1. A small fixed circuit example with a hand-checkable witness and a failing witness.
2. Deterministic test vectors for the R1CS→QAP reduction (polynomials and/or evaluations at fixed points).
3. A negative test proving that “evaluation-only forging” fails in the real scheme (i.e., consistency checks are active).
4. A short threat model: what assumptions are being made (pairing model + KoE/KoC variants, hash assumptions, CRS assumptions).
