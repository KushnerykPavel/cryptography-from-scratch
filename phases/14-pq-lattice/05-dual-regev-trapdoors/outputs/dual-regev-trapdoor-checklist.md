---
name: Dual Regev Trapdoor Review Checklist
description: Practical checklist for reviewing implementations that rely on short preimages Ax=y (mod q), gadget matrices, and trapdoor preimage sampling (Dual Regev / IBE / ABE / signatures).
phase: 14-pq-lattice
lesson: 05-dual-regev-trapdoors
---

# Dual Regev Trapdoor Review Checklist

Use this as a PR review checklist (or as a design doc template) for any codebase that claims:

- “the secret key is a short preimage `x` such that `A x = y (mod q)`”
- “we use a gadget matrix `G` and gadget decomposition”
- “we generate `A` with a trapdoor and can sample short preimages”

> Educational reminder: from-scratch implementations are rarely constant-time and are easy to break via side-channels or distributional bugs. Prefer audited libraries and published parameter sets.

## 1) Correctness invariants (must be unit-tested)

- Shapes are consistent and asserted:
  - `A` is `n x m`, `x` is length `m`, `y` is length `n`
  - gadget width `w = n*k` where `k = ceil(log2(q))` (or base-`B` analog)
- Core identity holds:
  - gadget trapdoor: `A * T == G (mod q)` (or `A * [R; I] == H*G (mod q)` for tagged variants)
- Preimage sampling is correct:
  - for random targets `y`, sampled `x` satisfies `A x == y (mod q)`
- Dual Regev decrypt cancels the `s^T y` term:
  - decryption computes `raw = (c2 - c1^T x) mod q`
  - decoding `raw` recovers the message for the intended noise bound

## 2) Distribution and security properties (the “trapdoor bugs” section)

- Deterministic preimages are forbidden in production:
  - `x = T * G^{-1}(y)` is a correctness proof, not a secure sampler
  - production must use randomized (typically discrete-Gaussian) preimage sampling so `x` does not reveal trapdoor structure
- Trapdoor matrix entries are bounded:
  - `R` (or trapdoor basis) must be sampled from the scheme’s stated distribution and size bounds
  - “small” must be quantified (e.g., max-norm, spectral norm, or sigma parameters)
- Public matrix indistinguishability is addressed:
  - if `A` is constructed from structured pieces, there is an argument (and citation) that it is statistically/computationally close to uniform

## 3) Noise budget checks (the “will it decrypt?” section)

- The implementation computes or documents a decryption noise budget:
  - dual Regev noise typically includes an inner product like `e^T x` plus `e'`
- It is clear what happens on decryption failure:
  - do you return an error, a random bit, or leak information through timing?
  - constant-time decode path if the threat model includes side channels

## 4) Modulus and decomposition choices

- Gadget decomposition matches the modulus:
  - bit decomposition is only an exact gadget inverse in special settings (e.g., `q=2^k`)
  - if `q` is not a power of two, the decomposition/inversion algorithm must match the scheme
- Encoding is unambiguous:
  - message embedding is consistent (e.g., add `floor(q/2)` for bit `1`)
  - decoding uses *circular distance* on `Z_q`, not naive integer distance

## 5) “Red flags” (ask for changes before approving)

- “We use `x = T * G^{-1}(y)` directly in signatures / keys / APIs.”
- “We sampled `R` with large integers (or with `randrange(q)`) and called it ‘small’.”
- “No tests for `A*T == G (mod q)` and no tests for `A*x == y (mod q)`.”
- “No documented noise bounds; correctness ‘seems to work’ for some samples.”
- “Matrix/vector transposes are implicit and not covered by shape assertions.”

## 6) Minimal test suite you can request in a PR

- Deterministic vectors for `G`, decomposition, and one small trapdoor instance
- Property tests:
  - decomposition roundtrip on random `y`
  - `A*T == G (mod q)`
  - `A*preimage(y) == y (mod q)` for many random `y`
  - encrypt/decrypt roundtrip for a range of noise levels

## 7) Copy/paste PR review prompt (for an LLM)

Paste this into your LLM of choice along with the diff:

> Review this PR as a cryptography engineer. Focus on: (1) dimension/shape correctness, (2) modular arithmetic correctness, (3) whether the preimage sampling is randomized and distributionally safe (not deterministic `T*G^{-1}`), (4) noise budgeting and decode correctness, (5) side-channel risks. List concrete issues and propose targeted tests.

