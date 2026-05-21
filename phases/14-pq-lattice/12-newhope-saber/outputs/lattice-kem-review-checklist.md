---
name: Lattice KEM Review Checklist (Noise vs Rounding)
description: Practical checklist for reviewing RLWE/RLWR-style KEM code paths: sampling, rounding, encoding/decoding, compression, and transcript binding.
phase: 14-pq-lattice
lesson: 12-newhope-saber
---

# Lattice KEM Review Checklist (Noise vs Rounding)

Use this when reviewing a PR that touches NewHope/Saber/Kyber-style code (or any LWE/LWR-derived KEM), especially around sampling, rounding, compression, and key derivation.

## 0) Identify the scheme pattern

- Is the core assumption LWE/RLWE (sampled error) or LWR/RLWR (rounding noise)?
- Is it ring-based (one polynomial) or module-based (vector/matrix of polynomials)?
- What are the moduli (`q`, and possibly `p`/`t`) and what is their relationship?
  - If `p|q`, rounding/lifting should look like “add half then shift/divide”.

## 1) Sampling & randomness

- RNG source: is the entropy source appropriate for the environment (OS RNG, DRBG, etc.)?
- Domain separation: are different purposes tagged distinctly?
  - Examples: `a` expansion, secret sampling, error sampling, ephemeral coins, KDF.
- Rejection sampling correctness (when sampling uniform mod `q`):
  - Is there a bias bound or exact rejection threshold?
  - Are rejections bounded (no DoS risk)?

## 2) Encoding/decoding correctness

- Message embedding:
  - RLWE PKE often embeds bits as coefficients near `{0, q/2}` (or `{0, (q+1)/2}` depending on scheme).
  - LWR PKE often embeds bits near `{0, p/2}` after rounding.
- Decoding rule is consistent with embedding:
  - “closest center” logic should be correct in modular distance.
  - Ensure the code is not mixing centered representatives with raw `0..q-1` arithmetic incorrectly.

## 3) Rounding, compression, and lifting (LWR-heavy code)

- Rounding definition:
  - Is the scheme doing “round-to-nearest bucket” (add half step then divide), not just floor?
- Lift definition:
  - Lifting back to `q` should map a `p` value to a representative bucket center (or scheme-specific choice).
- Round/lift consistency:
  - `round(lift(x)) == x` should hold (mod `p`) for all inputs in the `p` domain.
- Bias audit:
  - Is there any consistent bias introduced by always rounding ties one direction?
  - Are constants chosen to match the spec (common off-by-one pitfalls)?

## 4) Side channels (always)

- Are secret-dependent branches/memory access patterns avoided in:
  - sampling (especially rejection loops),
  - decoding,
  - re-encryption checks (FO-style transforms),
  - polynomial multiplication routines?
- Any “debug prints” or timing-dependent logs around secret paths should be treated as a hard stop.

## 5) CCA transform & transcript binding

If the construction is meant to be a KEM:
- Is there an explicit transform (often FO-style) that:
  - derives coins from a hash of `(pk, msg, context)`,
  - re-encrypts and compares ciphertexts on decapsulation,
  - derives the final shared key from a hash of `(msg, ct, context)`?
- Is the context string/domain tag stable (protocol version, KEM ID, suite ID)?

## 6) Test coverage expectations

- Vector tests for:
  - polynomial multiplication,
  - sampling determinism under fixed seeds (for tests),
  - rounding/lifting,
  - encoding/decoding.
- Property tests for:
  - distributivity/associativity (within reason),
  - roundtrip encrypt/decrypt under multiple messages/seeds,
  - range checks on sampled noise.

## 7) Red flags (escalate immediately)

- Any seed reuse across roles without domain separation.
- “Round” implemented as plain floor without the half-step constant (unless the spec explicitly says floor).
- Decoding based on raw comparisons that ignore modular wrap-around.
- Treating a toy prototype as production-ready (“just ship it”) or removing constant-time protections for speed.

