---
name: Regev PKE / LWE Encryption Review Checklist
description: Practical checklist for reviewing Regev-style LWE encryption code paths, parameter/encoding choices, and common failure modes.
phase: 14-pq-lattice
lesson: 04-regev-encryption
---

# Regev PKE / LWE Encryption Review Checklist

Use this when reviewing a PR that introduces or modifies “LWE/Regev-style encryption”, or when translating a PKE mental model into a KEM-DEM design (like ML-KEM/Kyber).

This checklist is about catching the mistakes that turn “math that looks right” into broken cryptography or broken reliability.

## 0) Inputs you must have

- A precise scheme reference: Regev PKE vs Dual-Regev vs MLWE/RLWE KEM (don’t mix shapes implicitly).
- The exact parameter set (n, m, q, error distribution, encoding) and where it came from (standard / paper / internal).
- At least one known-good end-to-end test vector (keygen → encrypt → decrypt) that runs in CI.

If any of these are missing, stop: you cannot review correctness or security.

## 1) Correctness invariants (easy to get subtly wrong)

- Public key construction matches: `b = A·s + e (mod q)` with intended shapes:
  - `A ∈ Z_q^{m×n}`, `s ∈ Z^n`, `e ∈ Z^m`, `b ∈ Z_q^m`.
- Encryption matches the intended variant:
  - `u = A^T·r + e1 (mod q)`
  - `v = b^T·r + e2 + Encode(m) (mod q)`
- Decryption removes the structured term:
  - `x = v - <u, s> (mod q)`
  - decision/decoding uses a clearly specified rule (e.g., circular distance to `0` vs `q/2` for bit encryption).

## 2) Noise + encoding checks (reliability is part of security)

- Confirm the encoding separation is large enough:
  - for bit encryption: targets are `0` and `q/2` (or equivalent), not “nearly adjacent” values.
- Confirm the total noise budget is bounded and documented:
  - how large can `<e1, s>`, `<r, e>`, and `e2` get?
  - does decryption still decode correctly in the worst case?
- Confirm “wrap-around” is explicitly considered:
  - failures happen when the phase crosses a midpoint modulo `q` and becomes closer to the wrong target.

If the code has no explanation of why decryption is correct for the chosen parameters, treat as a high-risk change.

## 3) Randomness and domain separation

- Ensure each role uses appropriate randomness:
  - keygen randomness for `A`,
  - encryption randomness for `r`, `e1`, `e2`,
  - any symmetric key/nonce material (if hybrid).
- Ensure domain separation:
  - do not reuse the same seed/key for “PRNG”, “hashing”, and “keystream” without clear domain tags.
- Ensure determinism is only used for tests/vectors:
  - test-only deterministic RNGs must not be used in production paths.

## 4) Side channels (production-blocking red flags)

- Noise sampling and decoding must be constant-time (or use a vetted constant-time library).
- Avoid secret-dependent branching or indexing on `s` and on intermediate values derived from `s`.
- Avoid timing leaks in:
  - rejection sampling,
  - decoding thresholds,
  - conditional reductions.

If the implementation is “from scratch”, assume it is not side-channel safe until proven otherwise.

## 5) Serialization and malleability

- Ensure a canonical encoding for all vectors/matrices (endianness, signed vs unsigned, range checks).
- Enforce bounds on received ciphertext components:
  - reject out-of-range values instead of silently reducing mod q (unless the spec says otherwise).
- If the scheme is used as a KEM-DEM:
  - authenticate ciphertexts (AEAD or explicit MAC); raw PKE malleability is a footgun.

## 6) “Do we really want Regev PKE here?”

In most real systems you should not implement Regev PKE directly.

- If the PR is educational / demo-only, keep it isolated and labeled.
- If the PR targets production, prefer standardized KEMs and vetted implementations:
  - ML-KEM (Kyber) for MLWE,
  - FrodoKEM for plain LWE assumptions.

## 7) Quick grep-able failure patterns

- `q` changed without updating noise/encoding logic.
- Encoding uses `q/2` with an odd `q` but decoding assumes symmetric halves without specifying tie-breaking.
- RNG seeding from timestamps, PIDs, or other low-entropy sources.
- “Works on my machine” tests with no deterministic vectors.

