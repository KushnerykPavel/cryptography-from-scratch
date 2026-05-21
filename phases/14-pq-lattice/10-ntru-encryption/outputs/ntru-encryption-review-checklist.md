---
name: NTRU Encryption Review Checklist
description: PR-review checklist for NTRU / NTRU-like PKE/KEM code (correctness, decryption failures, CCA transforms, and side channels).
phase: 14-pq-lattice
lesson: 10-ntru-encryption
---

# NTRU Encryption Review Checklist

Use this checklist when reviewing any code that implements, wraps, or parameterizes NTRU-family encryption/KEMs (classic NTRUEncrypt, NTRU Prime/sntrup, or custom “NTRU-like” constructions).

## 1) Construction clarity

- Is this **PKE** (encrypt/decrypt) or a **KEM** (encaps/decaps)? Production code should almost always be a KEM with a standard transform.
- If it’s PKE: what is the **threat model** (CPA vs CCA)? What prevents chosen-ciphertext attacks?
- Are the exact rings and moduli stated precisely (e.g., `R_q = (Z/qZ)[x]/(x^N - 1)` or an NTRU Prime ring)?

## 2) Parameters + sampling

- Are parameter sets **standardized / vetted** (not ad-hoc “seems big enough”)?
- Are sampling distributions exact and constant-time?
  - Small polynomials: how are coefficients sampled (ternary, centered binomial, bounded uniform)?
  - Are “weights” fixed, bounded, and validated?
- Are there explicit bounds ensuring correctness (or proofs/claims from a spec)?
  - If decryption relies on “center-lift then reduce,” what bounds ensure coefficients don’t wrap mod `q`?

## 3) Inversion and ring operations

- How is polynomial inversion performed?
  - Is it constant-time for all secret-dependent branches?
  - Are there rejection-sampling loops for invertibility? If so, are they constant-time or otherwise mitigated?
- Are ring multiplications implemented correctly for the chosen ring?
  - Cyclic ring (`x^N - 1`) vs other moduli (e.g., NTRU Prime variants).
  - Any “folding”/reduction steps are correct and tested.

## 4) Decryption failures (correctness + security)

- Can decryption ever fail?
  - If “no,” where is that guaranteed (parameter set + proof)?
  - If “yes,” what is the failure probability and how is it justified?
- Failure behavior must be **indistinguishable**:
  - constant-time path on success vs failure,
  - identical memory access patterns,
  - no distinct logging, metrics, or error strings.
- Are failures handled using a standard, proven transform (typical in KEMs)?

## 5) CCA security and transforms

- If using a CCA transform (e.g., Fujisaki–Okamoto style), is it:
  - implemented exactly as specified,
  - using domain-separated hashes,
  - using verified encoding/decoding and rejection logic?
- Are there any ad-hoc “hash the ciphertext and hope” shortcuts?

## 6) Side channels

- Constant-time: arithmetic, branching, and table lookups must not depend on secrets.
- Microarchitectural issues: does the implementation claim mitigations (timing, cache, branch predictor)?
- Are secret polynomials kept in memory safely (zeroization where required, no accidental copies)?

## 7) Interop + encoding

- Are serialization formats fixed and validated?
- Is there strict validation on input ciphertexts/encapsulated values?
- Are there test vectors from the target standard/library?

## Red flags (stop-the-line)

- “Decryption failures are fine; we just return an error quickly.”
- “We tweaked parameters for performance” without a security/correctness argument.
- Non-constant-time inversion/sampling on secret data.
- Undocumented encoding rules (“it works on our test cases”).
- Custom CCA transform.

## Questions to ask in a PR review

1. Which standard/spec are you implementing? Link it.
2. Which parameter set is used and where is it defined?
3. What is the failure behavior and why is it safe?
4. Where is constant-time guaranteed (or audited)?
5. Which vectors/known-answer tests prove interop?

