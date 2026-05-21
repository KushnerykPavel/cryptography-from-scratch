---
name: "ML-DSA (FIPS 204) Implementation Review Checklist"
description: "A practical checklist for auditing ML-DSA (formerly Dilithium) implementations and integrations."
phase: "14-pq-lattice"
lesson: "08-dilithium-ml-dsa"
---

# ML-DSA (FIPS 204) Implementation Review Checklist

Use this checklist for PR reviews, vendor due diligence, or internal audits when you ship ML-DSA (ML-DSA-44 / ML-DSA-65 / ML-DSA-87).

## 1) Scope & conformance

- [ ] The code targets **FIPS 204 ML-DSA**, not “Dilithium 3.1” by name alone (check interop expectations; FIPS 204 documents differences).
- [ ] The parameter set is explicit and stable (`ML-DSA-44`, `ML-DSA-65`, or `ML-DSA-87`), not inferred from key length.
- [ ] The implementation clearly specifies whether it supports:
  - [ ] `ML-DSA.Sign` (pure)
  - [ ] `HashML-DSA.Sign` (pre-hash variant)
  - [ ] deterministic vs hedged (randomized) signing
- [ ] Domain separation / context string handling matches the spec and your protocol (avoid cross-protocol signature replay).

## 2) Correctness-critical checks (must exist)

- [ ] Verification checks the response bound: `||z||∞ < γ1 - β`.
- [ ] Verification checks the hint weight bound: `#ones(h) ≤ ω`.
- [ ] Verification recomputes the challenge from exactly the same material the signer used (message representative + encoded `w1`).
- [ ] Signing includes the required **rejection sampling loop** and does not “force” success by clipping/rounding values.
- [ ] Signing rejects when `w1` would not match the verifier’s reconstructed `w1` (the “rounding mismatch” condition).

## 3) Encoding / decoding safety

- [ ] The encoding format is **canonical**: every valid signature/public key has exactly one byte encoding.
- [ ] Decoding rejects:
  - [ ] out-of-range coefficients
  - [ ] non-canonical bit patterns
  - [ ] hint vectors with malformed positions / duplicates
  - [ ] wrong lengths (no silent truncation/extension)
- [ ] The hash input uses a well-defined encoding of polynomials/vectors (no “stringifying arrays” or locale-sensitive formatting).

## 4) Randomness & nonce handling

- [ ] Nonces/masks are generated from an XOF/PRF as specified (and are not `random()` / OS RNG calls sprinkled into math code).
- [ ] If “deterministic signing” is offered:
  - [ ] It is clearly labeled and conforms to the spec’s deterministic mode
  - [ ] There is an option for hedged signing when the threat model demands it
- [ ] The implementation is robust to RNG failure modes (documented behavior, safe defaults).

## 5) Side-channel and leakage considerations

- [ ] No data-dependent branches/memory access on secrets in core operations (sampling, NTT/mul, packing, norm checks).
- [ ] Rejection sampling does not leak secrets via observable timing (or the implementation documents mitigations).
- [ ] Key material is zeroized where appropriate (especially long-lived services).

## 6) Interop & test strategy

- [ ] Known-answer tests (KATs) are present and run in CI.
- [ ] Negative tests exist (reject malformed signatures/keys).
- [ ] Cross-implementation interop is tested against at least one independent implementation (e.g., OpenSSL, liboqs, a reference implementation).

## 7) Operational integration checks

- [ ] Key sizes, signature sizes, and verification cost are measured in your target environment (latency + throughput + memory).
- [ ] Certificate / container formats are chosen consciously (X.509, CMS, COSE, SSH keys, etc.).
- [ ] Migration plan includes algorithm agility (ability to rotate parameter sets and handle multiple PQ schemes).

## Red flags (stop-ship until resolved)

- “It verifies, so it’s fine” without explicit `z` bound checks and hint-weight checks.
- Any acceptance of non-canonical encodings (“we just mask bits off”).
- Removing rejection sampling because it “sometimes retries”.
- Mixing “Dilithium 3.1” and “FIPS 204 ML-DSA” artifacts without explicit compatibility testing.

