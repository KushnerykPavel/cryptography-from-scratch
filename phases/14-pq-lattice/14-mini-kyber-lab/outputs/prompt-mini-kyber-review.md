---
name: Mini Kyber / ML-KEM Integration Review Checklist
description: Paste this into a PR review to sanity-check ML-KEM (Kyber) integrations: randomness, domain separation, serialization, compression, and constant-time failure handling.
phase: 14-pq-lattice
lesson: 14-mini-kyber-lab
---

# ML-KEM (Kyber) integration review — checklist + prompts

Use this when reviewing a PR that adds or modifies ML-KEM/Kyber usage (TLS, hybrid key exchange, encrypted messaging, key wrapping, etc.).

## 1) What is being built?

- What security goal is claimed: IND-CCA KEM, hybrid KEM+ECDH, or raw encryption?
- Which standard/library is used (spec name + version, library name + commit/tag)?
- What’s the wire format: exactly which bytes are sent/stored (pk, ct, shared secret, context)?

## 2) Randomness + domain separation

- Where does entropy come from (OS RNG, HSM, enclave)? Is failure handled?
- Are *all* required random inputs present (e.g., coins for encapsulation)?
- If a SHAKE/PRG is used internally, is it domain-separated per purpose (A sampling vs noise vs hashing vs packing)?
- Is any seed reused across roles or sessions?

## 3) Serialization + compression correctness

- Are packing/bit orders explicitly specified (little-endian vs big-endian) and tested?
- Are compressed values rounded exactly as the spec says (rounding constant, ties, masks)?
- Are there cross-language tests (Rust↔C, Go↔C, etc.) that ensure byte-for-byte compatibility?
- Are there “negative tests” for malformed inputs (wrong length, non-canonical encodings, out-of-range coefficients)?

## 4) Failure handling (side-channel hot zone)

- Does decapsulation ever branch on secret-dependent values?
- Are error paths constant-time and indistinguishable (timing + logs + returned error codes)?
- Is the “shared secret on failure” behavior spec-accurate and tested?
- Are there metrics/logs that could leak failure patterns in production?

## 5) Key lifecycle + memory hygiene

- Are secret keys zeroized on drop/free (where applicable)?
- Are shared secrets treated as key material (no logs, no metrics, no exceptions)?
- Are long-lived keys stored with correct permissions / keystore usage?

## 6) Protocol composition

- If hybrid (e.g., ECDH + ML-KEM): is the KDF construction explicit and reviewed?
- Is there transcript binding / context binding (e.g., include protocol IDs in KDF inputs)?
- Are downgrade protections present (no silent fallback to classical-only)?

## 7) Tests you want to see in the PR

- Known-answer tests (KATs) from the standard or a trusted test vector set.
- Roundtrip tests: `encaps(pk)` then `decaps(sk, ct)` matches *exactly*.
- Fuzz/robustness: malformed ciphertexts never crash; failure behavior is correct.
- Cross-impl compatibility tests if a wire format is involved.

## 8) “Explain it back” prompts (for the author)

Ask the author to answer these in the PR description:

1. What is the exact threat model (passive vs active attacker)?
2. Where does chosen-ciphertext security come from in this construction?
3. What bytes go on the wire and how are they encoded?
4. Where is randomness sourced and how do we handle RNG failure?
5. What was done to prevent side-channel leakage in decapsulation/failure paths?

