---
name: Schnorr Signature Audit Checklist
description: A practical checklist for reviewing Schnorr-like signature schemes (Schnorr, EdDSA, BIP340) in specs and code.
phase: 08-classical-asymmetric
lesson: 08-schnorr
---

# Schnorr Signature Audit Checklist

Use this when reviewing a design doc, implementation, or PR that claims to implement Schnorr (or a Schnorr-like scheme such as EdDSA / BIP340). The goal is to catch the real-world failure modes: nonce mistakes, hashing/encoding ambiguities, and missing validation.

## 1) Identify the exact scheme
- [ ] Which scheme is it exactly (Schnorr over a prime-field subgroup, Ed25519/EdDSA, BIP340 secp256k1, or a custom variant)?
- [ ] What are the exact signing equations (what is hashed into the challenge, and how is `s` formed)?
- [ ] What is the signature format on the wire (bytes layout, endian, fixed vs variable length)?

## 2) Nonce generation (the most important section)
- [ ] Nonce `k` is generated using a **CSPRNG** or a **deterministic construction** defined by a standard (e.g., RFC 6979-style or scheme-specific).
- [ ] Nonce derivation has **domain separation** (protocol name + context) so the same key used in multiple places does not reuse nonce material.
- [ ] Nonce derivation includes the **message** (or its hash) and **private key** in a way that prevents reuse across different messages.
- [ ] There is no path where `k` can become `0 (mod q)` or otherwise invalid; error handling is explicit.
- [ ] The code never accepts a caller-supplied `k` in production paths (test hooks must be clearly separated).

Red flags:
- `k = hash(message) mod q` (missing private key)
- `k = random.randint(...)` with a non-cryptographic RNG
- “We seed the RNG once at startup” (fork/VM snapshot reuse risk)

## 3) Hashing and challenge computation
- [ ] The hash function is specified (e.g., SHA-256) and consistent across all implementations.
- [ ] Hash-to-scalar conversion is well-defined (bit truncation / reduction modulo group order).
- [ ] The challenge `e` hashes an **unambiguous encoding** of all inputs (avoid naive string concatenation).
- [ ] There is explicit **domain separation** for the challenge hash (different from nonce derivation).

Questions to ask:
- What exact bytes are hashed for `e`?
- Are lengths fixed or length-tagged?

## 4) Encoding rules (ambiguity kills)
- [ ] Public keys have a canonical encoding; decoders reject non-canonical forms.
- [ ] Signatures have a canonical encoding; decoders reject non-canonical forms.
- [ ] Integers/scalars are fixed-length encodings (or length-tagged) with an explicit endianness.

Red flags:
- Variable-length integer encodings without length tags
- Accepting multiple encodings for the same value (“be liberal in what you accept”)

## 5) Group and key validation
- [ ] Group parameters are fixed by a standard or generated with a documented, auditable process.
- [ ] Public keys are validated as being in the correct group/subgroup (curve checks for EC, subgroup checks where relevant).
- [ ] Inputs are range-checked before inversion/division steps.
- [ ] The implementation rejects degenerate keys/points (identity / small subgroup points where applicable).

## 6) Malleability and uniqueness
- [ ] The scheme defines whether multiple signatures can verify for the same message/key.
- [ ] If canonicalization is required (e.g., low-`s`-style rules), it is applied consistently.
- [ ] Signature verification is strict and rejects “alternate” encodings.

## 7) Side channels and operational concerns
- [ ] Signing is implemented in constant-time (or uses a library that guarantees it).
- [ ] No secret-dependent branches/memory accesses on private scalars or nonces.
- [ ] Secrets are not logged, not formatted into exceptions, and not serialized accidentally.
- [ ] Test vectors exist and cover edge cases (zero/one boundaries, invalid encodings, invalid public keys).

## 8) Minimal test plan (copy/paste into a PR checklist)
- [ ] Sign/verify roundtrip tests pass for known vectors.
- [ ] Verification fails on a 1-byte message change.
- [ ] Verification rejects out-of-range scalars and non-canonical encodings.
- [ ] Nonce determinism test: signing the same message with the same key is reproducible (only if the scheme is deterministic).
- [ ] Nonce-reuse test hook (test-only): two signatures forced to reuse `k` demonstrate private-key recovery in a toy setting (to prove the risk is understood).

## 9) Recommendations
- If you need Schnorr in production, prefer a mature, reviewed library and an established scheme (Ed25519/EdDSA or BIP340), and follow the exact specification (hashing, domain separation, and encoding) byte-for-byte.

