---
name: "SPHINCS+ / Stateless Hash-Based Signatures: PR Review Checklist"
description: "A copy-paste checklist for reviewing SPHINCS+ (aka SLH-DSA lineage) integrations: parameters, encoding, domain separation, and operational pitfalls."
phase: "15-pq-code-hash-multivariate"
lesson: "08-sphincs-plus"
---

# SPHINCS+ / Stateless Hash-Based Signatures — PR Review Checklist

Use this when reviewing or designing an integration that claims “SPHINCS+”, “SLH-DSA”, or “stateless hash-based signatures”.

## 0) Quick Triage (5 minutes)

- What is the goal: long-term identity signatures, code signing, KMS-backed signing, or ephemeral session tokens?
- Do we actually need stateless hash-based signatures, or would stateful XMSS/LMS be acceptable (smaller signatures, but state management)?
- What signature size and verify-time budget is acceptable for the product?

## 1) Parameters and Algorithm Identity

- Parameter set is explicitly named and fixed (no “custom tuning” in production).
- Algorithm identifiers are explicit in protocol messages (avoid “algorithm confusion”).
- Public key, signature, and private key sizes are asserted and tested (including boundary cases).

Red flags:
- “We changed `n`/tree heights/winternitz to make it faster” without a full cryptographic rationale.
- “We accept any parameter set sent by the peer” in a handshake protocol.

## 2) Encoding and Canonicalization

- Public key encoding is canonical (single accepted form).
- Signature encoding is canonical and rejects:
  - wrong lengths
  - non-canonical integers / indexes
  - extra trailing bytes
- Hash input encoding is unambiguous (length-prefixed fields or a strict structured encoding).

## 3) Domain Separation / Addressing

- Every hash invocation is domain-separated by:
  - purpose tag (e.g., leaf vs parent vs PRF)
  - address / context (tree index, layer, chain index, etc.)
- There is a written mapping from “spec primitives” to implementation functions:
  - PRF / expand
  - WOTS chain function
  - Merkle parent hash
  - message hashing and randomization

Red flags:
- Reusing the same hash call for multiple roles without tags/addresses.
- Concatenating fields without length-prefixing.

## 4) Statelessness and One-Time Key Safety

Even though SPHINCS+ is stateless, implementations can accidentally reintroduce “one-time key reuse” hazards:

- No caching that reuses WOTS+ secret key material across signatures.
- Any per-signature randomness (`R` in SPHINCS+ style designs) is generated correctly:
  - CSPRNG-backed, or deterministic-from-secret with a proper PRF construction
  - never all-zero or constant
- Concurrency: parallel signing cannot accidentally reuse per-signature randomness.

## 5) Side-Channels and Faults

- Implementation is constant-time where it needs to be (or uses hardened primitives).
- No secret-dependent branches or table lookups in core signing operations.
- Fault attacks considered if running on hostile devices (e.g., HSM bypass, glitching).

If this is not hardened:
- make it explicit in docs and threat model
- restrict usage to environments where it’s acceptable

## 6) Testing Strategy

Minimum:
- official known-answer tests for the chosen parameter set(s)
- negative tests: malformed inputs, wrong lengths, wrong algorithm IDs
- cross-implementation interop tests (if available)

Good extras:
- property tests: verify(sign(m)) is True; verify(sign(m), m') is False
- fuzzing for signature parsing and verification

## 7) Operational Concerns

- Logging: signatures and secret seeds are never logged.
- Storage: keys are stored and rotated safely.
- Rate limits / DoS: verification can be expensive; defend endpoints accordingly.
- Migration plan: how will the system evolve if parameter sets are deprecated?

## 8) Questions to Ask the Author

- What parameter set is used, and where is it enforced?
- How are signatures encoded, and how is canonicalization enforced?
- Where is domain separation implemented, and how is it tested?
- What prevents accidental per-signature randomness reuse?
- What are the expected signature sizes and verification times in production?

