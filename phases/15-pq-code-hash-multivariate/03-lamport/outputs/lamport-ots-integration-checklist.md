---
name: Lamport OTS Integration Checklist
description: Practical checklist for reviewing one-time/hash-based signature usage, with a focus on key reuse hazards and domain separation.
phase: 15-pq-code-hash-multivariate
lesson: 03-lamport
---

# Lamport OTS Integration Checklist

Use this when reviewing a PR or design doc that mentions Lamport OTS (or a
hash-based signature system built on one-time keys, like WOTS+/XMSS/LMS/SPHINCS+).

## 0) First question: do you actually want Lamport OTS?

- If the requirement is “post-quantum signatures” for a product, Lamport OTS is
  almost never the right deployed primitive (key/signature size, strict one-time
  usage). Prefer a standardized hash-based signature scheme (XMSS/LMS/SPHINCS+)
  or the project’s chosen PQ signature standard.
- If the requirement is “teach / prototype / build a Merkle signature scheme”,
  Lamport OTS is appropriate as a learning step.

## 1) Key material: generation and storage

- Private key material is random bytes. Verify the RNG:
  - uses OS CSPRNG,
  - is not seeded from timestamps or environment-only entropy,
  - is not derived from user passwords unless a real KDF is used.
- Public key is a set of hash commitments:
  - store as raw bytes or canonical hex,
  - document the exact hash function used.
- Secret sizes and hash sizes are fixed and documented (e.g., SHA-256 + 32-byte
  secrets).

## 2) Domain separation (non-negotiable)

- Any PRG/KDF-like expansion used to generate secrets has an explicit domain tag
  so it cannot be confused with other uses of SHA-256 in the system.
- If multiple protocols share hashing, each has a distinct domain tag.

## 3) One-time enforcement (the entire security story)

- There is a *mechanism* that prevents signing more than once per private key:
  - stateful counter in secure storage,
  - “key is consumed” semantics,
  - or using a higher-level scheme (Merkle tree of OTS keys) that consumes a
    leaf key exactly once.
- There is a *detection* mechanism for key reuse (defense in depth):
  - logging/metrics for signature count per key id,
  - alarms on reuse,
  - tests that simulate accidental reuse.
- There is a clear key identifier and a stable serialization of the public key
  (or a fingerprint) used for monitoring.

## 4) Message handling: what exactly is signed

- The scheme signs a fixed-length digest (e.g., `SHA256(message)`), not an
  ambiguous variable-length structure.
- If the “message” is structured (JSON/protobuf/etc), serialization is
  canonicalized:
  - stable field ordering,
  - stable encoding,
  - explicit versioning.
- Include a protocol/context string in the signed bytes (domain separation at
  the message layer too).

## 5) Verification logic sanity checks

- Signature length is exactly the digest bit length (e.g., 256 elements).
- Each signature element is exactly one secret-sized chunk (e.g., 32 bytes).
- Bit order is specified and tested (MSB-first vs LSB-first).
- Verification hashes each revealed secret and compares to the correct public
  commitment.
- Rejection tests exist:
  - modified message fails,
  - modified signature element fails,
  - wrong-size signature fails.

## 6) Size and performance expectations

- Key sizes and signature sizes are acknowledged in the design:
  - private key: `2 * n_bits * secret_size`,
  - public key: `2 * n_bits * hash_size`,
  - signature: `n_bits * secret_size`.
- Any transport/storage constraints are addressed:
  - maximum header sizes,
  - database field sizes,
  - bandwidth costs.

## 7) If this is part of a larger hash-based signature

If Lamport OTS is used as a component (Merkle signature, XMSS/LMS, SPHINCS+):

- The tree construction is specified:
  - leaf = hash(public_key_of_OTS),
  - parent = hash(left || right) with domain separation.
- Authentication path verification is implemented and tested.
- Stateful schemes (XMSS/LMS) define how state is stored and protected against
  rollback (rollback can cause key reuse).

## 8) A ready-to-use PR review prompt

Paste this into your code review tool or LLM:

“Review this change as if it were introducing a one-time/hash-based signature
scheme. Confirm: (1) one-time enforcement cannot be bypassed, (2) domain
separation is present for PRG and message layers, (3) message serialization is
canonical, (4) verification rejects wrong sizes and tampering, (5) tests cover
modified message/signature cases, and (6) key/signature sizes are explicitly
accounted for in transport and storage.”

