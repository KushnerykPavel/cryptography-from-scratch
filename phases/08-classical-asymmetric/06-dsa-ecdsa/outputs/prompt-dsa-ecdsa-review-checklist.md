---
name: prompt-dsa-ecdsa-review-checklist
description: A practical review checklist for DSA/ECDSA usage (nonce safety, malleability, encoding, and key validation).
phase: 8
lesson: 6
---

You are reviewing code that generates or verifies DSA/ECDSA signatures. Use this checklist to find real-world failures quickly. Focus on nonce handling, malleability, encoding, and key validation.

## 1) Identify the protocol requirements
- What is being signed (bytes exactly), and how is it serialized/canonicalized?
- Is the signature format fixed (DER, raw `(r,s)`, JOSE, etc.)?
- Does the system require canonical signatures (e.g., low-`s` for ECDSA)?
- Is signature verification tied to an identity / key registry, or can attackers supply arbitrary public keys?

## 2) Nonce (`k`) safety (highest priority)
- Confirm `k` is never reused for the same private key.
- If non-deterministic: confirm the RNG is cryptographically secure and not reused across forks/VM snapshots.
- If deterministic: confirm it follows RFC 6979-style HMAC construction (keyed by private key, input includes message hash).
- Ensure `k` is reduced modulo the group order and rejected if `k == 0`.
- Add/confirm tests that two different messages produce different `k` (and therefore different `r`).

Red flags:
- `random.random()`, `rand()`, time-based seeds, PID-based seeds, or “shuffle a hash” style RNG.
- Caching or memoizing `k` across calls.
- Passing `k` in from external inputs or configs.

## 3) Input validation (reject early)
For ECDSA:
- Reject signatures where `r` or `s` is not in `[1, n-1]`.
- Reject public keys not on the curve (and reject the point at infinity).
- If the protocol requires it, reject high-`s` signatures (`s > n/2`).

For DSA:
- Reject signatures where `r` or `s` is not in `[1, q-1]`.
- Validate that parameters satisfy `q | (p-1)` and that `g^q mod p == 1`.

## 4) Encoding and parsing pitfalls
- If using DER: ensure strict parsing (reject non-canonical encodings, leading zeros issues, negative integers).
- Ensure signature bytes are not accepted in multiple encodings that verify the same `(r,s)` unless the protocol explicitly allows it.
- Ensure you are not accepting “empty” or truncated signatures that parse as zeros.

## 5) Hashing and domain separation
- Confirm the exact bytes signed match the protocol spec (no accidental string encoding differences).
- Confirm the hash function is the one required by the protocol.
- For structured messages: confirm there is domain separation (context string, version, chain-id, etc.) if the protocol needs it.

## 6) Side channels and implementation quality
- Confirm constant-time primitives are used (big-int inverses and scalar multiplication should not be custom in production code).
- Avoid branching or early returns based on secret values in signing code.
- Ensure private keys and nonces are not logged or exposed in exceptions.

## 7) Tests that should exist
- Roundtrip: `verify(sign(m)) == true`.
- Negative: wrong message and wrong public key fail verification.
- Edge cases: out-of-range `r/s` are rejected.
- Canonicalization: if low-`s` is required, high-`s` signatures are rejected.
- Deterministic vectors: include known-good test vectors (or internal deterministic vectors) for sign/verify.

## 8) Quick summary to write in your review
Provide a short, high-signal summary:
- Nonce strategy: deterministic RFC 6979 / CSPRNG (which one)
- Canonicalization: low-`s` enforced or not (and why)
- Validation: range checks + public-key-on-curve checks
- Encoding: strict parsing + canonical encoding
