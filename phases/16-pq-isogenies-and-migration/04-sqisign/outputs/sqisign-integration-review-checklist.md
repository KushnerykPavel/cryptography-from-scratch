---
name: "SQIsign Integration Review Checklist"
description: "A practical checklist for reviewing SQIsign-shaped signature integrations (transcript binding, aborts, encoding, side-channels)."
phase: "16-pq-isogenies-and-migration"
lesson: "04-sqisign"
---

# SQIsign Integration Review Checklist

Use this when reviewing PRs or design docs that add SQIsign (or SQIsign-shaped) signatures.

This is intentionally protocol-shape focused: commit → hash challenge → response, plus implementation pitfalls that matter in real systems.

## 1) Algorithm + parameter clarity

- Identify the exact scheme/variant name and parameter level(s) used.
- Confirm the hash functions and domain separation strategy are explicit and consistent across:
  - signing,
  - verification,
  - serialization,
  - test vectors.
- Confirm there is no “fallback to classical” path that silently triggers (unless explicitly intended and logged).

## 2) Transcript binding (Fiat–Shamir correctness)

- The challenge derivation hashes *at minimum*:
  - `public key`
  - `commitment`
  - `message`
  - plus a domain separator / context string.
- If there are multiple contexts (TLS handshake, code signing, JWT-like tokens, COSE, etc.), confirm the context is bound too.
- Confirm the signature cannot be replayed across:
  - different messages,
  - different public keys,
  - different protocol contexts.

## 3) Commitments and randomness

- Commitment generation uses a cryptographically secure RNG (or deterministic RFC-style nonce derivation that is safe for the scheme).
- Commitments/nonces are unique per message and never reused across signatures.
- Secrets used during signing are not logged (including seeds, intermediate curves/ideals, retry counters, or partial responses).

## 4) Aborts/retries: side-channel and DoS surface

- If the scheme uses retries/aborts:
  - confirm upper bounds (`max_tries`) are enforced,
  - confirm behavior on failure is explicit (error vs retry vs fallback).
- Evaluate side-channel leakage:
  - does retry count leak anything sensitive?
  - can timing correlate with key material?
- Evaluate DoS exposure:
  - can an attacker force high retry rates by choosing messages/contexts?
  - are rate limits/backpressure applied to signing endpoints?

## 5) Encoding and parsing (malleability control)

- Signature encoding is canonical:
  - no multiple encodings for the same mathematical object,
  - no acceptance of ambiguous or non-minimal encodings.
- Verifier rejects:
  - out-of-range values,
  - invalid lengths,
  - non-canonical encodings.
- Ensure decoding is memory-safe and constant-time where feasible (especially for comparisons and error paths).

## 6) Key management and operational hygiene

- Keys are labeled with algorithm + parameter set (to prevent “wrong key for wrong scheme” accidents).
- Rotation and revocation strategy exists (what happens to old signatures?).
- Hardware boundaries are explicit:
  - where keys live (HSM, enclave, file),
  - which processes can sign,
  - where auditing/logging occurs.

## 7) Test strategy

- Deterministic test vectors exist and run in CI.
- Negative tests exist:
  - wrong message,
  - wrong public key,
  - bit-flipped signature,
  - truncated/extended signature,
  - invalid encoding.
- Interop plan exists if multiple implementations are involved (e.g., “reference C” vs “optimized” vs “platform port”).

## 8) Migration and product fit

- Document why SQIsign is chosen over other PQ signatures for this use-case:
  - key/signature size vs latency vs code size vs platform constraints.
- Document where PQ signatures sit in your system:
  - code signing,
  - device identity,
  - certificate chains,
  - signed updates,
  - audit logs.
- If used alongside PQ KEMs (hybrid TLS), confirm algorithm negotiation is explicit and tested.

## Red flags (stop-and-ask)

- “We didn’t include the public key/commitment/message in the hash because it still verifies.”
- “We reuse nonces/commitments to save CPU.”
- “We accept multiple signature encodings for compatibility.”
- “We don’t cap retries because failures are rare.”
- “We log intermediate signing objects for debugging in production.”

