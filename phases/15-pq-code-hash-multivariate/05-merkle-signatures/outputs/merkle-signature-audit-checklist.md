---
name: Merkle Signature Audit Checklist
description: A practical checklist for reviewing hash-based signature schemes (MSS/XMSS/LMS/SPHINCS+) in designs, code reviews, and incident response.
phase: 15-pq-code-hash-multivariate
lesson: 05-merkle-signatures
---

# Merkle Signature Audit Checklist (MSS / XMSS / LMS / SPHINCS+)

Use this checklist when someone proposes “post-quantum signatures based on hashes”, or when reviewing an implementation that uses Merkle trees + one-time signatures.

## 1) Identify the scheme and its state model
- [ ] Scheme is explicitly identified (MSS/XMSS/XMSS^MT/LMS/HSS/SPHINCS+), not just “Merkle signatures”.
- [ ] State model is explicit:
  - [ ] **Stateful** (XMSS/LMS): leaf indices must never repeat.
  - [ ] **Stateless** (SPHINCS+): no leaf state, but larger signatures and different failure modes.
- [ ] Parameters are pinned and versioned (hash function, tree height, WOTS parameters, addressing, etc.).

## 2) Leaf key management (OTS)
- [ ] Leaf OTS scheme is identified (Lamport/WOTS/WOTS+).
- [ ] Leaf key derivation is safe and unique per `(master_seed, leaf_index)`:
  - [ ] Uses domain separation labels (not raw concatenation reused elsewhere).
  - [ ] Uses a fixed-length encoding for `leaf_index` (avoid ambiguity).
- [ ] Key generation randomness is handled safely:
  - [ ] CSPRNG when required, or a specified DRBG for deterministic derivation.
  - [ ] Seeds are treated as private keys (rotation, backup, access control).

## 3) Merkle tree construction (commitment layer)
- [ ] Leaf hashing and internal node hashing are domain-separated.
- [ ] Tree shape is unambiguous:
  - [ ] Fixed leaf count (power-of-two) or a specified padding strategy.
  - [ ] Leaf ordering is specified and stable across implementations.
- [ ] Root is the only long-term public key identifier, and it is authenticated/pinned where it matters (certs, config, protocol).

## 4) Signature structure and verification rules
- [ ] Signature format is fully specified and validated before use:
  - [ ] `leaf_index` bounds check.
  - [ ] `auth_path` length check equals tree height.
  - [ ] Rejects malformed encodings (truncated hashes, extra bytes, etc.).
- [ ] Verifier checks both layers:
  - [ ] OTS signature verifies under the included OTS public key.
  - [ ] OTS public key is proven to be in the tree via the auth path.
- [ ] Verification is constant-time where required by the threat model (or documented as not constant-time).

## 5) Stateful signing safety (XMSS/LMS) — the “leaf reuse” trap
If the scheme is stateful:
- [ ] Leaf index allocation is atomic and crash-safe (no reuse after restart).
- [ ] Concurrency is safe (multiple workers cannot sign with the same index).
- [ ] Rollback is handled (VM snapshots, DB restores, filesystem rollback).
- [ ] Monitoring exists:
  - [ ] Alerts on duplicate index attempts.
  - [ ] Metrics for “remaining signatures” and “current index”.
- [ ] Incident playbook exists for suspected index reuse (treat as key compromise).

## 6) Serialization and interoperability
- [ ] Signature and public key serialization is canonical and tested across languages (if applicable).
- [ ] Endianness and integer widths are specified for `leaf_index` and parameters.
- [ ] Test vectors include both positive and negative cases (tampering, wrong index, wrong path).

## 7) Performance and size realism
- [ ] Signature size is measured and acceptable for the protocol (MTU limits, QR codes, chain storage, etc.).
- [ ] Verification cost is measured under realistic loads (batch verify? cold cache?).
- [ ] Parameter choices match the security target (classical + PQ) and deployment constraints.

## 8) Red flags (stop-ship until answered)
- [ ] “We used Merkle signatures” but no one can explain how leaf indices are managed.
- [ ] Root is not pinned/authenticated (verifier accepts a root from an untrusted channel).
- [ ] No domain separation between leaf hashing and internal nodes.
- [ ] Signatures verify even when `leaf_index` is changed (index not actually bound).
- [ ] No negative tests (tampered message/path/key) in CI.

## Quick questions to ask in a PR review
1. What prevents signing twice with the same leaf key?
2. Where is the public root stored and how is it authenticated?
3. What exactly is hashed at leaves and internal nodes (domain separation)?
4. What are the bounds/format checks in verification?
5. Do we have regression vectors and a tampering test?

