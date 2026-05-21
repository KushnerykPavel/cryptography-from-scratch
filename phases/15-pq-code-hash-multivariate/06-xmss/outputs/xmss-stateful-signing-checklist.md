---
name: XMSS Stateful Signing Checklist
description: PR-review checklist for integrating XMSS/LMS-style stateful hash-based signatures without index-reuse failures.
phase: 15-pq-code-hash-multivariate
lesson: 06-xmss
---

# XMSS Stateful Signing Checklist

Use this checklist when reviewing any integration of **stateful hash-based signatures** (XMSS, XMSSMT, LMS, HSS). The core risk is not “crypto math” — it’s **state reuse**.

## 1) Decide: stateful vs stateless

- Do we truly want a **stateful** signature scheme (finite signatures per key, strict index tracking)?
- If we cannot guarantee correct state management under crashes and concurrency, should we use a **stateless** hash-based scheme instead (e.g., SPHINCS+/SLH-DSA)?
- Is the system OK with **key exhaustion** semantics (hard limit of `2^h` signatures per key)?

## 2) Index (`idx`) lifecycle (the hard requirement)

- Where is `idx` stored durably? (database row, file, HSM monotonic counter, etc.)
- Is `idx` increment **atomic** with signature output? (Never return a signature before the persisted idx advances.)
- Is `idx` monotone under failures?
  - crash after computing signature, before commit
  - power loss during write
  - rollback / snapshot restore
  - retry logic that replays a signing request
- Do we have a “single-writer” rule enforced?
  - one process owns the key, or
  - a distributed lock, or
  - partitioned idx ranges per signer instance (with strict non-overlap)
- Do we have monitoring/alerts for:
  - duplicate idx usage attempts
  - idx near exhaustion
  - gaps (unexpected large jumps) that indicate state corruption

## 3) Key copying, backup, and restore

- Is the private key ever cloned to another machine/environment?
  - If yes, how do we prevent two copies from using overlapping idx ranges?
- Do backups include the *current idx* and is restore safe?
- Do snapshot/restore systems (VM images, container checkpoints) risk reverting idx?

## 4) Format and parameter pinning

- Are parameters pinned by an algorithm identifier (OID), not by “inferred” lengths?
- Are signatures rejected if any field length is wrong?
- Is the public key root treated as the only trust anchor (no “helpful” fallbacks)?

## 5) Verification and test strategy

- Do we have unit tests for:
  - “wrong message” rejection
  - corrupted signature bytes rejection
  - auth path ordering by idx bits
- Do we have failure-mode tests for the state boundary?
  - simulate crash between “compute signature” and “persist idx”
  - simulate two concurrent signers racing for the same key
- Do we have a deterministic vector test suite (even if the vectors are internal regression vectors)?

## 6) Operational guardrails

- Do we expose `idx` (or remaining signatures) to operators?
- Do we define what happens at exhaustion?
  - key rotation
  - refusal with explicit error
  - migration path for verifiers
- Do we define SLOs for signing latency that don’t encourage dangerous batching/concurrency hacks?

## “Ship” check (what you should be able to say in the PR)

In one paragraph, the PR should state:

1) where `idx` is stored,  
2) how atomicity is guaranteed (crash-safe),  
3) how concurrency is prevented (single writer / lock / partitioning),  
4) what the exhaustion plan is.

