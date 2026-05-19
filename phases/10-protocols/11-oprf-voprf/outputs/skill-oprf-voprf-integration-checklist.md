---
name: oprf-voprf-integration-checklist
description: A practical checklist for designing, reviewing, and auditing OPRF/VOPRF integrations (OPAQUE, anonymous tokens, PSI-style encodings).
version: 1.0.0
phase: 10
lesson: 11
tags: [cryptography, protocols, oprf, voprf, opaque, privacy-pass, psi]
---

You are reviewing a design or PR that introduces an OPRF or VOPRF.

Output:
1) a pass/fail verdict for each checklist section,
2) concrete fixes with exact invariants to enforce,
3) the single highest-risk missing check (if any).

Do not approve educational implementations as production-safe.

## 1) Mode & Threat Model

- Is the construction **OPRF**, **VOPRF**, or **POPRF**? Is that choice justified?
  - If the client must detect server cheating/misconfiguration, require **VOPRF** (proof verification is mandatory).
- What does the server learn? What does the client learn? Are these acceptable?
- Is this used for **passwords** (OPAQUE-like), **tokens** (Privacy Pass-like), or **set encodings** (PSI-like)? State the expected privacy properties explicitly.

## 2) Group, Ciphersuite, and Encoding

- What prime-order group is used (e.g., Ristretto255, P-256, BLS12-381 G1)?
- What hash function is used? Are outputs truncated/expanded safely?
- Are **element encodings** canonical and unambiguous?
  - Reject non-canonical encodings.
  - Reject points not on the curve / not in the correct subgroup.

## 3) Hashing & Domain Separation

- Is there a robust **hash-to-group** (or hash-to-curve) per standard (not “hash then parse”)?
- Are domain separation strings used for:
  - `H1` (input -> group element),
  - `H2` (final output derivation),
  - proof transcript hashing (VOPRF),
  - key derivation (if any)?
- Is input framing prefix-free? (Lengths included, or a safe structured encoding.)

## 4) Blinding Correctness

- Is the blind sampled uniformly from the scalar field and non-zero?
- Is the blind **fresh per evaluation**? (No reuse across inputs or sessions.)
- Is unblinding done with the correct inverse in the scalar field?
- Is the implementation hardened against obvious side channels where practical (constant-time scalar mult, constant-time equality, etc.)?

## 5) Server Evaluation Rules

- Does the server validate received elements before scalar multiplication/exponentiation?
  - Reject invalid points / wrong subgroup elements.
- Is the server key material generated and stored correctly (key rotation story, multi-server story, backup story)?
- If batching is used, is the transcript bound to the exact batch (order, count, and per-item encodings)?

## 6) Verifiability (VOPRF-only)

- Is the server public key `pk` distributed/validated correctly (pinning, certificate binding, transparency, etc.)?
- Is proof verification performed on **every** response before finalization?
- If verification fails, does the client abort (no output, no partial acceptance)?
- Is the proof transcript bound to:
  - the ciphersuite / group identifier,
  - the server public key,
  - the exact `alpha` and `beta` values (and batch, if used)?

## 7) KDF / Output Use

- Is the OPRF output passed through an appropriate KDF before being used as:
  - an encryption key,
  - a MAC key,
  - a token seed?
- Is output length appropriate and consistent?
- Are outputs ever logged or persisted? If yes, why is that safe?

## 8) “What could go wrong?” Red Flags

Flag as high severity if any apply:

- No subgroup/membership checks (small-subgroup / invalid-curve style attacks).
- No domain separation between hashing roles.
- Blind reuse or deterministic blinding.
- VOPRF mode implemented but proof verification is optional or skipped.
- Non-canonical encodings accepted (multiple byte strings for the same element).
- Educational/toy arithmetic used in production paths.

## 9) Minimal Requirements Summary (copy/paste into review)

Require at minimum:

- Canonical element encoding + strict decoding + subgroup checks
- Domain-separated `H1`, `H2`, and proof transcript hashing
- Fresh uniform non-zero blinds
- Mandatory VOPRF proof verification (if VOPRF)
- Clear error handling: verification failure => abort
- Test vectors + negative tests (tamper `beta`, wrong `pk`, invalid element)

