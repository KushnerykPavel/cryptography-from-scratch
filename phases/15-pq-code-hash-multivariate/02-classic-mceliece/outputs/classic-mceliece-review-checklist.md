---
name: Classic McEliece Integration Review Checklist
description: A PR-review checklist + prompt for integrating Classic McEliece (and code-based KEMs) safely.
phase: 15-pq-code-hash-multivariate
lesson: 02-classic-mceliece
---

# Classic McEliece Integration Review Checklist (Code-Based KEMs)

Use this when reviewing a PR that adds **Classic McEliece** (or another code-based KEM) to an application, protocol, or library.

## 1) Decision Fit
- What is the goal: **primary KEM** or **backup/diversity KEM**?
- What constraints matter most: **bandwidth**, **key storage**, **CPU**, **latency**, **firmware size**, **side-channel resistance**?
- Is there a *hard requirement* for code-based assumptions (diversity) vs lattice-based KEMs?

## 2) Algorithm & API Correctness
- Are they integrating a **KEM API** (encapsulate/decapsulate) rather than “textbook PKE”?
- Do they clearly separate:
  - public key (`pk`),
  - secret key (`sk`),
  - ciphertext (`ct`),
  - shared secret (`ss`)?
- Are all byte lengths taken from the library constants for the chosen parameter set (no “magic numbers”)?

## 3) Randomness & Error Sampling
- Does the implementation use the **library’s RNG interface** correctly (no `rand()` / ad-hoc PRNG)?
- Are there any custom “fixed-weight error” samplers in application code? (There shouldn’t be.)
- Are seeds / entropy sources documented (OS RNG, HSM, DRBG), and are failures handled?

## 4) Failure Semantics (Critical)
- On decapsulation failure, does the code:
  - return an error cleanly, and
  - avoid branching/leaking timing differences that depend on secret data?
- If the library returns a “shared secret” even on failure (some APIs do), does the caller treat it as **invalid** unless success is explicit?
- Are retries / fallback paths documented to avoid downgrade attacks?

## 5) Side Channels & Constant-Time Expectations
- Is the chosen implementation documented as **constant-time** for decapsulation?
- Is the code running in an environment that makes constant-time meaningful (no debug logging, no exception timing leaks, no early returns that depend on secrets)?
- If keys are long-lived, is there a plan for:
  - process isolation,
  - memory hardening (mlock / secure enclave / HSM),
  - side-channel threat model (shared hosts, micro-architectural attacks)?

## 6) Key Management & Storage
- Where are the public keys stored and how are they authenticated?
- Where are secret keys stored (disk, OS keychain, HSM)? Are permissions correct?
- Is key rotation supported? Are old keys handled safely?
- Are keys or ciphertexts ever logged, traced, or included in metrics?

## 7) Interop & Test Strategy
- Is there a test that performs:
  - `ct, ss1 = encaps(pk)`
  - `ss2 = decaps(sk, ct)`
  - assert `ss1 == ss2`
- Are there negative tests that flip bits in `ct` and confirm correct failure handling?
- Do they pin the exact parameter set(s) and version(s) of the upstream library used?

## 8) Operational Constraints
- Have they measured:
  - public key size impact on handshakes / certificates / storage,
  - ciphertext size impact on packetization / MTU,
  - CPU and memory costs on target hardware?
- If used in a network protocol: is fragmentation / retransmission behavior acceptable?

## 9) Red Flags (Request Changes)
- “We implemented McEliece ourselves” or “we modified the decoder.”
- Custom “optimization” of decapsulation checks, especially if it changes branching behavior.
- Using non-audited forks without a clear security review.
- Treating decapsulation as “can’t fail” and omitting error handling.

## Copy/Paste Prompt for a Security Review

Paste this into a PR review (or an LLM) with the relevant diff context:

> You are reviewing a code change that integrates Classic McEliece (a code-based KEM).  
> Audit for: API misuse, key/ciphertext length mismatches, RNG misuse, failure-handling correctness, downgrade paths, and constant-time / side-channel hazards.  
> Provide a checklist of concrete issues to verify in the diff and concrete tests to add (positive interop + negative bit-flip tests).  
> If the integration uses fallback or hybrid mode, analyze downgrade and transcript-binding risks.

