---
name: mq-signature-review-checklist
description: A paste-ready checklist for reviewing MQ (multivariate quadratic) signature schemes and implementations, with Rainbow-specific red flags.
phase: 15-pq-code-hash-multivariate
lesson: 09-multivariate-rainbow
---

# MQ Signature Review Checklist (Rainbow / UOV / "MQ-like")

Use this as a PR-review prompt or design review template when you see an MQ-based signature or a “Rainbow-like” claim.

## 0) Stop / Go Decision (2 minutes)

- Is the scheme **Rainbow** (or directly derived from Rainbow parameters/submission)?
  - If yes: treat as **broken / do-not-deploy** unless you have a *current* cryptanalysis story and a clear reason this variant avoids known key-recovery attacks.
- Is the scheme **standardized** (or a current NIST finalist/standard)?
  - If yes: prefer the reference spec + known-good implementations.
- Is the scheme a **research MQ** (UOV-family, MAYO-family, etc.)?
  - If yes: proceed, but treat as high-risk and require explicit parameter/version pinning and a cryptanalysis review.

## 1) Threat Model Questions

- What are we protecting against: forgery, key recovery, signature malleability, fault attacks, side-channels, chosen-message attacks?
- Does the signer run in an attacker-controlled environment (browser, mobile, HSM, shared VM)?
- Is verification offline/batched (e.g., blockchains), where cheap verification is a priority?

## 2) Scheme-Level Checklist (Design)

- Field:
  - What field is used (GF(p), GF(2^k), extension fields)?
  - Are all operations well-defined (inverses exist when expected)?
- Hashing:
  - Is the message hashed into the field with **domain separation**?
  - Is salt used? If yes, is it included in what gets verified (e.g., `H(H(m)||salt)`)?
- Trapdoor structure:
  - Is there a clear “central map” `F` and two hiding maps `S, T` such that `P = S ∘ F ∘ T`?
  - If it’s OV/UOV:
    - Are oil×oil terms forbidden in the central polynomials?
    - Are the parameter ratios (vinegar vs oil) justified with references?
  - If it’s layered (Rainbow-like):
    - Are the layer boundaries and variable sets precisely specified?
    - Is the “previous layer variables become next layer vinegars” property explicit?
- Security claims:
  - Are claims tied to *specific* parameter sets and *dated* references?
  - Is there an up-to-date summary of known attacks and why they don’t apply?

## 3) Implementation Checklist (Code)

- Correctness:
  - Are all arithmetic operations reduced mod `p` (or in the correct field) consistently?
  - Do tests include deterministic vectors for:
    - field arithmetic
    - linear system solving
    - sign/verify roundtrip
    - tamper rejection
- Signing algorithm (high-risk area):
  - If the algorithm “chooses vinegar values then solves oils,” does it handle:
    - singular / no-solution linear systems (retry logic)?
    - bounded retries + fail-closed behavior?
  - Is randomness:
    - cryptographically strong?
    - domain-separated from message hashing?
    - protected against reuse issues (e.g., vinegar reuse across signatures)?
- Side-channel resistance:
  - Is the linear solver constant-time (or at least constant-shape) where needed?
  - Does the implementation avoid leaking:
    - which retries succeeded
    - pivot positions
    - early exits dependent on secret state
  - Is there a plan for fault attacks (glitches, rowhammer, induced faults)?
- Key material:
  - Are keys validated on load (invertibility checks, parameter checks)?
  - Are secrets zeroed on drop where applicable (language/runtime dependent)?
- Serialization:
  - Is signature and key encoding unambiguous and versioned?
  - Are inputs length-checked and decoded safely?

## 4) Performance / Operational Checklist

- Public key size: is it acceptable for your distribution channel and caching layer?
- Signing latency: is it acceptable for your service SLOs?
- Verification throughput: do you need batch verification? is it supported?
- Migration plan:
  - If this is replacing an existing scheme, is there version negotiation / dual-verify during rollout?

## 5) Reviewer Prompts (Copy/Paste)

Ask the implementer to answer these in the PR description:

1. Which exact scheme + parameter set is implemented (link to spec/paper, including version/date)?
2. What are the known attacks against this scheme family, and why are these parameters safe?
3. What is the signing failure rate (retries) in practice, and how is it bounded?
4. What side-channel assumptions are made, and what mitigations exist?
5. Which tests prove we didn’t accidentally reintroduce oil×oil terms (or break field arithmetic)?

