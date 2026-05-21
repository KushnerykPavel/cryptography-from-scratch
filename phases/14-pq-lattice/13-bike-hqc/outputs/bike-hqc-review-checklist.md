---
name: bike-hqc-review-checklist
description: Copy/paste checklist for reviewing BIKE/HQC (code-based) implementations: QC polynomial arithmetic, decoders, DFR, and side-channel/reaction-attack pitfalls.
phase: 14
lesson: 13
---

# BIKE / HQC Review Checklist (Copy/Paste)

You are reviewing a BIKE or HQC implementation (or a PR that touches it).
Your goal is to answer:

1) Are the math conventions correct (ring, bit order, shifts)?
2) Is decoding correct, and is the failure behavior safe?
3) Is the implementation hardened against timing/reaction leakage?
4) Are parameter and input validations complete?

Return:
- A short summary of what the code claims to implement (variant + parameter set).
- A list of concrete correctness risks (with file/function pointers).
- A list of concrete side-channel / reaction-attack risks.
- A short “questions for the author” section.

## 0) Pin down the exact variant

- Scheme: BIKE (which variant?) or HQC (which variant / parameter set?)
- Source of truth: spec version + commit hash of reference implementation (if used)
- Claimed security level/category
- Are keys intended to be ephemeral or static?

## 1) Ring + bit conventions (highest-risk correctness area)

Both BIKE and HQC use binary polynomials in a cyclic ring like `GF(2)[x]/(x^n - 1)`.

Checklist:

- What does bit `i` mean? Coefficient of `x^i` (little-endian) vs `x^{n-1-i}` (big-endian)?
- Does “rotate left by k” match the spec’s polynomial multiplication convention?
- Is multiplication performed modulo `x^n - 1` (cyclic) vs `x^n + 1` (negacyclic)?
- Do conversions between bytes <-> bits preserve the chosen bit order?
- Are test vectors sensitive to endianness being exercised?

Red flag: “it passes our internal tests” but no external vectors (or vectors only test one direction).

## 2) Sampling (fixed-weight / rejection sampling)

- Are “fixed weight” vectors sampled uniformly among all weight-`w` vectors?
- Is the sampler constant-time w.r.t. secret material?
- If rejection sampling is used, can the rejection rate leak information (timing)?
- Are RNG failures handled (no zero seeds, no reuse across sessions)?

## 3) Decoder behavior (correctness + security)

BIKE:

- Does the decoder return the unique low-weight `(e0,e1)` for the given syndrome when decoding succeeds?
- Is the maximum iteration count fixed (constant-time structure)?
- Are thresholds computed exactly as specified (or precomputed safely)?
- Is the decoder failure rate (DFR) accounted for at the *system* level?

HQC:

- Does `Decode(v - u*y)` (or the equivalent) actually produce the message under the spec’s noise model?
- Are the concatenated-code encoders/decoders correct (and constant-time where required)?
- Are truncations / bit-packing steps correct and covered by vectors?

## 4) Failure handling (reaction-attack surface)

Decode failures can be amplified into key recovery if an attacker can distinguish “success” vs “failure”
by timing, error messages, or protocol behavior.

- Is the decapsulation/encryption path indistinguishable on success vs failure?
- Are error codes, logging, metrics, or retries exposing failures?
- Are handshake/protocol-level “alerts” correlated with decoder failures?
- Is the implementation using a KEM transform / re-encryption check as required by the spec?

## 5) Input validation & invariants

- Public key: validated for structure (e.g., required weights, not all-zero, expected length)?
- Ciphertext: validated lengths and canonical encoding?
- Any non-invertibility cases handled (where relevant)?
- Are all “mod n” indices masked correctly (no out-of-bounds, no UB in C)?

## 6) Constant-time & micro-architectural concerns

- No secret-dependent branches, memory access patterns, or loop bounds in:
  - samplers,
  - decoders,
  - polynomial multiplication (when processing secrets),
  - hash/KDF input selection.
- If vectorized/ASM optimizations exist, do they preserve constant-time behavior?
- Are there clear unit/integration tests that compare “timing envelope” across success/failure paths?

## 7) Questions to ask the author

- “Which functions define the ring conventions (bit order + shift direction)?”
- “Show external test vectors that would fail if endianness were reversed.”
- “How does the code ensure decapsulation is indistinguishable on decode failure?”
- “Where is DFR addressed at the protocol level (retries, alerts, logging)?”

