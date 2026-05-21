---
name: "CKKS Precision & Parameter Checklist"
description: "A practical checklist for choosing CKKS and reviewing scale/level/rescale correctness and precision budgets in FHE projects."
phase: "17-fhe-and-mpc"
lesson: "03-ckks"
---

# CKKS Precision & Parameter Checklist

Use this when you’re:
- deciding whether CKKS is the right scheme for a feature,
- reviewing a PR that changes CKKS scales, modulus chains/levels, rescale schedule, or numeric tolerances,
- sanity-checking a vendor/library proposal for “encrypted inference” or “encrypted analytics”.

If you can’t answer an item, write “unknown” and add an action (measure/prove/test).

## 1) Goal fit (is CKKS appropriate?)

- [ ] The workload is **approximate real/complex arithmetic** (ML inference, stats, signal processing). If you need exact integers/equality, prefer BFV/BGV or redesign.
- [ ] Any comparisons/thresholds are designed with a **safety margin** (no branching on near-boundary results).
- [ ] Output tolerance is explicitly stated (e.g., `L∞ <= 1e-3` or “top-1 class must match plaintext”).

## 2) Data encoding (where most projects break)

- [ ] Input ranges are bounded per feature (min/max), not “it’s a float”.
- [ ] Feature scaling/normalization is documented and stable across deployments.
- [ ] Slot packing layout is documented:
  - which slot holds which feature,
  - any rotations needed (and which rotation keys are required),
  - whether you rely on conjugation / complex packing.

## 3) Scale plan (the central CKKS design artifact)

- [ ] You have a per-layer/per-operation **scale plan**:
  - starting scale `S0` (often ≈ `2^k`),
  - scale after each multiply (often `S^2`),
  - rescale targets to return to “about `S0`”.
- [ ] You know the maximum multiplicative depth `D_mul` and where rescale happens.
- [ ] You can explain why chosen scales avoid both:
  - underflow/precision loss (too small `S`),
  - overflow/modulus exhaustion (scale grows too large before rescale).

## 4) Modulus chain / levels

- [ ] Modulus chain depth supports the circuit:
  - enough levels for all rescale steps (plus any extra for key switching/rotations as required by the library).
- [ ] Level alignment rules are understood:
  - you only add/compare ciphertexts at compatible levels (and with compatible scales),
  - you don’t rely on implicit auto-rescale behavior without tests.

## 5) Correctness budget (precision + error)

- [ ] You have an explicit error budget at key checkpoints (not only at the end).
- [ ] You have tests that measure error on:
  - typical inputs,
  - worst-case bounded inputs (max magnitude),
  - near-boundary inputs (if there are thresholds).
- [ ] You have a plan for handling “approximate outputs”:
  - postprocessing that is robust to small error,
  - no exact equality checks on CKKS results.

## 6) Security & threat model (don’t skip)

- [ ] Target security level is stated (e.g., “≥128-bit classical”), and you know which estimator/library provides that claim.
- [ ] You have an adversary model (multi-tenant? malicious evaluator? chosen-ciphertext exposure?).
- [ ] Side-channel risk is acknowledged: FHE ops are heavy and implementations are complex; do not assume “crypto == safe”.

## 7) Testing requirements (non-negotiable)

- [ ] Deterministic vector tests exist for encode/decode and for a minimal end-to-end circuit.
- [ ] Property tests exist for your circuit class:
  - approximate add: `Dec(EvalAdd(Enc(x), Enc(y))) ~= x+y`,
  - approximate mul+rescale: `Dec(EvalMul(Enc(x), Enc(y))) ~= x*y`,
  - invariants around scale/level transitions.
- [ ] Tolerances are documented and justified (no magic epsilons).

## 8) Review red flags

- [ ] “It works on a small sample” without worst-case range + tolerance analysis.
- [ ] Branching/thresholding on CKKS results without a margin and tests near the boundary.
- [ ] Parameter changes without updated security estimate and updated error measurements.
- [ ] Hidden auto-rescale/modswitch behavior relied on without explicit assertions in tests.

## Quick decision log (fill in)

- **Workload:**  
- **Exact vs approximate:**  
- **Max multiplication depth:**  
- **Chosen scheme:** CKKS / BFV/BGV / TFHE / Hybrid  
- **Library:** SEAL / OpenFHE / Lattigo / Other  
- **Tolerance target:**  
- **Scale plan summary:**  
- **Levels/modulus chain plan summary:**  
- **Top 3 risks + mitigations:**  

