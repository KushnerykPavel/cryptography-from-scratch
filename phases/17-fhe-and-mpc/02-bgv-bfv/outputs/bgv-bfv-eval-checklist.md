---
name: "BFV/BGV Evaluation & PR Review Checklist"
description: "A practical checklist for choosing BFV vs BGV and reviewing parameter/implementation changes in FHE projects."
phase: "17-fhe-and-mpc"
lesson: "02-bgv-bfv"
---

# BFV/BGV Evaluation & PR Review Checklist

Use this when you’re:
- deciding whether BFV/BGV is the right scheme for a feature,
- reviewing a PR that changes FHE parameters, “levels”, modulus chains, relinearization/mod-switch behavior,
- sanity-checking a vendor/library proposal.

If you can’t answer an item, write “unknown” and add an action (measure/prove/test).

## 1) Goal fit (scheme choice)

- [ ] Workload is **exact integer** arithmetic (counts, sums, polynomial features, integer circuits). If you need approximate reals/ML, prefer **CKKS**.
- [ ] Circuit depth is known: max multiplication depth `D_mul` (not just “a few multiplies”).
- [ ] You know whether you need comparisons. If yes, you have a plan (bit-decomposition / programmable bootstrapping / hybrid MPC), not wishful thinking.
- [ ] You have a reason to pick **BFV vs BGV**:
  - BFV: “scale-and-round after multiply” mental model; common in SEAL-style stacks.
  - BGV: “modulus switching across levels” mental model; common in HElib-style stacks.

## 2) Security & threat model

- [ ] Security level target is stated (e.g., “≥128-bit classical”), and you know which estimator/library provides that claim.
- [ ] Adversary model is stated: passive vs malicious server, multi-tenant attacker, chosen-ciphertext exposure, etc.
- [ ] Side-channel risk is understood (FHE ops are heavy; constant-time is hard; do not assume “crypto == safe”).

## 3) Data encoding (the place most projects break)

- [ ] Plaintext modulus `t` (or equivalent) is documented, including how negatives are represented (centered vs unsigned).
- [ ] Input ranges are bounded (max coefficient / max value), not “it’s an int”.
- [ ] You have tests for edge inputs: max/min, sign boundaries, near-modulus wrap.
- [ ] If using batching/SIMD packing, the slot layout is documented (which slot holds what, how rotations align).

## 4) Correctness budget (noise/levels)

- [ ] You have a concrete statement of **depth vs parameters**:
  - max allowed multiplicative depth,
  - expected bootstraps (if any),
  - what constitutes “decryption failure” (wrong value, silent wrap, decode error).
- [ ] Relinearization strategy is explicit:
  - when you relinearize (every multiply? conditional?),
  - relinearization key size tradeoffs are acknowledged.
- [ ] Modulus switching / rescale strategy is explicit:
  - when it happens,
  - what modulus chain is used (RNS primes / levels),
  - how you validate “same plaintext after mod switch” in tests.

## 5) Performance & operational constraints

- [ ] Latency budget is stated per request and per ciphertext operation (add/mul/rotate/bootstrapping).
- [ ] Memory budget is stated (ciphertexts + keys can be huge; key rotation sets can dominate).
- [ ] Key management is designed:
  - who holds secret key,
  - where evaluation keys live (relin/rotations),
  - how keys rotate and how old ciphertexts are handled.
- [ ] Serialization format is defined and versioned (ciphertext params must match the decryptor).

## 6) Testing requirements (non-negotiable)

- [ ] Deterministic vector tests exist for core arithmetic (ring ops, encode/decode, decrypt roundtrip).
- [ ] Property tests exist:
  - `Dec(Enc(m1) + Enc(m2)) == m1 + m2`,
  - `Dec(Enc(m1) * Enc(m2)) == m1 * m2` (for the supported depth),
  - mod-switch invariants (if used).
- [ ] Failure is loud: decryption mismatch triggers test failure (no “best effort” decoding).

## 7) Review red flags

- [ ] “It passed on small samples” with no parameter/noise analysis.
- [ ] Parameter changes without updated security estimate.
- [ ] Using toy parameters (tiny `n`, tiny moduli) as evidence for production feasibility.
- [ ] Unclear handling of negatives / centered lift / rounding behavior.
- [ ] Shipping custom FHE primitives instead of using a maintained library without a very strong reason.

## Quick decision log (fill in)

- **Workload:**  
- **Exact vs approximate:**  
- **Max multiplication depth:**  
- **Chosen scheme:** BFV / BGV / CKKS / TFHE / Hybrid  
- **Library:** SEAL / OpenFHE / HElib / Lattigo / Other  
- **Key switching needs:** relin / rotations / both  
- **Modulus chain / levels approach:**  
- **Top 3 risks + mitigations:**  

