---
name: "Beaver Triples Review Checklist"
description: "A practical checklist for reviewing MPC implementations that use Beaver triples (multiplication triples) for arithmetic circuits."
phase: "17-fhe-and-mpc"
lesson: "10-beaver-triples"
---

# Beaver Triples Review Checklist

Use this checklist in PR reviews or design docs when an MPC system claims to support “arithmetic MPC” via Beaver triples (or an SPDZ-like offline/online split).

## 1) Protocol shape (offline vs online)
- Does the design clearly separate **offline preprocessing** (triple generation) from **online evaluation** (consuming triples on inputs)?
- Is it explicit that **each multiplication gate consumes 1 triple** (or more, depending on malicious security)?
- Is the number of values opened online (typically `d=x-a` and `e=y-b`) stated and enforced?

## 2) Algebra and domains
- Is every operation done in a single, well-defined ring/field (e.g., `F_p`)?
- Are negative values, fixed-point encodings, and wraparound behavior defined (and tested)?
- Are conversions between domains (ints ↔ field elems, floats ↔ fixed-point) centralized and reviewed?

## 3) Triple generation assumptions
- What is the triple source?
  - trusted dealer / hardware
  - OT-based (e.g., MASCOT)
  - HE-based
  - other
- Is the security level for the triple source stated (semi-honest vs malicious)?
- Is the randomness quality for triples reviewed (RNG, seeding, determinism in tests only)?

## 4) Triple usage rules
- Are triples **single-use**? Is reuse prevented structurally (types, counters, one-shot iterators)?
- Is there logging/telemetry that could accidentally leak triple material (shares of `a,b,c` or opened `d,e`)?
- Is `d,e` opening implemented exactly once per multiply, with correct modulus, and with correct reconstruction logic?

## 5) Correctness invariants to test
- For random inputs `x,y`: open(result) equals `x*y (mod p)`.
- For fixed seeds: deterministic end-to-end tests match known vectors.
- Edge cases: `0`, `1`, `p-1`, negative inputs (if allowed), and large integers reduced mod `p`.
- Share-shape checks: length mismatches are rejected early and loudly.

## 6) Malicious security (if claimed)
- If the system claims malicious security, where are the **consistency checks**?
  - SPDZ-style MACs / authentication
  - share verification / sacrifice checks for triples
  - commitments / ZK / other integrity mechanisms
- Is there a documented threat model for what a cheating party can and cannot do?

## 7) Engineering and operational risks
- Are transcripts (opened values, intermediate results) stored? If yes, for how long and why?
- Is there a clear boundary between “test/demo mode” and “production mode” (especially RNG seeding)?
- Are performance claims tied to concrete parameters (parties `n`, field size, network latency, triple throughput)?

## 8) Red flags (stop-ship)
- Triples reused across multiple multiplications.
- Modulus mismatch between preprocessing and online evaluation.
- “Malicious secure” without MACs / authentication or an equivalent integrity layer.
- Debug prints, metrics, or traces that include secret shares or reconstructed masked values outside controlled test runs.

