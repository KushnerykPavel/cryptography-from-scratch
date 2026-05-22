---
name: bgw-review-checklist
description: Practical checklist for reviewing Shamir/BGW-style MPC (arithmetic circuits), focusing on degree reduction, thresholds, and implementation hazards
phase: 17
lesson: 8
---

Use this checklist to review a Shamir/BGW-style MPC implementation (or a design doc) that evaluates arithmetic circuits over a prime field.

## 0) Scope: what model are we in?

- Security model stated explicitly: semi-honest vs malicious; honest-majority vs dishonest-majority.
- Threat model includes: corrupted parties count `t`, rushing/async assumptions (synchronous rounds vs eventual delivery), and whether the adversary is static or adaptive.
- Output policy defined: who learns the output and when (single party, all parties, or threshold declassification).

## 1) Parameters and invariants

- Field choice: prime `p` is validated (`p` prime; `p` big enough to avoid wraparound/overflow in the intended computation).
- Party IDs: fixed, distinct, non-zero field elements (common choice: `1..n`), and validation rejects duplicates/zero.
- Threshold condition is enforced:
  - For Shamir privacy: `t < n`.
  - For BGW multiplication/degree reduction (passive): `n >= 2t + 1`.
  - If claiming malicious security: check the stronger requirements (and the extra mechanisms) are actually present.
- Degree convention is consistent across the codebase/docs: clarify whether “threshold t” means degree `t` or degree `t-1`.

## 2) Sharing and reconstruction

- Share procedure:
  - Samples a fresh random polynomial for every shared secret (never reuses coefficients across secrets).
  - Samples coefficients uniformly in `F_p` (or uses a documented distribution with justification).
- Reconstruction procedure:
  - Uses interpolation at `x=0` with correct Lagrange coefficients.
  - Validates it has enough shares (at least `t+1`, or `2t+1` if reconstructing after a multiply without reduction).
- Robustness expectations are clear:
  - If malicious behavior is in scope, does reconstruction handle invalid points (VSS/complaints/error correction), or does it silently accept garbage?

## 3) Gate semantics (arithmetic circuit)

- Addition/subtraction:
  - Implemented as local operations on shares (no interaction).
  - Keeps polynomial degree unchanged.
- Multiplication:
  - Code acknowledges degree growth (`t -> 2t`) and performs a degree-reduction/refresh step unless the protocol allows a final unreduced multiplication by design.
  - Checks `n >= 2t+1` before multiplying.

## 4) Degree reduction / refresh (the “BGW moment”)

- The implementation matches the intended protocol:
  - Each dealer re-shares its local product value with a fresh degree-`t` polynomial.
  - Parties recombine received subshares using public coefficients `λ_i` to obtain a fresh degree-`t` sharing of the product.
- Public coefficients:
  - Computed for the correct dealer set and evaluation points.
  - Deterministic and consistent across parties (domain-separated if derived from protocol state).
- Randomness hygiene:
  - Fresh randomness per dealer, per multiplication (no reuse across multiplications).
  - RNG seeding is not attacker-controlled; no “predictable RNG” in production.
- Message flow is clear and authenticated in the intended model (or explicitly omitted in an educational/semi-honest model).

## 5) Correctness checks and test strategy

- Deterministic test vectors exist for:
  - field ops (`inv`, `div`)
  - polynomial eval
  - interpolation coefficients
  - share/reconstruct roundtrip
  - multiply correctness (reconstruct equals cleartext product mod `p`)
- Property tests include:
  - reconstruct from any `t+1` subset (same secret)
  - multiplication correctness over many random cases
  - error rejection for bad inputs (duplicate party IDs, insufficient shares, non-invertible denominators)

## 6) Common real-world failure modes

- Threshold mismatch: code allows `n < 2t+1`, causing multiplication to “work” in some tests but fail silently or leak in general.
- Reused polynomials: re-sharing steps reuse randomness, creating linkability across gates.
- Mixing rings/fields: arithmetic is performed modulo different moduli at different layers.
- Confusing local-vs-global indices: parties disagree on which `x` coordinate a share corresponds to.
- Treating an educational/semi-honest protocol as production-grade without integrity checks (VSS, MACs, commitments, etc.).

