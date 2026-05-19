---
name: KZG Opening Review Checklist
description: A practical checklist for reviewing KZG polynomial commitment (commit/open/verify) code in PRs.
phase: 09-hashes-commitments-accumulators
lesson: 06-kzg
---

# KZG Opening Review Checklist

Use this when reviewing changes to:
- trusted setup / SRS handling
- polynomial encoding (coefficient order, modulus, degree bounds)
- opening computation (quotient construction)
- pairing verification wiring
- serialization / transcript binding in larger protocols

## 1) Parameters and domains (non-negotiable)

- Field modulus is explicit and consistent everywhere (the polynomial lives in the scalar field `F_r`, not the curve base field `F_p`).
- Group/curve choice is explicit (e.g. BLS12-381) and subgroup checks are enforced where required by the library.
- All points/scalars are reduced mod `r` and validated (reject out-of-range encodings).
- Degree bounds are enforced:
  - commit rejects `deg(f) > max_degree`
  - open rejects inputs exceeding SRS coverage

## 2) SRS / ceremony assumptions

- SRS is treated as public, immutable data (no “regenerate if missing” logic in production paths).
- The code documents the trust model: “binding holds if at least one ceremony contributor was honest”.
- No path accidentally depends on secret toxic waste `s` after setup (e.g., debug hooks, test-only branches).
- If using updateable SRS / Powers of Tau:
  - transcript/hash binding is verified
  - correct final specialization step (to the target curve and power range) is applied

## 3) Polynomial representation (easy to get wrong)

- Coefficient order is pinned down (`[a0, a1, ...]` meaning `Σ a_i x^i`) and matches across prover/verifier.
- Leading-zero handling is specified:
  - trim behavior is consistent
  - degree is computed after trimming
- Evaluation points `z` are interpreted in the right field and reduced mod `r`.
- Any domain separation in higher-level protocols is preserved:
  - “this polynomial is for blobs” vs “this polynomial is for commitments” are not mixed

## 4) Opening computation correctness

- Opening uses the quotient polynomial definition:
  - `q(x) = (f(x) - y) / (x - z)` with `y = f(z)`
- Remainder check exists in tests:
  - dividing by `(x - z)` yields remainder `f(z)` (remainder theorem)
- Edge cases are covered:
  - constant polynomials (degree 0)
  - `z = 0` and `z = 1`
  - `y = 0`

## 5) Verification equation wiring

Confirm the implementation matches the intended equation (additive form shown):

- `e(C - [y], [1]) == e(π, [s] - [z])`

Review checklist:

- `C` is the commitment to `f` (not to `q`, not to coefficients hashed, etc.).
- `π` is the commitment to the quotient polynomial `q`.
- `[y]` is the scalar `y` times the correct generator in `G1`.
- `[z]` is the scalar `z` times the correct generator in `G2`.
- No sign mistakes (`[s] - [z]` vs `[z] - [s]`).

## 6) Security properties (what the code should claim)

- Binding depends on unknown toxic waste `s`. If `s` leaks, openings can be forged (tests should mention this explicitly).
- Basic KZG is not hiding; if the protocol needs privacy, verify that blinding is present and correctly removed/checked.
- If batch verification / aggregation is used:
  - challenges come from a transcript (Fiat–Shamir)
  - the transcript binds the statement (commitment, points, claimed values)
  - duplicates/ordering issues are covered by tests

## 7) Tests that should exist before merge

- Deterministic vectors:
  - known `f`, `z`, expected `y`, and a proof that verifies
  - negative tests: wrong `y`, wrong `z`, tampered proof
- Property tests:
  - linearity: `Commit(f+g) == Commit(f) + Commit(g)`
  - open/verify roundtrip for many random polynomials within degree bounds
- Serialization tests (if relevant):
  - reject non-canonical encodings
  - reject wrong subgroup points

