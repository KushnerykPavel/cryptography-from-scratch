---
name: "QAP Review Checklist"
description: "Prompt + checklist for reviewing R1CS→QAP conversions and divisibility checks (Pinocchio/Groth16-style arithmetization)."
phase: "12-zk-proof-systems"
lesson: "03-qap"
---

# QAP Review Checklist (R1CS → QAP)

Use this when reviewing code that:
- converts an R1CS `(A,B,C)` into per-wire polynomials `(A_j(x), B_j(x), C_j(x))`,
- constructs the vanishing/target polynomial `t(x)`,
- checks `t(x) | (A(x)B(x) - C(x))` (or the equivalent “in-the-exponent” identity).

## Context to request from the author

1. Field `F_p` (or `F_r`) and why it’s the right modulus for the circuit.
2. R1CS conventions:
   - Is wire 0 the constant `1` wire?
   - How are public inputs separated from private witness wires (if at all)?
3. Constraint domain:
   - What points `{x_1,…,x_m}` are used for constraints?
   - Are they fixed deterministically (recommended) or derived from a transcript/CRS?

## Checklist: R1CS → per-wire polynomials

- `m` constraints, `n` wires, and matrices `A,B,C` are all shaped consistently (`m×n`).
- Constraint points `{x_i}` are **distinct mod p**.
- For every wire `j`, polynomials satisfy:
  - `A_j(x_i) == A[i][j]` for all `i`
  - `B_j(x_i) == B[i][j]` for all `i`
  - `C_j(x_i) == C[i][j]` for all `i`
- Degree bounds are correct:
  - each per-wire polynomial has degree `< m`
  - `t(x)` has degree `m`

## Checklist: Aggregation from a witness

Given witness `a = (a_0,…,a_{n-1})`:
- Aggregates are constructed as **the same witness** across all three families:
  - `A(x) = Σ_j a_j·A_j(x)`
  - `B(x) = Σ_j a_j·B_j(x)`
  - `C(x) = Σ_j a_j·C_j(x)`
- Constant wire is handled correctly: `a_0` is forced/assumed to be `1`.
- All arithmetic is performed in the correct field (every add/mul reduces mod p).

## Checklist: Divisibility / quotient polynomial

- Define `P(x) = A(x)B(x) - C(x)` (or equivalent).
- Check either:
  - polynomial division: `P(x) = t(x)·h(x)` with remainder `0`, or
  - evaluation identity at a secret point τ (SNARK form): `P(τ) == t(τ)·h(τ)`.
- If doing polynomial division:
  - division handles leading coefficients correctly (needs inverses in `F_p`)
  - trimming/normalization does not accidentally drop information
  - remainder is exactly the zero polynomial (not “close to zero”)

## Common failure modes (high-signal)

- Mixing “per-wire” and “aggregated” polynomials (building `A(x)` incorrectly).
- Using non-distinct constraint points `{x_i}` (interpolation undefined or inconsistent).
- Wrong target polynomial:
  - using the wrong domain,
  - deduplicating points incorrectly,
  - or shifting indices (off-by-one in `x_i` vs constraint row `i`).
- Forgetting the constant wire or letting the prover choose `a_0`.
- Assuming “divisibility holds” implies the witness corresponds to a valid circuit execution.
  - In real protocols, cryptography is used to *bind* the prover to the committed polynomials and a single consistent witness.

## Suggested minimal tests to ask for

1. A tiny worked example with 2–3 constraints where `P(x)` is divisible by `t(x)` for a valid witness.
2. The same example with one witness coordinate tampered, showing non-zero remainder.
3. A property test that for random `xs, ys` the interpolated polynomial satisfies `f(xs[i]) == ys[i]`.

