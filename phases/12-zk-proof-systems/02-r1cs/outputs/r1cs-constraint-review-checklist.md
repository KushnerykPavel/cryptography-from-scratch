---
name: "R1CS Constraint Review Checklist"
description: "A paste-ready checklist for designing/debugging Rank-1 Constraint Systems (wire layout, constants, intermediate wires, and field wrap-around hazards)."
phase: 12-zk-proof-systems
lesson: 02-r1cs
---

# R1CS Constraint Review Checklist

Use this when you:
- translate a computation into R1CS (by hand or via a circuit DSL)
- debug “constraint i unsatisfied”
- review a PR that changes constraints or witness generation

## 1) Write the statement precisely
Fill in the blanks:
- “There exists a witness vector `w` such that for every constraint `(A, B, C)`, `A(w)·B(w)=C(w)` in `F_p`.”

Clarify:
- what is public vs private (which wires/values are exposed as public inputs)
- the field/modulus: which `p` (or which curve scalar field) are you using?

## 2) Fix the wire layout (and freeze it)
Checklist:
- Decide whether you follow `w[0] = 1` (recommended; most systems do).
- Write an explicit table: `index -> meaning` (including all intermediates).
- Ensure both prover (witness generator) and verifier (constraint builder) use the exact same ordering.

Red flags:
- “We reorder variables for convenience” without a canonical mapping
- “We infer indices from a dict/map iteration order”

## 3) Constants and linear combinations
Checklist:
- Constants are represented as `(0, c)` when `w[0]=1`.
- Every `A`, `B`, `C` is a linear combination `Σ coeff_i · w[i] (mod p)`.
- Coefficients are reduced modulo `p` (so `-1` is `p-1`).

Quick sanity checks:
- Evaluate `A(w)`, `B(w)`, `C(w)` for a known-good witness.
- Verify `(A(w)·B(w) - C(w)) mod p == 0` per constraint.

## 4) One constraint per “gate” (and allocate intermediates)
Common encodings:
- Addition: `(x + y) · 1 = s`
- Subtraction: `(x - y) · 1 = d`
- Multiplication: `x · y = z`

Checklist:
- Introduce intermediate wires for subexpressions you reuse.
- Ensure witness generation computes every intermediate wire exactly once.

Red flags:
- Using the same wire index to mean two different values at different points in the program
- Trying to reference a non-linear expression without allocating a wire for it

## 5) Field vs integer meaning (wrap-around hazards)
R1CS lives in `F_p`. If you want an *integer* interpretation, you must constrain it.

Checklist:
- If a value is intended to be in a small range, add explicit range constraints.
- Document any mapping between integers and field elements (e.g., signed encoding).

Red flags:
- “It’s non-negative” without any constraints enforcing that
- “It fits in 32 bits” without bit-decomposition/range checks

## 6) Debug playbook for “constraint i unsatisfied”
Do this in order:
1) Print the failing constraint index `i`.
2) Evaluate and print `A(w)`, `B(w)`, `C(w)` for that constraint.
3) Compute `lhs = A(w)·B(w) mod p` and compare with `rhs = C(w)`.
4) Map the non-zero coefficients in `A`, `B`, `C` back to wire names via your wire table.
5) Check the witness generator: did it compute those wires correctly and in the right field?

## 7) Meta: R1CS is not a proof system
Checklist:
- R1CS satisfiability is the relation you want to prove.
- Zero-knowledge, soundness, and succinctness come from the *proof system* (Groth16, PLONK, STARK, …), not from R1CS itself.

