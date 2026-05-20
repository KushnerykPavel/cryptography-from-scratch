---
name: zk-arithmetic-circuit-review-checklist
description: Copy/paste checklist for reviewing arithmetic-circuit specs/implementations for ZK (field, constraints, witness, and underconstraint risks).
phase: 12
lesson: 01
---

# Arithmetic Circuit Review Checklist (Copy/Paste)

You are reviewing a ZK circuit (Circom / Halo2 / Noir / Arkworks R1CS / Plonkish
DSL) or a PR that introduces new constraints. Your goal is to answer:

1) What computation is being proved?
2) What is public vs private?
3) Are the constraints complete (no slack / underconstraint)?
4) Is the field/arithmetization consistent with the proof system?

Return:
- A 5–10 bullet summary of the intended statement.
- A list of concrete constraint gaps or attack surfaces.
- A short “questions for the author” list.

## 0) Pin down the statement

Write these explicitly:

- Public inputs: `x = ...`
- Private witness: `w = ...`
- Output(s): `y = ...` (or accept/reject only)
- Relation: `R(x, w) = true` expressed as equations over the field

If you can’t write `R(x, w)` as equations, you can’t review soundness.

## 1) Field sanity

- What field is this circuit over? (`F_p` for some prime `p`, or `F_{p^k}`?)
- Is `p` the *native* field of the curve/proof system, or are there non-native
  field emulation gadgets?
- Are there any places that treat values as “integers” instead of field
  elements (e.g., missing mod reduction assumptions)?
- Are there cross-field values mixed accidentally (e.g., hashing bytes into one
  modulus but constraining in another)?

## 2) Constraint completeness (the big one)

For each “important claim” in the circuit, identify the constraint that forces it.

Common missing constraints:

- **Booleanity**: a value meant to be a bit must satisfy `b*(b-1)=0`.
- **Range bounds**: a value meant to be < 2^k must be range-checked.
- **Conditional logic**: “if flag then A else B” must be enforced with selectors,
  not with host-language branching during witness generation.
- **Equality**: “these two wires should match” must be an explicit constraint.
- **Uniqueness**: “this is the only solution” often needs extra constraints.

Red flag: “we compute it in the witness generator so it’s true.”
If it’s not constrained, a malicious prover can lie.

## 3) Witness story

- How is the witness computed? Is it deterministic from inputs?
- Are there intermediate wires whose values are never constrained (free wires)?
- Do any constraints accidentally allow division by zero, or rely on inverses
  without guarding denominators?
- Are public inputs bound exactly (not just “used somewhere”)?

## 4) Gate/constraint accounting

- Count constraints: does the circuit complexity match what’s being claimed?
  A “complex” feature with suspiciously few constraints often indicates a bug.
- Are constants constrained correctly (not accidentally mutable witness wires)?
- Are you relying on “one-time setup” assumptions that don’t hold (e.g., a
  verifier that doesn’t actually know the same circuit hash)?

## 5) Questions to ask the author

- “Point me to the constraints that enforce each item in the statement.”
- “What happens if I set this intermediate wire to an arbitrary value?”
- “Which values are intended to be bits / small integers / hashes? Where are
  those constraints enforced?”
- “What field are we working in? Where is it defined, and is it consistent end-to-end?”

