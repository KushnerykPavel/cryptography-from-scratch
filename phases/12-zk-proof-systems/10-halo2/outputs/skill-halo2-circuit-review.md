---
name: skill-halo2-circuit-review
description: A practical checklist for reviewing Halo2 circuits for missing constraints, selector bugs, and public input mismatches
version: 1.0.0
phase: 12
lesson: 10
tags: [crypto, zk, halo2, plonkish, circuit-review, security]
---

# Halo2 Circuit Review Checklist (PR / Audit)

Use this when reviewing Halo2 circuits (or when auditing your own). The goal is to catch **soundness bugs**: places where a prover can satisfy constraints without proving the intended statement.

## 1) Start with the statement

- What are the **public inputs/outputs**? Where are they assigned (instance column) and where are they constrained to the witness?
- What are the **private inputs**? Where do they enter the circuit (advice columns) and how are they constrained?
- What is the **exact claim** the verifier should learn (e.g., “I know `x` such that ...”)?

If the statement isn’t written down explicitly, stop and ask for it.

## 2) Column map (table mental model)

Write down a table summary:

- Advice columns: what each is supposed to represent
- Fixed columns: constants, selectors, lookup tables
- Instance columns: which indices correspond to which public values
- Any “semantic columns” (e.g., bits, limbs, carry, running sums)

Look for “orphan columns”: columns that get assigned but do not appear in any gate/lookup/copy constraint.

## 3) Gate checks (selectors + rotations)

For each gate, answer:

- What selector enables it? Is it **always enabled on the intended rows** and **disabled elsewhere**?
- Are selector values **boolean** (0/1), or can they accidentally be other field elements?
- Are rotations correct (`cur`, `next`, `prev`)? Is the gate accidentally constraining the wrong row?

Red flag patterns:

- A gate defined in `configure()` but selector is never enabled in `synthesize()`.
- A gate intended for one region but selector is enabled across multiple unrelated regions.
- Rotations that can underflow/overflow because the circuit doesn't assign the boundary rows.

## 4) Copy constraints (value reuse)

Whenever the same logical variable is used in multiple places, ensure there is an explicit equality constraint:

- `layouter.constrain_equal(cell_a, cell_b)` (or equivalent)
- Or the equality is enforced indirectly (e.g., via a shared lookup / permutation usage you can justify)

Red flags:

- A value is “recomputed” in two places and assumed equal, but there is no copy constraint tying them.
- Public input is assigned, but not constrained to the internal witness cell used by the circuit.

## 5) Lookups / range checks

If the circuit claims “this value is in a small set”:

- Is the lookup table correct and fixed?
- Is every value that must be ranged actually ranged (not just the final result)?
- If using bit decomposition: is each bit constrained with `b*(b-1)=0` and is reconstruction enforced?

## 6) “Unconstrained witness” attacks (try to break it)

Try to imagine a cheating prover:

- Can the prover pick different values for “the same” thing in different places?
- Can the prover set some advice cell to any value without consequences?
- Can the prover disable a constraint by keeping a selector at 0?

If you can describe a cheating strategy in words, you likely found a missing constraint.

## 7) Testing expectations (what to demand in a PR)

- Positive tests: `MockProver` passes for valid witnesses
- Negative tests: at least one test that flips a witness bit / breaks an equality and expects failure
- Edge cases: boundary values (0, max range), empty cases, and row-boundary rotations
- If applicable: randomized “fuzz” over small ranges (deterministic seed) to detect accidental under-constraint

## 8) Final sanity questions

- If I delete a gate selector assignment, will tests fail?
- If I change a public input, will the circuit fail (or can the prover “absorb” it)?
- If I change one witness value, do constraints force all dependent values to change consistently?

If any answer is “it might still pass”, ask for a concrete negative test.

