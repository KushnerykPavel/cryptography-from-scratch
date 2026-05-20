---
name: halo2-circuit-review-checklist
description: A practical checklist + prompt template for reviewing Halo2 (Rust) circuits: selectors, equality constraints, public IO, lookups, and layout hazards.
version: 1.0.0
phase: 13
lesson: 3
tags: [halo2, plonkish, zk, circuits, rust, review, selectors, lookups, permutation, instance]
---

Use this as a PR review checklist for Halo2 circuits (or paste it as a prompt into a code-review assistant).

Goal: decide whether the circuit is **sound**, **correctly constrained**, and **maintainable**.

## 1) Circuit summary (1–3 sentences)
- What statement is the proof supposed to convince the verifier of?
- What are the public inputs/outputs (instance columns), and what do they mean?

## 2) Table model sanity check
- List columns by type:
  - Advice columns (witness / intermediates):
  - Fixed columns (constants / selectors / tables):
  - Instance columns (public IO):
- For each custom gate, write the intended constraint as an identity `q(row) * t(row) = 0`.
- Confirm every queried cell in every enabled row is assigned in synthesis.

## 3) Selectors (soundness-critical)
For each gate/lookup selector:
- Where is it enabled?
- Is it enabled on *every* row where the gate’s queried cells are assigned?
- Can it accidentally be enabled on rows that don’t have a complete assignment for the queried cells?
- If it’s a “complex selector”, is it combined with other selectors in a way that could exceed the max degree?

Red flags:
- A selector exists but is never enabled.
- A selector is enabled in a loop with the wrong offset (off-by-one row).
- A gate is “always-on” when it should be conditional (constraints leak across unrelated rows).

## 4) Equality / copy constraints (permutation argument)
- Which columns have equality enabled (`meta.enable_equality(col)`)?
- For each value that must be reused across rows/regions, where is the equality constraint created?
- If a helper method does a “copy”, verify it actually creates a constraint (not just re-assigning the same integer).

Red flags:
- Two cells are assigned the same value but no equality constraint ties them together.
- Equality is enabled on too few columns, causing ad hoc workarounds or silent bugs.

## 5) Public IO (instance column) correctness
- List every `constrain_instance(cell, instance_col, row)` call.
- Verify the row indices match the external protocol/API (especially if multiple proofs compose).
- Confirm the circuit enforces *meaningful* binding between witness and instance (not just re-exposing a value without constraining it).

Red flags:
- Instance row indices drift due to refactors.
- A public output is assigned but not constrained (or constrained to the wrong cell).

## 6) Lookups / range checks
- Identify each lookup: what is being looked up, and in which table column(s)?
- Confirm the table is fully loaded (and loaded exactly once, in the intended location).
- If range checks are implemented via decomposition, verify bit/limb constraints are all present.

Red flags:
- Lookup inputs not conditioned by the same selector that conditions the gate.
- A table is loaded with the wrong domain (e.g., missing 0 or missing max value).

## 7) Degree / performance / layout notes
- What is the intended max degree? Do the gates/lookups respect it?
- Are there “expensive” patterns (many lookups, large fan-in, duplicated constraints) that can be simplified?
- Are regions structured so the layouter can pack them efficiently (or is it forced into a bloated layout)?

## 8) Failure mode review (attack mindset)
For each constraint family, answer:
- If this constraint were accidentally disabled (selector bug), could a prover produce an invalid proof?
- If this constraint were missing (equality/lookup bug), what “cheat” would become possible?

## 9) Reviewer verdict
Return:
- **Correctness:** pass / needs changes (1–2 sentences)
- **Soundness risk:** low / medium / high (1 sentence)
- **Top 3 issues:** bullets with file/function pointers
- **Suggested fixes:** bullets, prioritized

