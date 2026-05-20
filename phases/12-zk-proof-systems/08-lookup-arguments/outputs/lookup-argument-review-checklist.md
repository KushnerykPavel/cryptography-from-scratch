---
name: "Lookup Argument Review Checklist"
description: "A practical PR review checklist for lookup arguments (Plookup/Halo2-style): table binding, multiset semantics, row compression, and challenge hygiene."
phase: "12-zk-proof-systems"
lesson: "08-lookup-arguments"
---

# Lookup Argument Review Checklist

Use this checklist when reviewing a circuit/prover/verifier change that adds or modifies **lookups**.
It’s written to be tool-agnostic (Halo2, PLONKish, STARKs, custom systems).

## 1) What is being looked up?
- Is it **scalar membership** (one value per row) or **row membership** (multiple columns)?
- If row membership: what is the row schema (e.g. `(opcode, imm)`, `(x, x^2)`, `(limb0, limb1, carry)`)? Is it documented?
- Are duplicates meaningful? (They almost always are — treat lookups as a **multiset**.)

## 2) Table definition and binding
- Is the lookup table **fixed** (constant/fixed columns), **instance-defined**, or **witness-defined**?
- Is the table (or a table id / commitment) **bound into the transcript** before challenges are derived?
- If there are multiple tables: is there a clear **domain separation** or per-table transcript label?
- If the system supports “dynamic tables”: are there constraints preventing the prover from choosing the table *after* seeing challenges?

## 3) Multiset semantics (the common bug)
- Is the lookup check enforcing multiset membership (counts), not set membership?
- If the implementation does sorting / batching:
  - Are ties handled deterministically?
  - Does the argument still work with repeated values?
- If the table contains repeated values intentionally (e.g. extended tables): is that behavior understood and tested?

## 4) Row compression (θ) correctness
- For row compression `(a, b, c) -> a + θ·b + θ^2·c`:
  - Is `θ` derived from Fiat–Shamir (or verifier randomness), not chosen by the prover?
  - Is `θ` **domain-separated** across different lookup “types”?
  - Are all row entries interpreted in the correct field (modulus) and canonicalized consistently?
- Is there any risk of accidental collisions from:
  - Too-small field,
  - Low-entropy `θ`,
  - Reusing the same `θ` in unrelated contexts?

## 5) Challenge hygiene and transcript design
- Are challenges derived **after** all relevant commitments are absorbed?
- Is every challenge usage **domain-separated** (labels, tags, table ids)?
- Are there any “silent mismatch” risks from encoding:
  - Endianness differences,
  - Missing length prefixes,
  - Different normalization of negative/large integers?

## 6) Soundness and assumptions
- What enforces that the prover’s claimed evaluations/openings correspond to the committed objects?
  - Polynomial commitment openings (KZG/IPA),
  - Merkle openings (STARK),
  - Argument-specific opening proofs.
- Are there explicit notes on the required hardness assumptions (e.g., binding of commitment scheme)?
- If this is a “toy” or research prototype: is it clearly labeled as such?

## 7) Edge cases and tests
- Do tests cover:
  - Empty lookup set,
  - All values identical,
  - Values at boundaries (e.g. 0, max limb),
  - Multiple tables,
  - Multiple lookups batched together?
- Do tests include **negative** cases (should reject):
  - One value missing from table,
  - Duplicate value looked up too many times,
  - Tampered proof/opening.

## 8) Performance considerations
- Are lookups batched where appropriate?
- Is there a clear cost model (rows, columns, tables)?
- Does the implementation avoid accidental quadratic behavior (e.g., naive membership checks in prover hot path)?

## 9) “What would I change to break it?”
Ask these adversarial questions in review:
- If I swap the table after commitments, does verification still pass?
- If I reorder values / introduce duplicates, does anything break?
- If I reuse a challenge across two different arguments, can I satisfy both with one forged object?
- If I corrupt one opening/evaluation, is it detected?

