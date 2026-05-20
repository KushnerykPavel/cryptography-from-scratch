---
name: zk-circuit-review-checklist
description: A practical checklist for reviewing Circom (or any R1CS-style) circuits for soundness, safety, and proof-system fit.
version: 1.0.0
phase: 13
lesson: 01
tags: [zk, circom, r1cs, circuits, snark]
---

Use this checklist in PR review for Circom circuits, Noir circuits, or any \"constraints + witness\" codebase. The goal is to catch *soundness bugs* (a proof that shouldn't verify), not style.

1) Spec first
- Write the statement precisely: public inputs vs private witness, and what \"valid\" means.
- Write the allowed ranges for every integer-like signal (bit-length, signedness, endianness).
- Write the field: BN254, BLS12-381, Pasta, etc. List any hash/curve assumptions.

2) Range / domain checks (the #1 footgun)
- Every \"number\" used as an integer has an explicit range check (bits decomposition, lookup/range gadget, or verified limb representation).
- Every boolean is constrained: `b * (b - 1) == 0`.
- Every selector used in `out = b*x + (1-b)*y` is boolean and range-checked.
- Any division is justified: you either prove `den != 0` or avoid division entirely (use `IsZero`-style gadgets).

3) Equality vs assignment
- Anything that must hold in the proof is enforced by constraints, not by witness code.
- No critical condition relies on `===` in code without a matching constraint (\"set this value\" is not \"prove this value\").

4) Field arithmetic gotchas
- Check for unintended wraparound: `x + y == z` is modulo `p`; range-check if you mean integer arithmetic.
- Check signed/unsigned conversions and limb packing/unpacking are consistent and constrained.
- Ensure constants are reduced mod `p` and comparisons are done as integers (with bit decomposition), not as field comparisons.

5) Gadgets and reuse
- Prefer audited, well-known gadgets (Poseidon, MiMC, LessThan, Num2Bits) from established libraries.
- If you wrote a new gadget, include: constraints count, trusted assumptions, and at least one negative test (should reject).

6) Public inputs and binding
- Public inputs are minimal but sufficient to bind the statement (no \"free\" degrees of freedom).
- If the circuit proves knowledge of something, ensure the output commits/binds to that thing (hash, Merkle root, signature verify, etc.).

7) Adversarial witness mindset
- For every constraint set, ask: \"Can I satisfy constraints with a different semantic meaning?\" (e.g., weird field element that passes without range checks).
- Add a test that tries to cheat by changing witness values while keeping public inputs fixed.

8) Proof system / tooling fit
- Constraint count and witness size are measured and tracked (regression budget).
- Any recursion / aggregation constraints are compatible with the chosen curve and verifier environment.
- Build pipeline is reproducible: pinned circom/snarkjs/noir versions, deterministic artifacts, CI verifies keys/constraints.

Deliverable for a PR:
- A short \"Statement & Ranges\" section in the PR description.
- At least 3 tests: happy path, wrong public input, and a \"cheating witness\" attempt.

