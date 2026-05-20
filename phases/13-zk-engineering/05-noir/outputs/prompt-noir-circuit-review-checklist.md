---
name: prompt-noir-circuit-review-checklist
description: A practical checklist + prompt for reviewing Noir circuits for soundness, constraints, and security footguns
phase: 13
lesson: 05
---

You are reviewing a Noir ZK circuit for *soundness* (the constraints match the intent), not just style. Use this checklist to find bugs that still produce valid proofs.

## Inputs / Outputs

1. List every `pub` input/output and write (in one sentence) what it reveals to the verifier.
2. List every private input and state what property the proof is supposed to establish about it.
3. For each output, answer: “Is this output *fully determined* by the intended inputs?” If not, flag as **potential underconstraint**.

## Constraint Coverage (the big one)

1. Find all `unconstrained fn`, `unsafe { ... }`, oracle calls, and any code that runs outside the constraint system.
2. For each unconstrained return value, locate the *later* constraints that tie it to:
   - the call arguments, and/or
   - constants, and/or
   - other already-constrained values.
3. If any unconstrained value can flow into outputs without being checked (assert/range check/equality), flag as **critical**.

## Numeric Types: `Field` vs `u*`

1. For each arithmetic-heavy section, note the types: `Field`, `u8/u16/u32/u64`, or mixed.
2. If you see `Field` used where a fixed-width integer is intended (indexes, lengths, money-like values), require explicit range checks (or explicit conversion patterns) and a comment explaining why it is safe.
3. For `u32`/`u64` arithmetic, verify overflow behavior is intended:
   - If overflow must be impossible, there must be constraints preventing it.
   - If wrapping is intended, confirm it is explicit and tested.

## “Assert What You Mean”

1. Every security-critical claim must appear as an `assert`/`assert_eq`/range check:
   - membership (e.g., “in set”)
   - bounds (e.g., “< 2^32”)
   - linkage (e.g., “hash(preimage) == commitment”)
2. If the circuit computes something and never asserts a relation about it, treat it as **dead for soundness**.

## Underconstraint Red Flags

Flag these patterns:

- Outputs derived from values that were never constrained to inputs
- Branches that can skip constraints in some cases without enforcing a safe default
- “Helper” values computed unconstrained and later only partially checked
- Values that can be replaced by an attacker while all constraints still pass

## Review Output Format

Produce:

1. A short summary of what the circuit claims to prove.
2. A list of **must-fix** issues (soundness/security).
3. A list of **should-fix** issues (maintainability/performance/clarity).
4. For each must-fix, propose a concrete constraint or assertion to add (at the code level).

Now review the following Noir code (and any referenced files). If something is missing, ask for it explicitly.

