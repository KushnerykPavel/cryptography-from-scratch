---
name: "Sumcheck-First zkVM Review Checklist"
description: "A practical checklist for reviewing trace→MLE→sumcheck→PCS code paths (Jolt/SP1-style)."
phase: "13-zk-engineering"
lesson: "07-sp1-jolt"
---

# Sumcheck-First zkVM Review Checklist

Use this checklist in PR reviews for zkVM provers/verifiers that rely on multilinear polynomials + sumcheck (and then a polynomial commitment scheme (PCS) to make the final evaluation check succinct).

## 1) Statement clarity

- What is the exact claim being proven (one sentence)? Example: “This committed trace satisfies all transition + lookup constraints for T steps.”
- What is the domain of the sumcheck (which Boolean cube, which variable order)?
- What is the field (modulus / extension field), and what is the intended soundness error?

## 2) Trace → constraints → composition

- Constraints are local and explicitly tied to trace columns (`local`, `next`, and any cross-row reads).
- Constraint composition is explicit: if multiple constraints are combined, the random coefficients are derived from the transcript.
- Indexing is consistent: step `t` corresponds to one unique point in `{0,1}^k` (no off-by-one on the last row).
- Padding behavior is specified for non-`2^k` trace lengths (what rows/values are padded, and why it preserves the claim).

## 3) Multilinear encoding (MLE)

- Variable order is documented (LSB-first vs MSB-first) and matches:
  - evaluation-table layout in memory,
  - folding order in evaluation,
  - sumcheck round order.
- MLE evaluation uses a stable folding routine (pairwise fold with `(1−r)` and `r`).
- All arithmetic is reduced mod `p` at every step (avoid accidental big-int growth and mismatched semantics).

## 4) Sumcheck protocol integrity

- Each round checks the consistency condition (for multilinear degree-1 rounds: `s0 + s1 == claim`).
- Challenges `r_i` are derived after appending the prover message for round `i` (Fiat–Shamir ordering).
- Domain separation: each round’s label is unique (e.g. `sumcheck_round_i`, `r_i`), and labels don’t collide with other subprotocols.
- Any batching uses a clearly-defined aggregation strategy and transcript binding (don’t “just concatenate” without thinking).

## 5) Fiat–Shamir transcript discipline

- The transcript is initialized with a domain separator for the protocol/version.
- The transcript binds to:
  - instance data (public inputs),
  - commitments to witness polynomials (trace commitments / table commitments),
  - any protocol configuration that affects interpretation (dimensions, arity, degrees).
- Encodings are unambiguous (length-prefix or structured serialization; no “join with commas”).

## 6) PCS / opening plumbing (where most bugs hide)

- The final check “verifier needs `g(r)` once” is implemented as:
  - PCS opening at the correct point `r`,
  - correct polynomial id / commitment id,
  - correct transcript binding (opening proof uses the same transcript state).
- Multi-openings are batched carefully: proof verifies the batch claim, not just individual opens.
- Any “virtual polynomial” is never accidentally treated as “committed” (and vice versa).

## 7) Soundness & negative tests

- There is at least one adversarial test that flips a single trace cell and confirms verification fails.
- There is at least one test for each pitfall class:
  - swapped variable order,
  - wrong padding,
  - missing transcript binding,
  - wrong commitment id/opening point.
- “Seems fine” is not a test: assertions check exact failure modes and reject paths.

## 8) Performance sanity (even in correctness PRs)

- Hot loops are linear in the trace size (no accidental `O(n log n)` sorts in the prover inner loop).
- Allocations are controlled (reuse buffers across rounds; avoid per-round reallocation of full tables).
- Debug logging is gated; no per-row printing.

## 9) Review heuristics

- If a change touches transcript labels/serialization, require:
  - test coverage proving determinism,
  - a migration note if proofs must remain verifiable across versions.
- If a change touches indexing/order, require a one-page invariants note: “this index means this point”.

