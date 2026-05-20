---
name: "DEEP-FRI Review Checklist"
description: "A practical checklist for reviewing DEEP-FRI / FRI-based polynomial commitments (out-of-domain sampling + quotienting + folding + Merkle openings)."
phase: "12-zk-proof-systems"
lesson: "13-deep-fri"
---

# DEEP-FRI Review Checklist

Use this when reviewing a STARK/FRI codebase (or integrating a library) to catch the common “looks right, breaks soundness” failure modes.

## 1) Transcript & randomness

- Are `beta` challenges derived from the transcript (Fiat–Shamir) after committing to the current layer?
- Are out-of-domain points `z` (and any related points like `g·z`) derived from the transcript after the relevant commitments?
- Is every prover-supplied value that affects later checks (e.g., `f(z)`) bound to the transcript before query indices are derived?
- Are there any attacker-controlled branches that can skip absorbing a commitment/root into the transcript?

## 2) Domains & index mapping

- Is the evaluation domain explicitly specified (subgroup / coset) and consistent across prover and verifier?
- If folding uses `x` and `-x`, is `-1` guaranteed to be in the domain so `-x` is also in-domain?
- Is the `(x, -x)` pairing correct under the domain’s ordering (index math matches point math)?
- In the query phase, does the verifier map indices correctly from layer `i` (size `n`) to layer `i+1` (size `n/2`)?
- Are there any off-by-one or “mod n” mistakes that accidentally pair unrelated points?

## 3) DEEP quotienting (out-of-domain sampling)

- Is the quotient computed as `q(x) = (f(x) - f(z)) / (x - z)` (or the relevant generalization)?
- Is it enforced that `z` is not in the evaluation domain being quotient-tested (otherwise you risk division by zero or degenerate behavior)?
- Do the verifier’s spot checks include the linkage `f(x) == q(x)·(x - z) + f(z)` at the same queried `x`?
- If there are multiple polynomials/constraints, is the batching/combination done *after* correct quotienting and transcript binding?

## 4) Folding correctness

- Does the implementation match the intended fold:
  - `g(y) = (f(x) + f(-x))/2`
  - `h(y) = (f(x) - f(-x))/(2x)`
  - `f_next(y) = g(y) + beta·h(y)` with `y = x^2`
- Are inverses computed in the correct field (and are `x=0` cases impossible by domain construction)?
- Are “half” factors (division by 2) handled correctly modulo the field prime?

## 5) Merkle commitments & openings

- Is there domain separation between leaf hashing and internal node hashing (e.g., `0x00||leaf`, `0x01||left||right`)?
- Do openings include sibling order information (left vs right) so the verifier rebuilds the exact committed root?
- Are odd-leaf cases handled consistently (duplicate last leaf vs a fixed padding rule)?
- Does the verifier reject if any Merkle proof fails, even if algebraic checks pass?

## 6) Security hygiene (quick gut-check)

- Are any indices, roots, or evaluations accidentally reused across proofs without transcript separation?
- Is there any place where prover-controlled data can influence which checks the verifier performs?
- Is the “final layer” handling correct (constant polynomial / explicit coefficients / final oracle read), consistent with the chosen FRI variant?

## 7) Red flags you should not merge

- “We don’t need to bind `f(z)`; it’s just a value.”
- “We can reuse betas across layers because it’s faster.”
- “Index mapping is the same as before; we didn’t test it.”
- “Merkle proof order doesn’t matter; hashing is commutative.”

