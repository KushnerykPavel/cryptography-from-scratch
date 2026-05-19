---
name: "ZK Range Proof Review Checklist (Bit Decomposition)"
description: "A paste-ready checklist for designing/reviewing range proofs for Pedersen-committed values (bit proofs, linking, statement binding, edge cases)."
phase: 11-zero-knowledge-foundations
lesson: 07-range-proofs
---

# ZK Range Proof Review Checklist (Bit Decomposition)

Use this when you see:
- Pedersen commitments (`C = v·G + r·H` or `C = g^v h^r`)
- hidden amounts / balances / votes
- claims like “range-checked”, “non-negative”, “fits in 64 bits”

## 1) Write the exact statement (what is being proven?)
Fill in the blank:
- “Prover knows an opening `(v, r)` to commitment `C`, and `v ∈ [min, max]`.”

Be explicit about:
- inclusive vs exclusive bounds (`[0, 2^n)` vs `[0, 2^n-1]`)
- signed vs unsigned interpretation
- whether `v` is interpreted as an integer or as an element of `Z_q`

## 2) Check the arithmetic domain (wrap-around hazards)
Range proofs only make sense when the intended range is smaller than the scalar field / group order.

Checklist:
- Confirm `max < q` (or `2^n < q` for `[0, 2^n)`)
- Confirm there’s no “negative value becomes q - x” ambiguity
- If your protocol uses modular arithmetic, document how integers are mapped into `Z_q`

Red flags:
- “We commit to an amount mod q” with no separate range proof
- Range boundary close to `q` (easy to wrap)

## 3) “Bit proof” correctness (set membership)
For classic bit-decomposition range proofs:
- Prover produces commitments `C_i` to digits `b_i`
- Prover proves each `b_i ∈ {0, 1}` (a set membership proof)

Checklist:
- Proof really enforces membership, not just “has *some* opening”
- Verification checks every digit proof, for every `i` expected by the range
- Digit count is fixed and agreed (`n_bits` is a public parameter)

Red flags:
- Missing digit proofs for some indices
- Verifier accepts variable-length decompositions without a canonical rule

## 4) “Linking” correctness (recomposition / consistency)
Digit proofs alone are not enough. You must also link digits back to the original commitment.

Checklist:
- Verifier recomposes a derived commitment `D` from digit commitments (homomorphism)
- Prover provides a proof that `D` and `C` commit to the same value (possibly with different blinding)
- The linking proof is bound to the full statement (including `C`, all `C_i`, and `n_bits`)

Red flags:
- Range proof verifies digits but never checks they recombine to the committed value
- Linking proof doesn’t include all commitments / statement inputs in its Fiat–Shamir hash

## 5) Statement binding and domain separation (Fiat–Shamir footguns)
For non-interactive proofs:
- Challenges must be derived as `c = H(label, statement, commitments, context, ...)`

Checklist:
- Use a unique, protocol-specific `label` (domain separation)
- Hash all public inputs (group id, generators, commitment(s), any context/session id)
- For per-digit proofs, include the digit index `i` (or ensure canonical ordering)

Red flags:
- `c = H(t)` only
- Omitting the statement (e.g., commitment `C`) from the transcript hash

## 6) Group / curve validity checks
Checklist:
- Verify group membership / subgroup membership for every public element (commitments, generators)
- Reject identity/zero elements where invalid
- Use canonical serialization before hashing (no ambiguity, no multiple encodings)

Red flags:
- “We trust inputs are points on the curve”
- No subgroup checks in cofactor-bearing curves

## 7) Performance realism
Classic bit-decomposition range proofs are linear in `n` and large for `n=64`.

Checklist:
- If you need many 64-bit range proofs, consider Bulletproofs-style proofs or a circuit-based proof system
- If you batch proofs, confirm batching is sound and statement-bound

## 8) Quick reviewer questions
- What is the statement, exactly, and is it hashed into the Fiat–Shamir transcript?
- What prevents wrap-around (`2^n < q`) and negative/overflow amounts?
- Are digits proven to be bits, and are they linked back to the original commitment?
- Are per-digit indices and ordering bound to the transcript (no swapping attacks)?
- Are all inputs validated for group/subgroup membership?

