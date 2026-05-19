---
name: prompt-sigma-library-review
description: Review checklist for Σ-protocol implementations (Schnorr, DLEQ, Fiat–Shamir, compositions)
phase: 11
lesson: 12
---

You are reviewing a code change that implements (or modifies) a Σ-protocol or a Σ-protocol-based system (Schnorr PoK, DLEQ/Chaum–Pedersen, OR/AND proofs, or Fiat–Shamir proofs/signatures).

Goal: find the real failure modes (nonce reuse, missing binding, wrong group checks, weak challenge space) and force the author to state the exact relation being proved.

Ask the author for:
- The statement type (public inputs) and witness type (secret inputs)
- The verification equation(s)
- The exact transcript fields and their serialization
- The security target (interactive HVZK PoK? NIZK in ROM via Fiat–Shamir? signature-like?)

Then run this checklist.

## 1) Relation and transcript

1. Write the relation as `R(statement, witness) = True/False`. What is the witness? What is *not* part of it?
2. List the transcript fields: commitment(s) `a`, challenge `c`, response(s) `s`. Are there multiple commitments (e.g., DLEQ has `a1, a2`)?
3. Is the transcript bound to the right context (statement + parameters + protocol id)?

## 2) Group / field validation

1. Are all group parameters validated?
   - For `Z_p*` subgroup: `p` prime (or assumed prime), `q | (p-1)`, generator has order `q`.
2. Are all statement elements validated as belonging to the intended group/subgroup?
   - Reject identity elements when required (`1` in multiplicative groups).
3. Are reductions done in the right modulus?
   - Exponents in `mod q`, group ops in `mod p`.

## 3) Randomness and nonce handling

1. Where does the prover nonce `r` come from?
   - Must be fresh per proof/signature. Never reused across challenges.
2. Is the RNG cryptographic (`secrets` / OS RNG), not `random`?
3. If deterministic nonces are used (for testing or deterministic signatures), is it explicitly scoped and domain-separated to avoid cross-protocol reuse?

## 4) Challenge generation

Interactive Σ:
1. Is the challenge sampled uniformly from a large space?
2. Is there a replay defense (session id, transcript binding, channel binding) if used for authentication?

Fiat–Shamir Σ -> NIZK/signature-like:
1. Is the challenge `c = H(domain_sep || statement || commitment || context)`?
2. Is `domain_sep` non-empty and unique per protocol + version?
3. Is the serialization unambiguous and canonical?
4. Does verification recompute `c` exactly the same way (no hidden defaults, no string formatting differences, no missing fields)?

## 5) Simulation and extraction (sanity checks)

1. Can you write down the HVZK simulator? (Choose `c, s` first, back-compute commitment(s).)
2. Does the code include tests that:
   - Simulated transcripts verify for many `(c, s)` choices.
3. Do you understand the extractor and its precondition?
   - Two accepting transcripts with the same commitment(s) and `c1 != c2`.
4. Is there any risk that the implementation accidentally reuses a commitment while allowing multiple challenges (nonce reuse bug)?

## 6) Pitfalls to explicitly rule out

- Missing subgroup checks (statement not in subgroup)
- Small challenge space (soundness error too large)
- No binding (proof can be transplanted to a different statement)
- Ambiguous transcript encoding (different parsers hash different bytes)
- Mixing moduli (`p` vs `q`)
- Side channels (timing/leaky branches), if secrets handled in software

## 7) What to ask for before approval

1. A 1-paragraph security claim in the PR description (interactive vs Fiat–Shamir, what assumptions).
2. A test that demonstrates:
   - A real proof verifies
   - A simulated proof verifies
   - Nonce reuse extracts the witness (as a negative test / educational test)
3. A clear domain separation string and context-binding list.

