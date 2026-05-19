---
name: prompt-chaum-pedersen-dleq-review
description: Review checklist for Chaum–Pedersen / DLEQ proofs (equality of discrete logs) with focus on statement binding, parameter validation, Fiat–Shamir transcript hashing, and nonce hazards.
phase: 11
lesson: 05
---

# Chaum–Pedersen / DLEQ Proof Review Prompt (Copy/Paste)

You are reviewing a spec, PR, or implementation that claims to implement a
Chaum–Pedersen proof (a DLEQ proof: equality of discrete logarithms) in a cyclic
group of prime order `q`.

Input you will receive:
- The exact statement being proved (all public inputs).
- The proof/transcript format (which fields are sent).
- Challenge generation rule (interactive randomness or Fiat–Shamir hash).
- Group parameters, subgroup order, and validation rules.
- Serialization/encoding rules and byte layout for hashing/signing.
- Any batching, aggregation, or repetition logic.

Your job:
1) Restate what the proof *actually* proves (the relation `R(statement, witness)`).
2) Identify the highest-risk correctness/security issues first.
3) Propose concrete fixes (specific checks and transcript-binding edits).

Return your answer as:
- **Claim Summary:** 3–6 bullets.
- **Transcript Table:** fields, domains, and what each binds to.
- **Findings (highest risk first):** bullets with concrete failure modes.
- **Required Changes:** specific implementation/spec edits.
- **Optional Hardening:** nice-to-have improvements.

## 1) Statement and relation (R)

Mark each item as OK / Risk / Fail:

- Is the statement explicitly written as `(y1, y2, g, h, params, context, ...)`?
- Is the witness explicitly written as `x` such that `y1 = g^x` and `y2 = h^x`?
- Does the protocol prove *equality* of discrete logs (same `x`), not merely
  knowledge of one of them?
- If the proof is used for “equality of openings” (commitments), is the mapping
  from openings to a DLEQ statement explicit?

## 2) Transcript definition and domains

Confirm the exact transcript form and domains:

- Are commitments defined as `a1 = g^r` and `a2 = h^r` using the *same* nonce `r`?
- Are `c` and `s` scalars modulo `q` (not modulo `p`)?
- Are `y1`, `y2`, `a1`, `a2` group elements modulo `p` (or curve points)?
- Is verification exactly:
  - `g^s == a1 · y1^c`
  - `h^s == a2 · y2^c`
  (in the same group)?

## 3) Challenge generation (interactive vs Fiat–Shamir)

Interactive:
- Is `c` sampled uniformly from a challenge space large enough for the desired security?

Fiat–Shamir:
- Is `c = H(domain || statement || commitments || ...) mod q`?
- Does the hash bind:
  - protocol domain/version tag,
  - group parameters (or an unambiguous identifier),
  - the full statement `(y1, y2, g, h, ...)`,
  - both commitments `(a1, a2)`,
  - any application context (message, session id, transcript id)?
- Are encodings canonical and unambiguous (no multiple byte encodings of the same element)?

Hard fail if any are true:
- `c` does not bind the statement and both commitments.
- Domain separation is missing (no protocol/version tag).
- Hash input omits `y1` or omits `y2` (proves a different relation than intended).

## 4) Parameter / subgroup validation (where systems break)

- Are `g`, `h`, `y1`, `y2`, `a1`, `a2` validated as belonging to the intended prime-order subgroup?
- Are identity / small-subgroup / invalid-point edge cases rejected?
- Are scalars reduced and parsed canonically into `[0, q)`?
- Are checks applied on both prover and verifier sides (at least verifier-side)?

## 5) Nonce / randomness safety (catastrophic risk)

- Is the nonce `r` generated with a cryptographic RNG?
- Is `r` unique per proof and per domain/context?
- Can callers supply `r` via an API? If yes, is this flagged as dangerous or prohibited?
- Is there any caching that could accidentally reuse `r` across different challenges?

Explain the risk explicitly:
- If the same `(a1, a2)` occurs twice with different challenges `c1 != c2`, then
  `x = (s1 - s2) · (c1 - c2)^{-1} mod q` is extractable.

## 6) Tests that should exist before merge

- Deterministic vectors: at least one accepting proof and one failing proof.
- Negative tests:
  - wrong `y1` or `y2`,
  - wrong `(a1, a2)`,
  - wrong `s`,
  - wrong hash domain tag,
  - invalid subgroup elements / invalid points.
- Fiat–Shamir binding test: changing any statement field must change `c` and invalidate the proof.
- Nonce-reuse test: two accepting transcripts with same commitments recover `x` (to prove the hazard is understood).

