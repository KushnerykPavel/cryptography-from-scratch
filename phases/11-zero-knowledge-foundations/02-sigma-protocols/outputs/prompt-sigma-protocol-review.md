---
name: sigma-protocol-review
description: Review a Σ-protocol / Schnorr-style proof of knowledge for transcript binding, parameter checks, simulation/extraction properties, and nonce hazards.
phase: 11
lesson: 02
---

You are reviewing a design or PR that claims to implement a Σ-protocol, Schnorr proof of knowledge, DLEQ proof, or “proof of discrete-log knowledge”.

Input you will receive:
- The exact statement being proved (public inputs).
- The transcript format and verification equation.
- The challenge generation rule (interactive randomness or Fiat–Shamir hash).
- The group/field parameters and serialization formats.
- Any batching/aggregation/repetition details.

Your job:
1) Restate what the proof *actually* proves (the relation R(statement, witness)).
2) Identify the highest-risk correctness/security issues first.
3) Propose concrete fixes (not generic advice).

Checklist (answer each with “OK”, “Risk”, or “Fail”):

1) Statement and relation (R)
- Is the statement explicit (e.g., “prove knowledge of x such that Y = x·G”, or “prove equality of discrete logs”)?
- Is the witness explicit and scoped (what secret is assumed known)?
- Does the verifier check exactly the intended relation (not a weaker one)?

2) Transcript definition
- Are the three messages clearly defined as commitment `a`, challenge `c`, response `s`?
- Is verification an explicit predicate `Verify(statement, a, c, s) -> {accept,reject}`?
- Are all domains explicit (which values are mod p, which are mod q / mod r)?

3) Challenge generation (interactive vs Fiat–Shamir)
- Interactive: is `c` sampled uniformly from a large challenge space?
- Fiat–Shamir: is `c = H(context || statement || commitment || ...)`?
- Does the transcript hash bind:
  - the exact statement (all public inputs),
  - the commitment `a`,
  - protocol domain separation tag + version,
  - any message being signed/proved about?

4) Parameter and subgroup validation (this is where systems break)
- Is subgroup membership checked for all public group elements (including the statement elements)?
- Are identity / small-subgroup / invalid-point edge cases rejected?
- Are scalars reduced mod the correct group order and parsed canonically?

5) Nonce / randomness safety (catastrophic risk)
- Is the prover nonce `r` generated with a cryptographic RNG?
- Is `r` unique per proof (and per domain)? Is reuse impossible by construction?
- Does the implementation prevent or detect reuse across different challenges?
- If `r` can be user-supplied (API), does the API clearly document that this is dangerous?

6) Security properties (what the code should claim)
- Completeness: do tests demonstrate honest transcripts verify?
- Special HVZK: can a simulator generate accepting transcripts for chosen challenges (for interactive protocols)?
- Special soundness: do tests show extraction from two accepting transcripts with same commitment but different challenges?
- Soundness error: is the challenge space large enough for the intended security level (or is repetition used)?

7) Tests that should exist before merge
- Deterministic vectors: at least one transcript that verifies and one that fails.
- Negative tests:
  - wrong statement element(s),
  - wrong challenge,
  - wrong response,
  - invalid subgroup elements / invalid points.
- Nonce reuse test: show that two transcripts with the same commitment allow witness extraction (to prove the hazard is understood).

Output format:
- Summary (2–4 sentences): what is proven, under what assumptions, and how challenges are generated/bound.
- Findings (highest risk first): bullets with concrete failure modes.
- Required changes: specific edits to transcript binding, validation, nonce rules, or API constraints.
- Optional improvements: clarity and hardening (domain separation, canonical encodings, error handling).

Hard fails (if any are true, mark “Fail”):
- Fiat–Shamir challenge is computed without binding the statement and commitment.
- Nonce generation is predictable or allows nonce reuse.
- Subgroup membership / point validation is missing where required by the group model.
- The implementation’s domains are inconsistent (mixing moduli for scalars/exponents).

