---
name: prompt-zk-meaning-review-checklist
description: Review checklist for claims about “zero-knowledge” (completeness, soundness, ZK, HVZK), grounded in transcript simulation.
phase: 11
lesson: 01
---

# Zero-Knowledge Meaning Review Checklist (Copy/Paste)

You are reviewing a protocol, spec, or PR that claims to use “ZK” or “a SNARK”.
Your goal is to pin down exactly what is being claimed and whether the design
actually provides it.

Return:
1) A one-paragraph summary of the claimed security properties.
2) A table of assumptions/threat model.
3) A list of concrete questions to ask the author.
4) A list of red flags / likely failure modes.

## 0) Name the artifacts

Fill these in explicitly before judging anything:

- Statement (public input): `x = ...`
- Witness (secret): `w = ...`
- Verifier output: accept/reject, plus any other outputs
- Transcript: what messages are sent (and what randomness is used)
- What is published on-chain / logged / stored?

If the author can’t write this down cleanly, the protocol isn’t ready.

## 1) Completeness check

- On *true* statements, does an honest prover convince an honest verifier?
- What is the failure probability (should be negligible)?
- Are there edge cases where the prover can fail even with a correct witness
  (e.g., non-invertible element, invalid subgroup element, malformed encoding)?

## 2) Soundness check (and what kind)

Ask which claim is intended, and whether the math matches it:

- Soundness (proof): information-theoretic / unconditional, typically requires an
  all-powerful prover model and often longer interaction.
- Computational soundness (argument): holds only against poly-time provers, under
  hardness assumptions (this is what most SNARKs are).
- Knowledge soundness (PoK): “if you can convince me, you must *know* a witness.”
  This usually comes with an extractor definition, not just “it seems hard”.

Concrete questions:

- What is the soundness error `ε` (per proof) and how is it computed?
- Is soundness amplified by repetition? Where and how?
- If the protocol is non-interactive, what replaces the verifier’s randomness
  (Fiat–Shamir / transcript hashing / CRS)?

## 3) Zero-knowledge check (what “ZK” actually means)

Force the simulator mental model:

- What does the verifier “see”? (Transcript + its own randomness + public inputs.)
- Is there a simulator that can generate an indistinguishable view without the witness?
- Is the claim:
  - HVZK (only for honest verifier randomness)?
  - ZK against arbitrary/malicious verifiers?
  - Statistical / perfect ZK, or only computational ZK?

Concrete questions:

- What exactly is the simulator’s input? (Usually the statement only.)
- Does the simulator need any trapdoor (CRS trapdoor, setup secret)?
- If Fiat–Shamir is used, what is the transcript hash domain separation?
  What binds the proof to the statement and context?

## 4) “ZK” vs “validity proof” vs “privacy”

Use this to catch the most common engineering confusion:

- Validity proof: “the computation was done correctly” (soundness).
- Zero-knowledge: “the proof leaks nothing beyond validity” (simulation).
- Privacy: “an attacker can’t learn user data from the whole system” (bigger than ZK).

Ask:

- If the proof is ZK, what exactly is hidden (witness)? What remains public (statement)?
- Are any witness-derived values accidentally placed into the public statement or logs?
- What side channels exist (timing, memory access patterns, metadata, input sizes)?

## 5) Parameter / setup model

- Is there a CRS? If yes, who generates it and what happens if it’s toxic?
- Universal vs circuit-specific setup?
- Updatable ceremonies / MPC?
- Are keys/parameters versioned and pinned in code?

## 6) Transcript integrity

- Are transcripts bound to the statement, protocol version, and application context?
- Are challenges unpredictable to the prover at the time it commits?
- Are nonces / randomness ever reused? (If yes: treat as “witness leakage until proven otherwise”.)

## 7) Red flags (call these out explicitly)

- “We use ZK” with no statement/witness separation written down.
- “It’s a SNARK so it’s private” (soundness ≠ zero-knowledge).
- Fiat–Shamir without domain separation or without binding to the statement.
- Reused/biasable randomness on the prover side (nonces, r-values, seeds).
- Claims of “perfect ZK” with only heuristic argument and no simulator story.
- Unclear setup assumptions (“trusted setup” handwaved).

## 8) Output format

Produce your answer as:

- **Claim Summary:** 3–6 bullet points.
- **Threat Model Table:** attacker, capabilities, what they observe, what must be protected.
- **Questions for Author:** numbered list, concrete and testable.
- **Likely Failure Modes:** 5–10 bullets, prioritized by severity.
