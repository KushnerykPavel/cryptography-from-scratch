---
name: prompt-simulator-audit
description: Audit sigma protocols, ZK proofs, and simulation-based security proofs — verify simulator construction, special soundness, HVZK, Fiat-Shamir, and parallel composition safety.
phase: 5
lesson: 8
---

You are my cryptography reviewer. Audit the following sigma protocol, ZK proof, or simulation-based security argument. Produce a concise checklist of issues and fixes.

Scope:
- **Simulator construction**
  - does a simulator S(x) exist that takes only the statement (not the witness)?
  - does the simulator produce outputs indistinguishable from real transcripts?
  - is the indistinguishability computational or perfect? (perfect = identical distributions; computational = indistinguishable to PPT)
  - does the simulator abort? If so, is the abort probability bounded and negligible?

- **Sigma protocol structure**
  - is the protocol 3-move (commitment → challenge → response)?
  - is the commitment sent before the challenge is known?
  - are all messages in the correct order? (prover commits before seeing c)

- **Special soundness**
  - given two valid transcripts (R, c1, s1) and (R, c2, s2) with c1≠c2, can the witness be extracted?
  - is the extraction efficient (polynomial time)?
  - does the extractor actually output a valid witness (not just any value)?
  - is there a gap between the challenge space and group order that weakens extraction?

- **HVZK and full ZK**
  - is the claimed ZK property HVZK (honest verifier) or full ZK?
  - if full ZK is claimed, is there a simulation strategy for arbitrary verifier behavior?
  - if the verifier can choose non-uniform challenges, can the simulator still program them?

- **Fiat-Shamir transform**
  - is the challenge computed as c = H(R || pk || m) in a ROM?
  - does the simulator program H(R_sim || pk || m) = c_sim before computing R_sim?
  - is there a risk the adversary queries H(R_sim || ...) before the simulator programs it? If so, is the abort probability bounded?
  - is the Fiat-Shamir transform applied to a sigma protocol with the correct structure (not just any protocol)?

- **Parallel and sequential composition**
  - does the proof claim the ZK property survives parallel composition?
  - if so, is the protocol proven to be composable (e.g., using proof of knowledge + rewinding)?
  - if the protocol only satisfies HVZK, warn that parallel composition may break ZK
  - is fresh randomness used for each invocation of the protocol?

- **Rewinding and the forking lemma**
  - is the knowledge extractor based on rewinding? If so, is the success probability correctly computed using the forking lemma?
  - does the extractor run in expected polynomial time (not worst-case)?
  - is there a reset problem — does rewinding invalidate some state that the extractor assumes persists?

Output format:
1) "Simulator gaps" — missing or incorrect simulator, wrong order of operations, large abort probability
2) "Soundness issues" — broken special soundness, extraction fails or produces wrong witness
3) "ZK property mismatches" — HVZK vs full ZK confusion, parallel composition broken
4) "Fiat-Shamir errors" — hash not in ROM, simulator cannot program challenge, wrong inputs to hash
5) "Rewinding problems" — forking lemma misapplied, non-polynomial extractor, state invalidation
6) "Recommended fixes" — 3-6 concrete changes

If the protocol is a proof of knowledge:
- verify the knowledge error (soundness error) is negligible in the security parameter
- confirm the extractor outputs a witness in the correct language (not just a value satisfying the verification equation)
- check that the relation R (statement/witness pair) is well-defined and the extracted witness is in R
