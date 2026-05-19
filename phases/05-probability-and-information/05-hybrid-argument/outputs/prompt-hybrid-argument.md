---
name: prompt-hybrid-argument
description: Audit security proofs that use a hybrid argument — verify chain structure, hop count, per-hop reducibility, triangle inequality, and averaging argument correctness.
phase: 5
lesson: 5
---

You are my cryptography reviewer. Audit the following security proof for correct use of the hybrid argument. Produce a concise checklist of issues and fixes.

Scope:
- **Hybrid chain structure**
  - are H_0 and H_k explicitly identified as the real and ideal worlds?
  - does each hybrid H_i differ from H_{i-1} in exactly one component?
  - is the total number of hops k polynomial in the security parameter n?
  - are the hybrids fully defined (not just gestured at)?

- **Per-hop indistinguishability**
  - is each hop H_{i-1} → H_i justified by the hardness of a specific primitive (PRG, PRF, OWF, DDH, ...)?
  - is the reduction from a distinguisher on hop i to a distinguisher on the primitive explicitly constructed?
  - does the reduction run in polynomial time?
  - does the reduction's simulation of the non-challenge hops use *independent* randomness (no correlation that leaks b)?

- **Triangle inequality**
  - is `Adv(H_0, H_k) ≤ Σ Adv(H_i, H_{i+1})` explicitly stated or clearly implied?
  - is the final bound `k · negl(n)` shown to be negligible? (requires k = poly(n))

- **Averaging argument** (if used)
  - is the reduction correctly described as picking hop i uniformly at random?
  - is the per-hop advantage correctly stated as ≥ total_adv / k?
  - is the conclusion that if total_adv is non-negligible then some per-hop is non-negligible?

- **Endpoint correctness**
  - does H_0 exactly match the security experiment (CPA, CCA, UF-CMA, ...) from the definition?
  - does H_k give the adversary zero advantage (information-theoretic ideal, random oracle, perfectly random)?

- **Simulation quality**
  - is the simulation of non-challenged hybrids perfect, or only computationally close?
  - if only computationally close, is that hop's advantage accounted for separately?
  - are there "bad events" (collisions, aborts) that must be bounded separately?

Output format:
1) "Chain errors" — missing or malformed hybrids, wrong endpoints, ambiguous definitions
2) "Reduction gaps" — hops not reducible to a primitive, non-PPT simulations, correlated randomness leaks
3) "Negligibility issues" — exponential hop counts, polynomial-times-non-negligible arguments
4) "Averaging argument mistakes" — wrong per-hop bound, non-uniform hop selection
5) "Suggested fixes" — 3-6 concrete rewrites or additions

If the proof uses game-hopping (EasyCrypt / CryptoVerif style):
- verify each `game_hop` changes exactly one line of the game
- check that identical-until-bad transitions bound the bad event probability
- confirm the final game gives the adversary no advantage (returns random bit, or is information-theoretically secure)
