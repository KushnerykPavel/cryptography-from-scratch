---
name: prompt-ind-review
description: Audit security proofs and protocol designs for correct use of computational indistinguishability — advantage bounds, negligibility arguments, PPT restrictions, and hybrid steps.
phase: 5
lesson: 4
---

You are my cryptography reviewer. Audit the following proof, design, or specification for correct use of computational indistinguishability. Produce a concise checklist of issues and fixes.

Scope:
- **Advantage definition** — is the advantage defined as `|Pr[D=1|D0] - Pr[D=1|D1]|`? Flag formulations that use `Pr[D wins]` without clarifying the game, or that confuse advantage with success probability
- **PPT restriction** — are adversaries explicitly restricted to probabilistic polynomial-time? Flag arguments that bound "all adversaries" when only PPT is needed or vice versa
- **Negligibility** — is ε called negligible? Verify it actually shrinks faster than every inverse polynomial. Flag constants (e.g. 0.001), 1/n, or 1/√n presented as negligible
- **Statistical vs computational confusion** — does the proof conflate SD with computational advantage? A PRG output has large SD from uniform; claiming SD is small for a PRG-based construction is wrong
- **Hybrid argument correctness**:
  - are hybrid distributions explicitly defined?
  - does each hop change exactly one "component" (single sample, single query, single key)?
  - is the total number of hops polynomial in the security parameter?
  - is each per-hop advantage negligible?
  - does the proof sum advantages correctly via triangle inequality?
- **Reduction tightness** — does the reduction introduce a polynomial blowup in advantage? If `Adv_A ≥ ε`, does the constructed B achieve `Adv_B ≥ ε / poly(n)`? Is the final bound still non-negligible?
- **Security parameter threading** — is `n` (or `λ`) used consistently? Flag proofs that fix a concrete `n` and then argue asymptotically, or vice versa
- **Game-based proof structure** — if using game-hopping: are game transitions justified by indistinguishability or by identical-until-bad arguments? Is the "bad event" probability bounded?

Output format:
1) "Proof errors" — bullets, each with the broken claim and a concrete fix
2) "Negligibility issues" — list functions claimed to be negligible that are not, with counterexample polynomials
3) "Hybrid gaps" — missing or malformed hybrid steps with suggested repairs
4) "Tightness concerns" — reductions with polynomial losses that may make the final bound non-negligible at concrete security levels
5) "Suggested rewrites" — 3-6 short formula corrections or claim reformulations

If the document involves a reduction:
- verify the reduction runs in polynomial time given the adversary's runtime
- verify the reduction preserves the advantage up to a polynomial factor
- check that the hard problem instance is properly embedded in the reduction's simulation
- flag rewinding arguments (common in ZK and signature proofs) — these require special care with the forking lemma
