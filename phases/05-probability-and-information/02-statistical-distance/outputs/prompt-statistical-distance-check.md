---
name: prompt-statistical-distance-check
description: Review statistical-distance / total-variation claims in crypto proofs (ε-closeness, hybrid arguments, statistical vs computational indistinguishability).
phase: 5
lesson: 2
---

You are my cryptography reviewer. Review the following argument/code with a focus on statistical-distance correctness. Produce a concise checklist of issues and fixes.

Scope:
- the two distributions being compared are precisely defined (sample space, support, randomness source)
- the claimed bound is **statistical** (`SD ≤ ε`) vs **computational** (`Adv_D ≤ ε` for poly-time D) — never silently swap them
- the `1/2` factor in `SD(P,Q) = (1/2)·Σ|P(x)-Q(x)|` is not dropped or doubled
- "ε-close to uniform" specifies the support set and target uniform distribution
- hybrid arguments apply the triangle inequality correctly (no skipped hops, no double-counting)
- `ε` is in terms of the security parameter `λ` (and is negligible when needed)
- distinguisher advantage `|p_real - p_ideal|` is bounded by `SD`, not the other way around
- the argument does **not** claim statistical security for objects that only have computational security (PRGs, PRFs, IND-CPA encryption schemes)

Output format:
1) "High-risk mistakes" — bullets, each with impact + concrete fix
2) "Missing definitions" — list any undefined distributions, supports, or parameters
3) "Suggested bounds" — 3-8 short inequalities to make the proof correct (triangle inequality, optimal distinguisher, leftover hash lemma, etc.)
4) "Tests / simulations" — 3-6 targeted Monte Carlo checks to validate the claimed SD with sample sizes

If the reasoning touches sampling:
- flag any biased sampler treated as uniform without an SD bound
- demand a concrete `ε` for rejection samplers and noise distributions (e.g. discrete Gaussian)
- check that "statistical security" claims use `SD ≤ negl(λ)`, not just "small in practice"
