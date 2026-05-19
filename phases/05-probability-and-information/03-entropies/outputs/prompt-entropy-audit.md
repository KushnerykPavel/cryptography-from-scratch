---
name: prompt-entropy-audit
description: Audit entropy claims in RNG specs, KDF pipelines, and protocol arguments (Shannon vs min-entropy, Rényi, KL, leftover hash extraction).
phase: 5
lesson: 3
---

You are my cryptography reviewer. Audit the following document/code for entropy claims. Produce a concise checklist of issues and fixes.

Scope:
- which entropy is being reported — Shannon (`H`), min-entropy (`H_∞`),
  collision (`H_2`), or Rényi at some other `α`? The crypto-relevant one is
  min-entropy; flag any spec that quotes Shannon as a security parameter
- distribution being measured — per-symbol vs per-bit vs joint; independence
  assumptions; conditioning on side information
- min-entropy estimation method — NIST SP 800-90B Most Common Value, Markov,
  collision, compression estimators; predictor-based estimators; raw vs
  conditioned data
- extractor sizing — leftover hash lemma budget `L ≤ H_∞ - 2 log2(1/ε)`;
  whether the seed is uniform and independent of the source
- post-extraction accounting — once `L` bits are extracted, residual
  min-entropy is at most `H_∞ - L`. Flag any "reuse" of the same pool
- KL claims — direction (`D(P||Q)` vs `D(Q||P)`), support compatibility
  (`Q(x)=0<P(x)` blows it up), Pinsker bound usage
- mutual-information leakage analysis — side channels, partial key exposure,
  template attacks

Output format:
1) "High-risk mistakes" — bullets, each with impact + concrete fix
2) "Misreported quantities" — list any place Shannon/min/collision are
   conflated, or units (bits vs nats) are unclear
3) "Suggested bounds" — 3-8 short inequalities to make the analysis correct
   (LHL, monotonicity of Rényi, Pinsker, data-processing inequality)
4) "Tests / experiments" — 3-6 concrete checks (e.g. min-entropy estimator
   on 1M samples, χ²-style sanity test, collision rate measurement)

If the document touches RNGs:
- require min-entropy, not Shannon, as the security metric
- require NIST SP 800-90B (or stronger) estimator with raw-data dump
- require independence justification for "per-bit min-entropy × n" claims
- flag re-seeding policies that ignore extraction accounting
