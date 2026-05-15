---
name: skill-gaussian-sampling
description: Checklist for discrete Gaussian sampling over Z for lattice crypto (tail cut + normalization + deterministic test vectors + safety warnings)
version: 1.0.0
phase: 4
lesson: 8
tags: [lattices, gaussian, sampling, lwe, randomness, post-quantum]
---

# Discrete Gaussian Sampling (Z) — Quick Skill

Use this when you need to sample integers (or integer vectors) from a discrete Gaussian-like distribution for lattice crypto demos (LWE/RLWE noise, toy trapdoor intuition) and you want to avoid the most common correctness pitfalls.

## Target distribution

Centered discrete Gaussian on integers:

```text
P[x] ∝ exp(-x^2 / (2σ^2))   for x ∈ Z
```

Optionally shifted by a center `c`:

```text
P[x] ∝ exp(-(x-c)^2 / (2σ^2))
```

## Practical decisions you must make

- **Tail cut `t`:** choose a finite window, e.g. `x ∈ [⌊c⌋-t, ⌈c⌉+t]`.
- **Normalization:** convert weights into exact integer bucket counts that sum to a fixed scale (e.g. `2^64`) to avoid drift.
- **Randomness source:**
  - For **tests/vectors**: deterministic DRBG (seeded, reproducible).
  - For any **security-critical** code: use a real CSPRNG / XOF design (and constant-time sampling).

## CDT (CDF-table) sampling recipe

1. Compute weights `w_x = exp(-(x-c)^2/(2σ^2))` for all integers `x` in your tail window.
2. Normalize to probabilities `p_x = w_x / sum(w_x)`.
3. Scale into integer counts `count_x ≈ p_x * 2^64`, then adjust so `sum(count_x) = 2^64`.
4. Build cumulative ends:

```text
cdf_ends[i] = count_0 + ... + count_i
```

5. Draw `u ← uniform{0, ..., 2^64-1}` and return the first `x_i` with `u < cdf_ends[i]`.

## Red flags (things that break crypto demos)

- Using `random.Random(...)` or time-seeded RNGs for anything that is supposed to be secret.
- Hard-clipping samples without accounting for the statistical distance to the intended distribution.
- Building tables with floating-point normalization and then comparing outputs across machines (non-determinism).
- Reusing the same RNG stream across “independent” secrets in a way that creates correlations.

## Safety warning

This course’s implementations are educational and **not constant-time**. Do not ship them in production.

