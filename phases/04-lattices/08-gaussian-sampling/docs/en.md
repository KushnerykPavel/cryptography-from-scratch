# Discrete Gaussian Sampling

> Noise is the secret sauce: sample from a discrete Gaussian, not “some small ints”.

**Type:** Build
**Languages:** Python
**Prerequisites:** 04-gauss-lagrange-2d, 05-lll, 07-babai-nearest-plane
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## The Problem

Most lattice cryptosystems hide secrets behind *noise*:

- In LWE / RLWE, you add an error vector `e` to make equations ambiguous.
- In trapdoor constructions, you sample short lattice vectors that look “random enough”.

If your “noise” is the wrong shape (too small, clipped, biased, or predictable), the scheme can become distinguishable or outright breakable. Discrete Gaussians are the default target distribution because they behave nicely under linear algebra and have strong smoothing / tail properties.

## The Concept

We want a distribution over integers `x ∈ Z` that looks like a Gaussian bell curve:

```text
probability
  ^
  |            *
  |          * * *
  |        * * * * *
  |      * * * * * * *
  +-------------------------> x
        -3 -2 -1 0 1 2 3
```

A centered discrete Gaussian with parameter `σ` assigns probability proportional to:

```text
P[x] ∝ exp(-x^2 / (2σ^2))
```

In practice you must:

1. **Truncate the tails** to a finite window `x ∈ [c - t, c + t]` (otherwise the support is infinite).
2. **Normalize** so probabilities sum to 1.
3. **Sample** using a reproducible source of uniform random bits.

This lesson builds a simple CDF-table sampler:

- Precompute a cumulative distribution table over the truncated window.
- Draw a uniform 64-bit integer `u`.
- Binary-search into the CDF to pick the corresponding integer.

## Build It

### Step 1: Deterministic RNG (for tests)

For test vectors we want deterministic sampling. We use a tiny SHA-256 counter-mode RNG (`seed || counter`) that outputs a stream of bytes.

```python
Sha256CtrRng(seed=b"...").uint64()
```

### Step 2: Build a discrete Gaussian CDF table

We compute weights `w_x = exp(-(x-c)^2 / (2σ^2))` on an integer window, then normalize into `2^64` buckets (integers that sum exactly to `2^64`). This produces a CDF array `cdf_ends` such that:

```text
u in [0, cdf_ends[0])         -> values[0]
u in [cdf_ends[0], cdf_ends[1]) -> values[1]
...
```

```python
sampler = build_discrete_gaussian_cdf(sigma="2.0", center="0", tail=16)
sampler.sample(rng)
```

## Use It

In production lattice crypto, discrete Gaussian (or small-noise) sampling is implemented:

- with carefully designed samplers (rejection / CDT / Knuth–Yao / Ziggurat variants),
- using constant-time techniques,
- with XOF/PRF-backed randomness (e.g., SHAKE, AES-CTR),
- and with parameters tuned to the scheme’s security proof.

Educational takeaway: treat sampling as a *cryptographic primitive*, not an afterthought. Your from-scratch code is for learning and for toy experiments, not deployment.

## Attack It

Two common failure modes to recognize:

1. **Predictable randomness:** if the sampler’s RNG state is guessable, an attacker can predict `e`, turn “noisy” equations back into clean linear algebra, and recover secrets.
2. **Wrong tails / bias:** if you clip too aggressively or round incorrectly, the distribution can become distinguishable from the intended one; in LWE-like settings, less/noisy errors can enable lattice reduction attacks at smaller dimension.

## Ship It

You ship a reusable checklist for discrete Gaussian sampling decisions (tail cut, normalization, determinism for tests, constant-time warning) in `outputs/skill-gaussian-sampling.md`.

## Exercises

1. Easy: change `tail` and observe how often you see large-magnitude samples.
2. Medium: estimate empirical mean/variance for several `σ` values and compare to intuition.
3. Hard: implement a “clipped” sampler (hard bound) and write a simple distinguisher based on sample variance.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Discrete Gaussian | “Gaussian over the integers” | `P[x] ∝ exp(-(x-c)^2/(2σ^2))` for integer `x` |
| Tail cut / truncation | “just ignore the tails” | Restricting to a finite window, introducing a small statistical error |
| CDT / CDF table | “precompute probabilities” | A lookup table that maps uniform bits to outcomes via cumulative mass |
| Statistical distance | “close enough” | A quantitative measure of how far your sampled distribution is from the target |

## Test Vectors

Source: academic motivation (Micciancio–Regev; Peikert). Vectors are project-internal deterministic samples for a fixed sampler + RNG. Code must pass `tests/vectors.json`.

## Further Reading

- Micciancio & Regev (2009) — Lattice-based cryptography survey; discrete Gaussians as a core tool.
- Peikert (2016) — A decade of lattice crypto; practical notes and parameter intuition.
