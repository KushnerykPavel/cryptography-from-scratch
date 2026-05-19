# Statistical Distance & Total Variation

> Two distributions are "close" iff no observer can tell them apart.

**Type:** Learn
**Languages:** Python
**Prerequisites:** Phase 05 · 01 (Probability Basics)
**Time:** ~60 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Define statistical distance (total variation) and state its three equivalent formulations.
- Explain why SD upper-bounds every distinguisher's advantage, including unbounded ones.
- Compute SD between two discrete PMFs by hand and verify with code.
- Apply the triangle inequality to bound SD across a chain of hybrid distributions.
- Distinguish statistical security (SD ≤ ε) from computational security (PPT advantage ≤ negl).

## The Problem

Crypto proofs constantly say things like "this distribution is statistically
close to uniform" or "the real and ideal worlds are `ε`-close". You will see:

- `SD(Real, Ideal) ≤ negl(λ)`
- "the output is `2^-80`-close to uniform"
- "the simulator's transcript is statistically indistinguishable from the real one"

Without a precise meaning for **close**, those claims are vibes. The right
meaning is **statistical distance** (also called **total variation distance**).
It bounds *every* unbounded distinguisher at once: if `SD(P, Q) ≤ ε`, then no
observer — no matter how clever — can tell `P` from `Q` with advantage greater
than `ε`. This is the cleanest non-asymptotic security notion in crypto.

## The Concept

### Definition

For probability mass functions `P, Q` over the same (countable) set `X`:

```
SD(P, Q) = (1/2) · Σ_x | P(x) - Q(x) |
```

Equivalent formulations (all useful):

```
SD(P, Q) = max_{E ⊆ X} | P(E) - Q(E) |          (event view)
SD(P, Q) = Σ_x max(0, P(x) - Q(x))              (positive part)
SD(P, Q) = 1 - Σ_x min(P(x), Q(x))              (overlap view)
```

The factor `1/2` exists so that `SD` ranges in `[0, 1]`. `0` means identical;
`1` means disjoint support.

### Why the factor 1/2

For *any* event `E`, define the complement `Ē`. Then

```
P(E) - Q(E) = -(P(Ē) - Q(Ē))
```

so `Σ_x |P(x) - Q(x)|` double-counts the gap. Halving lines `SD` up with
"max over events", which is the quantity crypto actually cares about.

### SD bounds every distinguisher

A **distinguisher** is any function `D: X → {0, 1}`. Its advantage at telling
`P` from `Q` is

```
Adv(D) = | Pr_{x←P}[D(x) = 1] - Pr_{x←Q}[D(x) = 1] |
       = | P(E_D) - Q(E_D) |       where E_D = {x : D(x) = 1}
       ≤ max_E |P(E) - Q(E)|
       = SD(P, Q)
```

The bound is **tight**: the optimal (unbounded) distinguisher outputs 1 exactly
on `E* = {x : P(x) > Q(x)}`, and achieves `Adv = SD(P, Q)`.

So `SD` is the information-theoretic upper bound on distinguishing advantage —
even for adversaries with infinite time.

### A metric

`SD` is a metric on distributions:

- `SD(P, P) = 0`
- symmetry: `SD(P, Q) = SD(Q, P)`
- triangle inequality: `SD(P, Q) ≤ SD(P, R) + SD(R, Q)`

The triangle inequality is what makes **hybrid arguments** work. To bound the
distance between `Real` and `Ideal`, you build a chain `H_0 = Real, H_1, …,
H_k = Ideal` and sum the per-hop distances.

### Statistical security

A protocol is **ε-statistically secure** if the real and simulated
distributions are within `SD ≤ ε`. Common in MPC, ZK, leftover-hash lemma,
extractor outputs, and "smoothed" lattice arguments.

## Build It

### Step 1: the definition

```python
def statistical_distance(p, q):
    support = set(p) | set(q)
    return 0.5 * sum(abs(p.get(x, 0.0) - q.get(x, 0.0)) for x in support)
```

`(1/2) · Σ |P(x) − Q(x)|`. The factor 1/2 normalises to `[0,1]` and equals `max_E |P(E) − Q(E)|`.

### Step 2: optimal distinguisher (brute force on small support)

```python
def sd_from_event_max(p, q):
    support = list(set(p) | set(q))
    best = 0.0
    for size in range(len(support) + 1):
        for subset in combinations(support, size):
            best = max(best, abs(
                sum(p.get(x, 0.0) for x in subset) -
                sum(q.get(x, 0.0) for x in subset)))
    return best
```

`O(2^|support|)` — for teaching only. Confirms `SD = max_E |P(E) − Q(E)|` by exhaustion.

### Step 3: derived helpers

```python
def biased_bit_sd(epsilon):
    return abs(epsilon)            # SD(Bern(1/2+ε), Bern(1/2))

def sd_to_uniform(p, support_size):
    uniform = {x: 1 / support_size for x in p}
    return statistical_distance(p, uniform)

def is_statistically_close(p, q, *, epsilon):
    return statistical_distance(p, q) <= epsilon
```

### Step 4: triangle inequality

```python
def triangle_inequality_gap(p, q, r):
    return (statistical_distance(p, r)
            - statistical_distance(p, q)
            - statistical_distance(q, r))  # always <= 0
```

`SD(P, R) ≤ SD(P, Q) + SD(Q, R)` — the workhorse of hybrid arguments.

Run it:

```
python3 code/main.py
```

## Use It

You will use `SD` to:

- **Compare a sampler to its target distribution.** Reject sampling, biased
  RNGs, rejection-sampled lattice noise — measure how close the empirical or
  exact output is to the intended distribution.
- **Bound leakage.** If a transcript leaks at most `ε` of statistical
  information, no adversary distinguishes with advantage `> ε`.
- **Compose hybrids.** Bound `SD(Real, Ideal)` by `SD(H_0, H_1) + … +
  SD(H_{k-1}, H_k)` via triangle inequality.

In practice, libraries like `scipy.stats` have closed-form distances for
specific families, and `numpy` makes `0.5 * np.sum(np.abs(p - q))` a one-liner.
The lesson code mirrors the math literally so the definition stays visible.

## Attack It

Statistical distance gives the **optimal** unbounded distinguisher. The
construction is trivial: given the two PMFs, output 1 on `E* = {x : P(x) >
Q(x)}` and 0 otherwise. The achieved advantage is exactly `SD(P, Q)`.

This is the threat model for statistical (information-theoretic) security:
the adversary already knows the two distributions and has unlimited
computation. The only protection is that `SD` is genuinely small.

Two common mistakes:

1. **Computational vs statistical confusion.** PRGs and PRFs have
   *computational* distance from uniform that is large statistically (their
   image is a tiny subset of all strings). Statistical security demands
   `SD ≤ negl(λ)`, which PRGs cannot satisfy.
2. **Forgetting the `1/2`.** Without it you get `L1` distance, which ranges
   in `[0, 2]`. Many papers drop the `1/2` for the L1 form — read carefully.

## Ship It

This lesson ships a reusable review prompt:

- `outputs/prompt-statistical-distance-check.md`

Use it when reviewing claims of "ε-close to uniform", "statistical
indistinguishability", or hybrid arguments.

## Exercises

1. Easy: compute `SD` between a fair coin and a coin that lands heads with
   probability `0.51`. Confirm `biased_bit_sd(0.01)` matches.
2. Medium: prove that `SD(P, Q) = Σ_x max(0, P(x) - Q(x))` by pairing positive
   and negative contributions to the sum.
3. Hard: given two distributions over `{0,1}^n` that differ only on the first
   bit, derive `SD` analytically, then verify with `statistical_distance` for
   `n = 4`.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| statistical distance | "how far apart" | `(1/2) · Σ |P(x) - Q(x)|` |
| total variation distance | "TV distance" | same thing as SD |
| statistically close | "ε-close" | `SD(P, Q) ≤ ε` |
| statistical indistinguishability | "look the same" | `SD ≤ negl(λ)` |
| hybrid argument | "chain of distributions" | bound `SD` along intermediate hops |
| optimal distinguisher | "best attacker" | outputs 1 on `{x : P(x) > Q(x)}` |

## Test Vectors

Source: derived directly from the definition `SD(P,Q) = (1/2)·Σ|P(x)-Q(x)|`.

Code must pass all vectors in `tests/vectors.json`.

## Further Reading

- [Katz & Lindell, *Introduction to Modern Cryptography*](https://www.cs.umd.edu/~jkatz/imc.html) — statistical vs computational indistinguishability
- [Vadhan, *Pseudorandomness*](https://people.seas.harvard.edu/~salil/pseudorandomness/) — extractors, leftover hash lemma, statistical distance lemmas
- [Goldreich, *Foundations of Cryptography, Vol. 1*](https://www.wisdom.weizmann.ac.il/~oded/foc-vol1.html) — hybrid arguments
