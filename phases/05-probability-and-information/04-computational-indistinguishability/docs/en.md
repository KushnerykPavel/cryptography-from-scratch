# Computational Indistinguishability

> Statistical distance bounds every adversary; computational indistinguishability bounds only the ones that run in polynomial time.

**Type:** Learn
**Languages:** Python
**Prerequisites:** Phase 05 · 01 (Probability Basics) · 02 (Statistical Distance) · 03 (Entropies)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- State the computational indistinguishability definition: no PPT distinguisher has non-negligible advantage.
- Explain why a PRG output can be computationally indistinguishable from uniform even when SD ≈ 1.
- Compute distinguishing advantage from sample lists and from the IND game experiment.
- Determine whether a function is negligible using polynomial witnesses.
- Place perfectly secure, statistically secure, and computationally secure in the correct containment order.

## The Problem

Phase 05 · 02 gave you a clean tool: if `SD(D0, D1) ≤ ε`, no observer — not
even one with infinite compute — can distinguish the two distributions with
advantage greater than `ε`. That is **statistical security**, and it is the
gold standard.

But almost every practical crypto primitive — PRGs, PRFs, block ciphers, public-key
encryption — *cannot* achieve statistical security. A PRG stretches `n` bits into
`2n` bits; the output distribution is a set of `2^n` strings inside a space of
`2^(2n)` strings. Statistically it looks nothing like uniform — a `2^n`-time
adversary wins trivially by checking membership. Yet we call PRGs "secure".

The escape hatch is **computational indistinguishability**: we restrict the
adversary to probabilistic polynomial-time (PPT) algorithms. The PRG's output
*looks* uniform to every efficient algorithm, even though it is far from uniform
in total variation.

Without this concept you cannot read a security proof past the first page.
Every reduction ("if the adversary breaks X, we build a PPT that breaks Y") lives
in this framework.

## The Concept

### The IND experiment

Fix a security parameter `n`. Two distributions `D0(n)` and `D1(n)` are **computationally indistinguishable** — written `D0 ≈_c D1` — if for every PPT distinguisher `D`:

```
Adv_D(n) = | Pr[D(x) = 1 | x ← D0(n)] - Pr[D(x) = 1 | x ← D1(n)] |
```

is **negligible** in `n`.

The advantage can also be written via the game form:

```
Adv_D(n) = |Pr[b' = b] - 1/2| · 2

where: challenger picks b ← {0,1}, samples x ← D_b, gives x to D, D outputs b'
```

Both definitions are equivalent.

### Negligible functions

A function `ε : ℕ → ℝ≥0` is **negligible** if for every polynomial `p` there
exists `N` such that for all `n > N`:

```
ε(n) < 1 / p(n)
```

Intuition: it shrinks faster than any inverse polynomial. Common negligible
functions: `2^-n`, `n^-100`, `e^-n`. Common **non-negligible** functions:
`1/n`, `1/√n`, `0.001`.

Rule of thumb at a fixed `n`:
- `ε < 1/n^1` — negligible w.r.t. linear polynomial
- `ε < 1/n^2` — negligible w.r.t. quadratic polynomial
- Security proofs usually work with `ε < 2^-λ` where `λ ≥ 128`

### Statistical vs computational indistinguishability

| Property | Bound | Adversary | When achievable |
|----------|-------|-----------|-----------------|
| Statistical (SD ≤ ε) | every distinguisher, even unbounded | all-powerful | one-time pads, extractors, leftover hash |
| Computational (Adv ≤ negl) | every PPT distinguisher | polynomial time | PRGs, PRFs, encryption |
| Perfect (SD = 0) | no distinguisher at all | any | only equal distributions |

Containment: perfectly secure ⊆ statistically secure ⊆ computationally secure.

### Advantage and statistical distance

Recall from lesson 02: `SD(D0, D1) = max_D Adv_D` over all (unbounded) distinguishers.

Corollary:
```
if SD(D0, D1) ≤ negl(n)  then  D0 ≈_c D1
```

The converse is false: a PRG output has `SD ≈ 1` from uniform (unbounded
distinguisher wins), yet is computationally indistinguishable from uniform.

### PPT restriction matters

The PRG stretches `k`-bit seeds to `2k`-bit outputs. The image has size `2^k`
inside a space of size `2^(2k)`. An unbounded distinguisher checks: "is x in
image(G)?" — wins with advantage `≈ 1`. A PPT distinguisher cannot enumerate
`2^k` possibilities when `k ≥ 128`. So the PPT bound is non-trivially small
even though the statistical bound is huge.

### Hybrid argument (preview)

Lesson 05 will make this rigorous. The sketch: to show `D0 ≈_c Dk`, construct
a chain `D0, D1, …, Dk` where each hop is computationally indistinguishable.
By the triangle inequality for computational distance, the endpoints are too:

```
Adv(D0, Dk) ≤ Adv(D0, D1) + … + Adv(D_{k-1}, Dk)
```

Each hop is negligible (by assumption); a polynomial number of negligible
functions sums to a negligible function. This is the workhorse behind
every multi-step security proof.

## Build It

### Step 1: empirical advantage estimator

```python
def estimate_advantage(distinguisher, samples_0, samples_1):
    pr1_d0 = sum(1 for x in samples_0 if distinguisher(x) == 1) / len(samples_0)
    pr1_d1 = sum(1 for x in samples_1 if distinguisher(x) == 1) / len(samples_1)
    return abs(pr1_d0 - pr1_d1)
```

`Adv = |Pr[D=1 | D0] − Pr[D=1 | D1]|`. Compare to the closed-form `advantage_bernoulli(p0, p1) = |p0 − p1|`.

### Step 2: the IND game

```python
def run_ind_game(sampler_0, sampler_1, distinguisher, n_rounds, *, rng=None):
    correct = 0
    for _ in range(n_rounds):
        b = rng.randint(0, 1)
        x = sampler_0() if b == 0 else sampler_1()
        if distinguisher(x) == b:
            correct += 1
    return abs(correct / n_rounds - 0.5) * 2
```

Challenger picks `b`, sends `x ← D_b`. Advantage `= 2 · |Pr[win] − 1/2|`.

### Step 3: negligibility check

```python
def negligible_bound(security_param, *, poly_degree=1):
    return 1.0 / (security_param ** poly_degree)

def is_negligible(epsilon, security_param, *, poly_degree=1):
    return epsilon < negligible_bound(security_param, poly_degree=poly_degree)
```

Point-check: `ε < 1/n^d`. Not the full asymptotic definition — use it for sanity-checking at a specific `n`.

### Step 4: closed-form advantage

```python
def advantage_bernoulli(p0, p1):
    return abs(p0 - p1)

def advantage_uniform_vs_biased(support_size, delta):
    return delta * (support_size - 1) / support_size
```

Run it:

```
python3 code/main.py
```

## Use It

Real libraries and proof tools express this as:

- **Advantage functions** in game-based frameworks (EasyCrypt, CryptoVerif) —
  they compute `Adv` as a probability expression, then bound it by a reduction
  to a hard problem.
- **ROM proofs**: `Adv ≤ q/2^n` where `q` is the number of hash queries —
  the "query bound" is negligible when `n ≥ 128` and `q` is polynomial.
- **Reduction argument**: "if Adv_A(PRG) ≥ ε, construct B with Adv_B(one-way) ≥ ε/poly(n)".
  If ε is non-negligible, so is ε/poly(n), contradiction.

This lesson's `estimate_advantage` and `run_ind_game` let you empirically
measure advantage on small examples before writing a reduction.

## Attack It

The classic demonstration that PPT restriction is essential:

**Distinguishing a 16-bit PRG from uniform (exhaustive attack):**

A toy PRG with 16-bit seed has `2^16 = 65536` possible outputs. An adversary
enumerates all seeds, pre-computes the image set, and on input `x` outputs:

```
D(x) = 1  if x in image(G)
D(x) = 0  otherwise
```

This runs in time `O(2^16 · T_G)` — perfectly polynomial for `n = 16` — and
achieves `Adv ≈ 1`. Stretch to 128-bit seeds: the same algorithm runs in
`O(2^128)` time, no longer PPT. The PRG is secure *because* this enumeration
is infeasible.

The lesson: computational security is not about the distribution being close
to uniform — it is about efficient algorithms being unable to detect the gap.

## Ship It

This lesson ships a reusable review prompt:

- `outputs/prompt-ind-review.md`

Use it when reviewing security proofs, reduction arguments, or claims of
"computationally indistinguishable from random".

## Exercises

1. Easy: for `D0 = Bernoulli(0.5)` and `D1 = Bernoulli(0.6)`, compute the
   optimal advantage and verify with `advantage_bernoulli`. Is it negligible
   at `n = 128`?
2. Medium: implement a toy "PRG" that just returns its seed repeated twice
   (e.g. `G(k) = k || k`). Write a distinguisher that achieves advantage 1.
   Why does the PPT restriction not save this construction?
3. Hard: show that if `D0 ≈_c D1` and `D1 ≈_c D2`, then `D0 ≈_c D2`. Use
   a proof by reduction: assume a PPT D distinguishes D0 from D2 with
   non-negligible advantage; derive a PPT that distinguishes one of the
   adjacent pairs with non-negligible advantage.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| computational indistinguishability | "looks random" | no PPT distinguisher has non-negligible advantage |
| negligible | "tiny" | smaller than 1/p(n) for every polynomial p, for large n |
| advantage | "how well D tells them apart" | `|Pr[D=1 \| D0] - Pr[D=1 \| D1]|` |
| PPT | "efficient" | probabilistic polynomial-time Turing machine |
| IND game | "distinguishing experiment" | challenger samples from D_b, distinguisher guesses b |
| statistical distance | "info-theoretic gap" | max advantage over all (unbounded) distinguishers |
| reduction | "cryptographic proof" | convert a D that breaks X into one that breaks Y |

## Test Vectors

Source: derived from closed-form definitions of advantage (Bernoulli, uniform-vs-biased)
and negligibility threshold (1/n^d).

Code must pass all vectors in `tests/vectors.json`.

## Further Reading

- [Katz & Lindell, *Introduction to Modern Cryptography*, Ch. 3](https://www.cs.umd.edu/~jkatz/imc.html) — computational indistinguishability, negligible functions, hybrid argument
- [Goldreich, *Foundations of Cryptography, Vol. 1*](https://www.wisdom.weizmann.ac.il/~oded/foc-vol1.html) — formal definition of computational indistinguishability
- [Boneh & Shoup, *A Graduate Course in Applied Cryptography*](https://toc.cryptobook.us/) — advantage notation, IND-CPA, IND-CCA
- [Vadhan, *Pseudorandomness*](https://people.seas.harvard.edu/~salil/pseudorandomness/) — pseudorandom generators, computational distance
