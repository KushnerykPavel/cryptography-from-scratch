# Probability Basics for Cryptographers

> If you can't write the event, you can't prove the claim.

**Type:** Learn
**Languages:** Python
**Prerequisites:** Phase 00 · 04 (Test Vectors) + basic Python
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Write crypto probability statements using sample spaces, events, and PMFs.
- Apply union bound, conditional probability, and independence to security arguments.
- Compute joint and marginal distributions from a PMF table.
- Distinguish statistical independence from computational independence.
- Implement a sampling experiment and verify empirical vs theoretical probabilities.

## The Problem

Cryptography is full of statements that look like code but are really probability:

- `Pr[Verify(pk, m, sig) = 1]`
- `Pr[Adversary wins the game]`
- “Except with negligible probability…”

If you can't manipulate those probabilities correctly, you will:

- misread security definitions (what is being quantified over?)
- make invalid “independence” assumptions
- forget a union bound and accidentally turn a secure scheme into an insecure one “by proof”

This lesson installs the minimal probability toolkit you will reuse in every later proof: events, conditioning, independence, and the union bound.

## The Concept

### Experiments and events (crypto game notation)

In crypto we describe a **randomized experiment** and then talk about an **event** inside it.

Example:

```
Experiment: pick a random bit b ← {0,1}
Event E: "b = 1"
Claim: Pr[E] = 1/2
```

You will often see:

```
Pr[ Exp(1^λ) = 1 ]
```

Read it as: “the probability that the experiment returns 1”.

### Conditional probability

Conditioning is “updating your world” to only the outcomes where `B` happened:

```
Pr[A | B] = Pr[A ∩ B] / Pr[B]   (only defined when Pr[B] > 0)
```

Crypto pitfall: conditioning can completely change a probability. The most common proof bug is to treat `Pr[A|B]` like `Pr[A]` when `B` is correlated with `A`.

### Independence (and why it is easy to get wrong)

Two events are independent when learning one doesn't change the probability of the other:

```
Independent: Pr[A | B] = Pr[A]
Equivalent:  Pr[A ∩ B] = Pr[A] · Pr[B]
```

Coin flips are independent. Drawing cards *without replacement* is not.

### The union bound (Boole's inequality)

When you have many “bad events” `E1, E2, ..., Ek`, you almost always need this:

```
Pr[E1 ∪ E2 ∪ ... ∪ Ek] ≤ Pr[E1] + Pr[E2] + ... + Pr[Ek]
```

It is an *upper bound* (sometimes loose), but it is a workhorse in security proofs:

- “the adversary wins if **any** of these things goes wrong”
- bound each bad thing separately, then sum

### Distinguishers and advantage

A lot of modern crypto is about “can you tell two worlds apart?”.

If a distinguisher `D` outputs 1 with probability `p_real` in the real world and `p_ideal` in the ideal world, a common notion of advantage is:

```
Adv(D) = | p_real - p_ideal |
```

If the two worlds look identical, `Adv(D) = 0`. If they are easy to tell apart, `Adv(D)` is large.

## Build It

### Step 1: finite probability spaces

```python
def pmf_from_counts(counts):
    total = sum(counts.values())
    return {k: c / total for k, c in counts.items()}

def prob_event(pmf, predicate):
    return sum(p for x, p in pmf.items() if predicate(x))
```

A PMF is just a dict mapping outcomes to probabilities that sum to 1. `prob_event` computes `Pr[E]` for any event `E`.

### Step 2: conditioning and independence

```python
def conditional_probability(p_a_and_b, p_b):
    if p_b == 0:
        raise ValueError("cannot condition on probability-0 event")
    return p_a_and_b / p_b

def are_independent(pmf, pred_a, pred_b):
    p_a = prob_event(pmf, pred_a)
    p_b = prob_event(pmf, pred_b)
    p_ab = prob_event(pmf, lambda x: pred_a(x) and pred_b(x))
    return abs(p_ab - p_a * p_b) < 1e-9
```

`are_independent` tests the product rule: `Pr[A ∩ B] = Pr[A] · Pr[B]`.

### Step 3: union bound

```python
def union_bound(probs):
    return min(1.0, sum(probs))
```

`Pr[A1 ∪ … ∪ Ak] ≤ Pr[A1] + … + Pr[Ak]`. Used constantly in security proofs to bound "any bad event occurs".

### Step 4: distinguishing advantage

```python
def distinguishing_advantage(p_real, p_ideal):
    return abs(p_real - p_ideal)
```

`Adv(D) = |Pr[D outputs 1 | real] − Pr[D outputs 1 | ideal]|`. When this is small for all distinguishers, the worlds are indistinguishable.

Run it:

```
python3 code/main.py
```

## Use It

In real cryptographic systems you rarely “compute probabilities” with a library. You usually:

- reason symbolically (by definition + inequalities like the union bound)
- confirm intuition with simulation (Monte Carlo)

What you *do* use libraries for is randomness:

- `random` is for simulations and games
- `secrets` (or an audited crypto library) is for keys, nonces, salts, challenges

Rule: never use `random` for cryptographic randomness.

## Attack It

Probability mistakes are security bugs. Two classics:

1) **Fake independence.** Treating correlated events as independent can shrink a failure probability by orders of magnitude “on paper”.
2) **Missing a union bound.** If you do something `k` times, a per-trial failure probability `p` often becomes “about `k·p`”, not just `p`.

## Ship It

This lesson ships a reusable review prompt:

- `outputs/prompt-probability-sanity-check.md`

Use it when reviewing proofs, protocol arguments, or any code that claims “this fails with probability at most …”.

## Exercises

1. Easy: write down the sample space and compute `Pr[sum=7]` for two fair six-sided dice.
2. Medium: compute `Pr[first die = 6 | sum >= 10]` (exactly, not by simulation).
3. Hard: you run a randomized protocol `k` times and each run fails with probability ≤ `2^-40`. Use the union bound to upper-bound the probability that any run fails.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| experiment | “the protocol” | a randomized procedure that produces an outcome |
| event | “a thing happens” | a subset of outcomes you care about (“adversary wins”) |
| conditional probability | “given that” | probability inside the world where `B` happened |
| independence | “unrelated” | `Pr[A|B]=Pr[A]` (learning `B` doesn't change `A`) |
| union bound | “sum the bad probabilities” | `Pr[⋃Ei] ≤ ΣPr[Ei]` |
| advantage | “how distinguishable” | typically `|Pr[1|Real] - Pr[1|Ideal]|` |

## Test Vectors

Source: basic probability identities + hand-derived examples.

Code must pass all vectors in `tests/vectors.json`.

## Further Reading

- [A Modern Introduction to Probability and Statistics (Dekker)](https://www.dekkerstochastic.nl/miaps/) — clear probability foundations
- [Katz & Lindell, *Introduction to Modern Cryptography*](https://www.cs.umd.edu/~jkatz/imc.html) — probability in game-based proofs
