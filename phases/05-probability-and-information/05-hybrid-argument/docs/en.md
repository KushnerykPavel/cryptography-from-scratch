# The Hybrid Argument

> You cannot jump from Real to Ideal in one step — but you can hop there one negligible step at a time.

**Type:** Learn
**Languages:** Python
**Prerequisites:** Phase 05 · 01 (Probability Basics) · 02 (Statistical Distance) · 04 (Computational Indistinguishability)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Construct a hybrid chain H₀ = Real, H₁, …, Hₖ = Ideal for a given multi-message scheme.
- Apply the triangle inequality to bound endpoint advantage as a sum of per-hop advantages.
- Explain why the number of hops must be polynomial: poly(n) × negl(n) = negl(n).
- State the averaging argument: if full-chain advantage is α over k hops, at least one hop has advantage ≥ α/k.
- Implement and run the IND game on each adjacent hybrid pair to verify per-hop advantages empirically.

## The Problem

Security proofs never say "the scheme is secure". They say "if the scheme is
breakable, then some hard problem is solvable". The proof works by showing that
the **real world** (real scheme, real adversary) and the **ideal world** (perfect
security) are computationally indistinguishable.

But real and ideal are usually far apart — directly comparing them produces an
advantage that is not obviously small. The hybrid argument solves this by
cutting the distance into small steps.

Without the hybrid argument you cannot follow the security proof for *any*
multi-message encryption scheme, any PRF-based MAC, or any multi-round protocol.
It is the universal proof template of modern cryptography.

## The Concept

### The hybrid chain

Define a sequence of distributions:

```
H_0 = Real world
H_1
H_2
  ⋮
H_k = Ideal world
```

Each `H_i` is called a **hybrid** — a carefully constructed intermediate world
that shares some features with Real and some with Ideal.

The rule: adjacent hybrids `H_i` and `H_{i+1}` differ in exactly **one
component** — typically one PRF/PRG call, one key, one ciphertext.

### Triangle inequality for advantage

For any (possibly unbounded) function `Adv`:

```
Adv(H_0, H_k) ≤ Adv(H_0, H_1) + Adv(H_1, H_2) + … + Adv(H_{k-1}, H_k)
```

This follows from the triangle inequality for statistical distance
(Lesson 02) and extends to computational advantage:

- If each hop is computationally indistinguishable (`Adv_i ≤ negl`),
- and there are polynomially many hops (`k = poly(n)`),
- then the total advantage is `k · negl = poly · negl = negl`.

### Polynomial sums of negligibles

Key fact: if `ε(n)` is negligible and `k(n)` is a polynomial, then
`k(n) · ε(n)` is still negligible.

Proof sketch: for any polynomial `p`, we need `k·ε < 1/p`. Pick `q(n) = k(n)·p(n)`,
also a polynomial. By negligibility of `ε`, eventually `ε < 1/q = 1/(k·p)`, so
`k·ε < 1/p`. ∎

This is why the number of hybrid hops must be polynomial — exponentially many
negligible terms can sum to something non-negligible.

### The reduction (averaging argument)

Suppose a PPT adversary `A` distinguishes `H_0` from `H_k` with advantage `α`.
We build a reduction `B` that breaks one of the `k` hops:

```
B picks i ← Uniform({1, …, k})
B runs A, using the hop-i challenge for H_{i-1}/H_i
   and simulating all other hops internally
B outputs A's output
```

By averaging: `∃ i` such that `Adv(H_{i-1}, H_i) ≥ α/k`.

If `α` is non-negligible and `k = poly(n)`, then `α/k` is also non-negligible —
contradiction with the assumed hardness of each hop. So `α` must be negligible.

### Template: multi-message PRG encryption

**Real (H_0):** encrypt `n` messages with `n` independent PRG outputs.

```
H_i: first i ciphertexts use truly random pads
     remaining n-i ciphertexts use PRG(k_j)
```

**Ideal (H_n):** all `n` messages XOR'd with independent uniform pads (perfect OTP).

Each hop `H_{i-1} → H_i`:
- Replace one `PRG(k_i)` output with a truly random `r_i`.
- Advantage of any distinguisher on this hop = PRG advantage (by reduction).

By the hybrid argument, `Adv(Real, Ideal) ≤ n · Adv(PRG)`. If the PRG is
secure, the whole scheme is secure for polynomially many messages.

### What makes a good hybrid

| Requirement | Why |
|-------------|-----|
| Adjacent hybrids differ in one component | Keeps per-hop advantage reducible to one primitive |
| Number of hops is polynomial in `n` | Poly sum of negligibles is negligible |
| Each hop is justified by a primitive | Each advantage is bounded by a hard-problem advantage |
| `H_0 = Real`, `H_k = Ideal` | The endpoints are the security claim |

### Common mistakes

1. **Exponentially many hops.** If `k = 2^n`, the sum `2^n · negl` may not be
   negligible. Always count your hops.
2. **Hops that change two components.** Two changes make the reduction
   simulation unclear — you cannot cleanly embed the challenger's challenge.
3. **Forgetting the reduction is PPT.** The simulation inside `B` must run in
   polynomial time; it cannot enumerate exponential spaces.

## Build It

### Step 1: triangle bound

```python
def hybrid_advantage_bound(per_hop_advantages):
    return sum(per_hop_advantages)  # Adv(H_0, H_k) <= Σ Adv(H_i, H_{i+1})
```

### Step 2: run the hybrid chain

```python
def run_hybrid_chain(samplers, distinguisher, n_rounds, *, rng=None):
    per_hop = []
    for s0, s1 in zip(samplers, samplers[1:]):
        correct = sum(
            1 for _ in range(n_rounds)
            if distinguisher(s0() if rng.randint(0,1)==0 else s1()) == 0
        )
        per_hop.append(abs(correct / n_rounds - 0.5) * 2)
    return {"per_hop": per_hop, "triangle_bound": sum(per_hop)}
```

Measures each adjacent-pair advantage empirically. Verifies the triangle inequality holds on samples.

### Step 3: sum of negligibles

```python
def negligible_sum(epsilon_per_hop, n_hops):
    return n_hops * epsilon_per_hop

def is_poly_sum_negligible(epsilon_per_hop, n_hops, security_param, *, poly_degree=1):
    return negligible_sum(epsilon_per_hop, n_hops) < 1 / security_param ** poly_degree
```

`k · negl(n) = negl(n)` when `k = poly(n)`. Fails for exponential `k`.

### Step 4: averaging argument

```python
def reduction_advantage(distinguisher_advantage, n_hops):
    return distinguisher_advantage / n_hops  # worst-hop lower bound
```

If full-chain advantage is `α` over `k` hops, at least one hop has advantage `≥ α/k`.

Run it:

```
python3 code/main.py
```

## Use It

The hybrid argument appears in virtually every modern crypto proof:

- **IND-CPA for CBC/CTR mode**: hybrids replace one PRF call per block.
- **MAC security (HMAC, CMAC)**: hybrids replace PRF calls with truly random functions.
- **Public-key encryption (ElGamal, RSA-OAEP)**: hybrids use DDH/RSA hardness at each hop.
- **EasyCrypt / CryptoVerif**: these proof assistants mechanise the hybrid argument — each `game_hop` tactic is exactly one hybrid step.

In real proofs, the "ideal world" is often a random oracle or an information-theoretically
secure primitive. The hybrid chain bridges Real → Ideal using the hardness of one
primitive per hop.

## Attack It

The hybrid argument is a *proof technique*, not a primitive, so "attack" means
finding where the argument breaks:

**Attack 1 — exponential hops.** Suppose an adversary distinguishes a scheme
with advantage `1/n`. If the proof has `2^n` hops, the per-hop advantage is
`1/(n · 2^n)` — that is negligible, so no contradiction arises, and the proof
gives no security guarantee. Always verify the hop count is polynomial.

**Attack 2 — leaky simulation.** If the reduction `B` simulates the other hops
using *correlated* randomness that leaks information about the challenge bit,
the per-hop advantage could be 0 even though the real-vs-ideal advantage is
large. Each hop's simulation must be *perfect* (or statistically close to the
real game) in the non-challenge positions.

**Attack 3 — wrong endpoints.** Replacing `H_0` with a distribution that is
not actually the real attack game means the proof proves the wrong thing. Check
that `H_0` matches the exact security experiment in the definition.

## Ship It

This lesson ships a reusable review prompt:

- `outputs/prompt-hybrid-argument.md`

Use it when reviewing a security proof that uses a hybrid chain, game-hopping,
or a sequence of reductions.

## Exercises

1. Easy: a scheme encrypts 3 messages with independent PRG keys. Write out
   the hybrid chain (4 hybrids). How many hops? What does each hop change?
   What is the triangle bound on `Adv(Real, Ideal)` in terms of `Adv(PRG)`?

2. Medium: implement a reduction that takes a distinguisher `D` for a 3-hop
   hybrid and returns a distinguisher for hop `i` (for a randomly chosen `i`).
   Verify empirically that the per-hop advantage is at least `total_adv / 3`.

3. Hard: the proof above assumes `n` is fixed. Show that if the number of
   messages the adversary can request is `q(n)` (adaptive, polynomial), the
   hybrid argument still goes through — and compute the exact bound on `Adv(PRG)`
   needed to achieve `2^-128` security at `n = 128` with `q = 2^30` messages.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| hybrid argument | "proof by reduction" | chain of distributions; bound endpoints via triangle inequality |
| hybrid distribution | "intermediate game" | world that partially replaces one component with the ideal |
| triangle inequality | "sum the hops" | `Adv(H_0, H_k) ≤ Σ Adv(H_i, H_{i+1})` |
| reduction | "if A breaks X, B breaks Y" | simulation that converts a distinguisher on the chain into one on a primitive |
| averaging argument | "pigeonhole on hops" | at least one hop has advantage ≥ total/k |
| poly-many negligibles | "still negligible" | `k(n) · negl(n) = negl(n)` when k is polynomial |

## Test Vectors

Source: derived directly from definitions — triangle inequality sum, negligible_sum,
reduction_advantage.

Code must pass all vectors in `tests/vectors.json`.

## Further Reading

- [Katz & Lindell, *Introduction to Modern Cryptography*, §3.4](https://www.cs.umd.edu/~jkatz/imc.html) — hybrid argument for multiple encryptions
- [Goldreich, *Foundations of Cryptography, Vol. 1*, §3.2](https://www.wisdom.weizmann.ac.il/~oded/foc-vol1.html) — formal treatment of hybrid distributions
- [Boneh & Shoup, *A Graduate Course in Applied Cryptography*, Ch. 5](https://toc.cryptobook.us/) — game-hopping proofs
- [EasyCrypt documentation](https://www.easycrypt.info/) — mechanised hybrid proofs
