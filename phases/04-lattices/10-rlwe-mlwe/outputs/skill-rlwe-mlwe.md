---
name: skill-rlwe-mlwe
description: Quick checklist for building toy RLWE/MLWE instances (ring arithmetic + Regev-style bit encryption + tiny brute-force attack intuition)
version: 1.0.0
phase: 4
lesson: 10
tags: [lattices, rlwe, mlwe, module-lwe, ring-lwe, post-quantum, pke, noise]
---

# RLWE & MLWE — Quick Skill

Use this when you need a small, deterministic, educational RLWE/MLWE demo that you can test and reason about.

## Core object: noisy ring equations mod q

Pick:

- `q`: modulus (integer, typically odd in toys)
- `n`: ring dimension (power of two for `x^n + 1`)
- `R_q = Z_q[x]/(x^n+1)` ring elements as length-`n` coefficient vectors
- `s`: secret with small coefficients (e.g. ternary)
- `a`: uniform random element(s) in `R_q`
- `e`: small error polynomial (e.g. ternary)

RLWE public key shape:

```text
pk = (a, b = a*s + e)   in R_q
sk = s
```

## Toy RLWE bit encryption (Regev-style in a ring)

Encrypt bit `μ ∈ {0,1}`:

```text
choose small r,e1,e2
u = a*r + e1
v = b*r + e2 + μ·(q/2)
ct = (u, v)
```

Decrypt:

```text
x = v - u*s  ≈ μ·(q/2) + small noise
μ̂ = threshold(x)  (toy: majority vote over coefficients)
```

## MLWE variant (module rank k)

Choose a short vector of ring elements:

```text
a = (a1,...,ak) in R_q^k
s = (s1,...,sk) small
b = <a,s> + e = a1*s1 + ... + ak*sk + e
```

Encryption uses `u = a*r + e1` where `u` is a length-`k` vector of polynomials, and `v = b*r + e2 + μ·(q/2)`.

## Tiny brute-force “attack” for intuition (toy only)

If the secret coefficients are ternary and dimensions are tiny:

1. enumerate all candidates (`3^n` for RLWE, `3^(k·n)` for MLWE),
2. compute `e = b - a*s` (or `b - <a,s>`) modulo `q`,
3. center-lift coefficients and accept if `|e_i| ≤ bound`.

This explains why real schemes need large dimensions and careful parameter choices.

## Safety warning

Educational implementation. Not constant-time. Not production-safe.

