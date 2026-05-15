---
name: skill-coppersmith-stereotyped-rsa
description: Procedure to recover a small unknown RSA plaintext suffix when the plaintext is a known prefix plus a bounded integer x (Coppersmith/Howgrave–Graham univariate small-root workflow)
version: 1.0.0
phase: 4
lesson: 12
tags: [lattices, lll, coppersmith, rsa, cryptanalysis]
---

# Coppersmith (Univariate) — Stereotyped RSA Messages

Use this when you have textbook RSA `c ≡ m^e (mod N)` and the plaintext is structured as:

```text
m = A + x
```

where `A` is known and `x` is an unknown integer with a public bound `|x| < X`.

Goal: recover `x` without factoring `N`.

## Preconditions

- Textbook RSA (no OAEP / no PSS / no randomized padding).
- You can express the unknown part as a *small integer* `x` with known bound `X`.
- The constructed polynomial is monic in `x` (common for `(A+x)^e - c`).

## Model

Define:

```text
f(x) = (A + x)^e - c
```

Then the target is:

```text
f(x0) ≡ 0 (mod N)  with  |x0| < X
```

## Lattice construction (Howgrave–Graham univariate)

Let `d = deg(f)`. Choose integers `m >= 1` and `t >= 0`. Build the set:

```text
g_{i,j}(x) = x^j * N^{m-i} * f(x)^i     for i = 0..m-1,  j = 0..d-1
g_{m,j}(x) = x^j * f(x)^m              for j = 0..t-1
```

Scale by the root bound by substituting `x → xX` before taking coefficients:

```text
g_{i,j}(xX)
```

Each scaled polynomial is a coefficient vector; these vectors form a lattice basis.

## Reduction + root recovery

1. Run LLL on the basis (LLL-with-exact rationals is fine for small dimensions).
2. Take one of the shortest output vectors and interpret it as coefficients of `h(xX)`.
3. Divide coefficient `k` by `X^k` to recover `h(x)`.
4. Find integer roots of `h(x)` with `|x| < X`.
5. Verify the candidate root: check `f(x) ≡ 0 (mod N)` (or `gcd(N, f(x)) = N` when working modulo `N`).

## Practical notes

- If nothing works, vary `m` (and optionally `t`) and keep dimension modest.
- Success is sensitive to parameters and root size. This is expected: the provable bounds are conservative and implementations often rely on heuristics.
- Real systems use padding specifically to prevent this algebraic structure from existing.

