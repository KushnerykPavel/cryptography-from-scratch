---
name: skill-gauss-lagrange-reduction
description: Checklist and procedure for Gauss/Lagrange (2D) lattice basis reduction and extracting a shortest vector
version: 1.0.0
phase: 4
lesson: 4
tags: [lattices, reduction, svp, lll, post-quantum]
---

# Gauss / Lagrange Reduction (2D) — Quick Skill

Use this when you have a 2D integer lattice basis `(b1, b2)` and you want a short, non-skew basis (and, in 2D, a shortest vector).

## Preconditions

- `b1, b2 ∈ Z^2`
- `det([b1 b2]) != 0` (linearly independent)

## One Allowed Move (unimodular update)

You may replace:

```text
b2 ← b2 - m*b1   for any integer m
```

This does not change the lattice `L(b1,b2)`.

## Size Reduction Rule

Compute:

```text
μ = <b1,b2> / <b1,b1>
m = round(μ)   (nearest integer)
```

Then update:

```text
b2 ← b2 - m*b1
```

This makes `||b2||` as small as possible using `b1`.

## Swap Rule

If after size reduction you have `||b2|| < ||b1||`, swap the vectors and repeat size reduction.

## Stop Condition (Gauss-reduced)

A basis is reduced when:

- `||b1|| <= ||b2||`, and
- `2*|<b1,b2>| <= ||b1||^2`

## Output Guarantees (2D)

- The returned pair is a basis for the same lattice.
- The first vector `b1` is a shortest non-zero lattice vector (up to sign).
  - In 2D, that means you can solve exact SVP by “reduce then read b1”.

## Common Pitfalls

- Using floating-point `round(<b1,b2>/<b1,b1>)` for large integers (use exact integer arithmetic).
- Forgetting that output is not unique (sign flips and other unimodular changes can produce different valid reduced bases).

