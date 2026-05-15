---
name: skill-lll-reduction
description: Checklist and procedure for LLL lattice basis reduction (size reduction + Lovász swaps) and for verifying an LLL-reduced basis
version: 1.0.0
phase: 4
lesson: 5
tags: [lattices, reduction, lll, bkz, post-quantum]
---

# LLL Reduction — Quick Skill

Use this when you have an integer lattice basis `B = (b1, ..., bn)` and you want a shorter, less-skew basis that is easier to work with (approx-SVP, Babai, BKZ pre-reduction, attack demos).

## Preconditions

- `b_i ∈ Z^n`
- full rank: `det([b1 ... bn]) != 0`
- choose `δ` with `1/4 < δ < 1` (common: `δ = 3/4`)

## Two Allowed Moves (unimodular updates)

1. **Size reduction (column operation):**

```text
b_k ← b_k - r*b_j   with r ∈ Z,  j < k
```

2. **Swap adjacent vectors:**

```text
swap(b_{k-1}, b_k)
```

Both preserve the lattice.

## Gram–Schmidt quantities

Compute the Gram–Schmidt orthogonalization `b*_0, ..., b*_{n-1}` and coefficients:

```text
μ_{k,j} = <b_k, b*_j> / <b*_j, b*_j>
```

Also track `||b*_k||^2`.

## LLL Conditions

**1) Size-reduction condition**

After size reduction, require for all `k > j`:

```text
|μ_{k,j}| ≤ 1/2
```

Enforce by choosing `r = round(μ_{k,j})` (nearest integer) and applying `b_k ← b_k - r*b_j`.

**2) Lovász condition**

For `k ≥ 1`, require:

```text
||b*_k||^2 ≥ (δ - μ_{k,k-1}^2) * ||b*_{k-1}||^2
```

If it fails, swap `b_k` and `b_{k-1}` and continue (step back).

## Practical Notes

- Larger `δ` usually means stronger reduction (shorter vectors) but more runtime.
- Floating-point Gram–Schmidt can make LLL non-deterministic for large integers; for education, exact rationals are simplest.
- Output is not unique: sign flips and different unimodular paths can yield different valid reduced bases.

