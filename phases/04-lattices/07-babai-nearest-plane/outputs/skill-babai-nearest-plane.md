---
name: skill-babai-nearest-plane
description: Checklist and procedure for Babai's nearest-plane algorithm (approximate CVP) and for the standard LLL-then-Babai workflow
version: 1.0.0
phase: 4
lesson: 7
tags: [lattices, cvp, babai, nearest-plane, bdd, reduction, lll]
---

# Babai Nearest Plane — Quick Skill

Use this when you have an integer lattice basis `B = (b1, ..., bn)` and a target point `t`, and you want a fast approximate answer to CVP (or BDD) without full enumeration.

## Preconditions

- `b_i ∈ Z^n`, full rank.
- target `t ∈ Z^n` (or rationals/reals; the output lattice vector is still in `Z^n`).
- best results when `B` is close to orthogonal (often after LLL/BKZ).

## Standard workflow

1. Reduce the basis:

```text
B' = LLL(B)    (or BKZ(B, β) for stronger reduction)
```

2. Run Babai in the reduced basis:

```text
v ≈ argmin_{x ∈ L(B')} ||x - t||
```

3. Treat `v` as a candidate:

- if you are in a BDD setting (noise is small), `v` is often correct,
- otherwise, use `v` as a starting point for enumeration / local search.

## Nearest-plane loop (with Gram–Schmidt)

Compute Gram–Schmidt:

- orthogonal vectors `b*_1, ..., b*_n`,
- squared lengths `||b*_i||^2`.

Initialize `residual ← t`.

For `i = n .. 1` (from last to first):

```text
c_i = <residual, b*_i> / ||b*_i||^2
k_i = round(c_i)   (nearest integer)
residual ← residual - k_i * b_i
```

Return the lattice vector:

```text
v = Σ k_i b_i
```

## Diagnostics

- If Babai output is poor, the basis is likely too skew → reduce more (LLL/BKZ).
- In tiny dimensions, verify quality with brute-force CVP in a bounded coefficient window.

