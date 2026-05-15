---
name: skill-bkz-tours
description: Checklist and mental model for BKZ lattice basis reduction (block tours + SVP oracle + insertion), and how to reason about the blocksize/runtime tradeoff
version: 1.0.0
phase: 4
lesson: 6
tags: [lattices, reduction, bkz, lll, enumeration, post-quantum]
---

# BKZ — Quick Skill

Use this when you have an integer lattice basis `B = (b1, ..., bn)` and you want a stronger reduction than LLL by spending exponential time in a local block size `β`.

## What BKZ does (one sentence)

BKZ is “LLL + local SVP”: it slides a `β`-vector window across the basis, finds a short vector in each block lattice, inserts it back into the basis using unimodular operations, and re-LLL’s to restore shape.

## Inputs / knobs

- `β` (block size): `2 <= β <= n`
  - `β = 2` is roughly “LLL strength”
  - larger `β` is stronger reduction but much slower
- `tours`: number of left-to-right passes (often stop early if a full tour makes no changes)
- `δ`: the LLL Lovász parameter (common: `3/4` for education; higher is stronger but slower)

## One tour (the outer loop)

For each block start index `k = 1..n`:

1. Define block `B_k = (b_k, ..., b_{min(k+β-1, n)})`
2. Ensure the block is “nice enough” (usually via local LLL / size reduction)
3. Run the **SVP oracle** in the *projected* block lattice to find a short non-zero vector `v`
4. If `v` is not an improvement, move on
5. Otherwise **insert** `v` back into the basis near position `k`
6. Run (local) LLL again to remove skew introduced by insertion

## SVP oracle (what it means in practice)

- Exact SVP is exponential in the block dimension `β`
- Practical BKZ uses Schnorr–Euchner enumeration (often with pruning)
- Security estimates often say “attacker runs BKZ(β)” which means they are paying this exponential cost

## Insertion (the lattice-preserving part)

The insertion must preserve the lattice, i.e. it must be a product of unimodular basis updates:

- swap columns
- add an integer multiple of one basis vector to another
- flip a sign

If your insertion step is not unimodular, you silently change the lattice (and your “reduction” is invalid).

## Quick sanity checks

- determinant magnitude is preserved: `|det(B)|` should not change
- the output is usually at least LLL-reduced (many implementations maintain this between insertions)
- “good reduction” shows up as noticeably shorter early vectors and flatter Gram–Schmidt profile

