# Babai's Nearest Plane Algorithm

> Approximate CVP by rounding in a Gram–Schmidt coordinate system: “walk down orthogonal planes, one coefficient at a time.”

**Type:** Build
**Languages:** Python
**Prerequisites:** `04-lattices/03-svp-cvp` (CVP definition + brute force), `04-lattices/05-lll` (LLL reduction intuition + Gram–Schmidt)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## The Problem

The **Closest Vector Problem (CVP)** is the workhorse query in lattice cryptography and lattice attacks:

- given a basis `B = (b1, ..., bn)` and a target point `t ∈ R^n`,
- find the lattice vector `v ∈ L(B)` that minimizes `||v - t||`.

Exact CVP is hard in general, but you still need a practical way to get *a good candidate* quickly:

- **Bounded Distance Decoding (BDD):** if you know the target is close to the lattice (typical in cryptosystems), you want the “correct” nearest lattice point efficiently.
- **Attack demos:** in knapsack-style constructions, subset-sum embeddings, and many toy cryptanalytic setups, “LLL + a CVP-ish step” is the moment the secret pops out.
- **Tooling mental model:** real libraries (fplll/fpylll, Sage) expose *Babai* as a fast approximate CVP primitive used inside more powerful enumeration routines.

This lesson builds the classic approximation: **Babai’s nearest-plane algorithm**.

## The Concept

### CVP depends on the basis you choose

The lattice `L` is the *set* of all integer combinations of the basis vectors, but the basis itself can be wildly skew.

Babai’s algorithm is a “CVP approximation **relative to a basis**”. If the basis is close to orthogonal, it tends to work very well. If the basis is skew, it can be noticeably wrong.

This is why the standard recipe is:

```text
LLL-reduce the basis  →  run Babai in the reduced basis
```

### Gram–Schmidt gives the right “coordinate system”

Given a basis `b1, ..., bn`, Gram–Schmidt produces orthogonal vectors:

```text
b1* , b2* , ... , bn*
```

and projection coefficients:

```text
μ_{i,j} = <b_i, b*_j> / <b*_j, b*_j>    for j < i
```

Intuition:

- `b*_i` is the “new orthogonal direction” contributed by `b_i`.
- `μ_{i,j}` tells you how much of `b_i` lies along earlier orthogonal directions.

### Nearest plane = round one coefficient, subtract, repeat

Think of walking from the last vector to the first:

1. project the current residual onto the last orthogonal direction `b*_n`,
2. **round** that coordinate to the nearest integer,
3. subtract that integer multiple of the original basis vector,
4. continue with `b*_{n-1}`, etc.

On an orthogonal basis, this is literally “round each coordinate” and it solves CVP exactly. On a general basis, it’s an approximation that becomes better as the basis becomes more orthogonal.

## Build It

### Step 1: Exact Gram–Schmidt (rational arithmetic)

Babai’s decisions depend on dot products and divisions. Using floating point can introduce “almost 0.5” rounding mistakes on large integers.

For an educational implementation, keep it deterministic:

- represent Gram–Schmidt values with `fractions.Fraction`.

This lesson reuses the same exact Gram–Schmidt style as the LLL lesson.

### Step 2: Babai’s nearest-plane loop

Given a basis `B` and target `t`:

1. compute Gram–Schmidt `b*` and squared lengths `||b*_i||^2`,
2. initialize `residual ← t`,
3. for `i = n-1 .. 0`:
   - compute `c_i = <residual, b*_i> / ||b*_i||^2`,
   - choose `k_i = round(c_i)`,
   - update `residual ← residual - k_i * b_i`.

At the end, `v = Σ k_i b_i` is the algorithm’s approximate closest vector.

Run the demo:

```bash
python3 code/main.py
```

It prints:

- `babai(B, t)` on a skew basis,
- `babai(LLL(B), t)` after LLL reduction,
- the exact CVP answer via brute-force search in a bounded coefficient window (only feasible in tiny dimensions).

## Use It

In practice you don’t implement Babai by hand — you use lattice toolchains that already provide:

- high-performance Gram–Schmidt with stable floating-point precision management,
- LLL/BKZ reduction,
- Babai as a fast “good first guess” inside enumeration and BDD-style routines.

Common options:

- **SageMath** (wraps mature lattice libraries).
- **fplll / fpylll** (LLL/BKZ and CVP-related primitives).

Your takeaway: Babai is a *building block*, not a standalone “CVP solver for production”.

## Attack It

Babai’s “attack surface” is not a bug in arithmetic — it’s a **basis-quality failure mode**.

You can build two bases for the same lattice:

- one close to orthogonal (Babai works well),
- one skew (Babai makes an early rounding choice that sends you to the wrong coset).

This is exactly why lattice attacks almost always begin with **basis reduction**:

```text
bad basis  --(LLL/BKZ)-->  good basis  --(Babai / enumeration)-->  useful CVP candidates
```

In the lesson vectors, you’ll find an instance where:

- `babai(B, t)` returns a vector at distance `2`,
- `babai(LLL(B), t)` returns a vector at distance `1` (optimal in that toy case).

## Ship It

This lesson ships a small reusable artifact:

- `outputs/skill-babai-nearest-plane.md` — a quick checklist for “LLL then Babai” as an approximate CVP primitive.

## Exercises

1. **Easy:** Pick a 2D lattice basis `B` and a target `t`. Verify that Babai is exact when `B` is orthogonal (e.g., `((a,0),(0,b))`).
2. **Medium:** Find a 2D basis `B` where Babai returns a non-optimal vector for some target `t`. Confirm with brute-force CVP in a small coefficient window.
3. **Hard:** Build a small “BDD-style” instance: choose a lattice vector `v`, add a small error `e`, and try to recover `v` from `t = v + e` using `LLL + Babai`. Explore when it succeeds or fails as you change the error size.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| CVP | “Find the nearest lattice point” | Given a basis and target `t`, find `v ∈ L` minimizing `||v - t||`. |
| BDD | “CVP but easy if noise is small” | CVP restricted to targets guaranteed to be within a decoding radius. |
| Gram–Schmidt | “Orthogonalize the basis” | Produces orthogonal `b*` plus coefficients `μ` that describe projections. |
| Nearest plane | “Round in a smart coordinate system” | Process `b*_n ... b*_1`, round one coordinate at a time, subtract, repeat. |
| Basis reduction | “Make the basis nicer” | Unimodular transforms (LLL/BKZ) that preserve the lattice but improve geometry. |

## Test Vectors

Vectors live in `tests/vectors.json`. They are deterministic toy instances (not RFC/NIST), designed to:

- validate the Babai implementation,
- demonstrate how LLL reduction can improve Babai’s output in a skew basis.

## Further Reading

- L. Babai (1986): *On Lovász' lattice reduction and the nearest lattice point problem*.
- H. W. Lenstra, A. K. Lenstra, L. Lovász (1982): *Factoring polynomials with rational coefficients* (LLL).
- N. Gama, P. Q. Nguyen (2008): *Predicting Lattice Reduction* (reduction quality intuition).
