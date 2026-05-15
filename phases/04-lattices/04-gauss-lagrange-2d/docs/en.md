# Gauss / Lagrange Reduction in 2D

> In 2D, lattice reduction is the Euclidean algorithm in disguise: keep subtracting the best multiple until nothing gets shorter.

**Type:** Build
**Languages:** Python
**Prerequisites:** `04-lattices/01-what-is-a-lattice`, `04-lattices/02-bases-determinant-minima` (dot products, determinants, “basis ≠ lattice”)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## The Problem

In lattice crypto, you’re given a basis `B` (two vectors in this lesson). The attacker’s “hard problem” is usually stated in terms of the *lattice* (the set of all integer combinations), but the input is a *basis* (a coordinate system).

The core failure mode is:

- a basis can look huge and skew,
- yet the lattice can still contain a very short vector,
- and if an attacker can find that short vector, many toy schemes collapse.

In 2D, there’s a fast, exact, integer-only algorithm that turns a “bad” basis into a “good” one — and the first vector of the reduced basis is a shortest non-zero lattice vector. This lesson builds that algorithm, because it is:

- the cleanest place to understand “reduction” without black boxes, and
- the conceptual ancestor of LLL (the workhorse reduction algorithm in higher dimensions).

## The Concept

We work in `Z^2` with an ordered basis `(b1, b2)` where each `bi` is a 2D integer vector.

### The one operation you’re allowed to do

Replacing `b2` by `b2 - m*b1` for any integer `m` does not change the lattice:

```text
L(b1, b2) = L(b1, b2 - m*b1)
```

This is a unimodular basis change: it’s “row/column operations over Z”, not floating-point geometry.

### Pick the best m: “size reduction”

Treat `m` as a real number for a moment. Consider the squared length:

```text
||b2 - m*b1||^2
```

This is a quadratic function of `m` and is minimized at:

```text
μ = <b1, b2> / <b1, b1>
```

But we must keep integer combinations, so we choose:

```text
m = round(μ)   (nearest integer)
```

and set:

```text
b2 ← b2 - m*b1
```

This makes `b2` as short as possible “using” `b1`.

### When do we stop?

A 2D basis is Gauss/Lagrange reduced when:

- `||b1|| <= ||b2||` (shorter vector comes first), and
- `2*|<b1,b2>| <= ||b1||^2` (the projection of `b2` onto `b1` is small; `b2` isn’t “almost parallel” to `b1`)

Geometrically, that second condition implies the angle between `b1` and `b2` is at least 60° (i.e. the basis is not extremely skew).

### The algorithm: reduce, maybe swap, repeat

1. Ensure `b1` is the shorter vector (swap if needed).
2. Size-reduce `b2` using `b1` by subtracting the best multiple.
3. If the new `b2` became shorter than `b1`, swap and repeat.
4. Otherwise stop: you have a reduced basis.

## Build It

Everything here is exact integer arithmetic. No floats, no `numpy`, no hidden linear algebra.

### Step 1: vector ops + nearest-integer division

Implement:

- `dot_2d(a,b)` and `norm2_2d(v)`
- `round_div_nearest(n, d)` for `n/d` rounded to the nearest integer (avoid Python `round()` quirks)

### Step 2: the size-reduction step

Given `(b1, b2)` with `b1 != 0`, compute:

```text
m = round(<b1,b2> / ||b1||^2)
b2' = b2 - m*b1
```

This is the lattice analogue of “subtract the quotient” in Euclid’s algorithm.

### Step 3: loop with swap until stable

Implement `gauss_lagrange_reduce_2d(basis)` that repeats:

- swap if `||b2|| < ||b1||`,
- reduce `b2` by the best multiple of `b1`,
- stop when `m = 0` (meaning `b2` is already size-reduced w.r.t. `b1`).

Add `is_gauss_reduced_2d(basis)` to check the stopping conditions.

### Step 4: use it as a 2D SVP solver

In 2D, the first vector of a reduced basis is a shortest non-zero lattice vector (up to sign).

Implement:

- `shortest_vector_gauss_2d(basis)` → returns that first vector.

## Use It

In practice you rarely hand-roll reduction; you call a library.

One common Python binding is `fpylll`:

- It exposes LLL, which generalizes the 2D idea.
- In 2D, LLL output should be consistent with (or comparable to) Gauss reduction.

This lesson’s `code/main.py` includes an optional `fpylll` sanity-check: if the library is installed, it runs `LLL.reduction` on the same 2D basis and prints the reduced matrix.

## Attack It

Toy “basis hiding” is not security.

Suppose someone publishes the basis:

```text
b1 = (1000, 1)
b2 = (1,    0)
```

To a beginner, `b1` looks huge, so the lattice “looks hard”.

But the lattice obviously contains the short vector `(1,0)` (it’s literally `b2`). Even if the short vector were less obvious (hidden as a combination of `b1` and `b2`), in 2D an attacker can just run Gauss/Lagrange reduction and recover a shortest vector quickly.

The lesson: security comes from high dimension + well-chosen distributions + careful reductions, not from “making a basis look long”.

## Ship It

This lesson ships a reusable reduction checklist:

- `outputs/skill-gauss-lagrange-reduction.md`

Use it whenever you need to:

- sanity-check a claimed “reduced” 2D basis,
- quickly extract a shortest vector in a 2D lattice,
- build intuition before moving to LLL.

## Exercises

1. Easy: Run your reducer on `b1=(2,0)`, `b2=(1,1)`. Verify the output basis is reduced and `det` stays unchanged (up to sign).
2. Medium: For a few random small bases, compare `shortest_vector_gauss_2d` with a brute-force search over coefficients in `[-k,k]^2` for increasing `k`. When do they match? When does brute force become slow?
3. Hard: Build the “Euclid in disguise” connection: form a 2D lattice from integers `a,b` and show how reduction relates to finding small remainders / Bézout coefficients.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Size reduction | “Make the basis shorter” | Replace `b2` by `b2 - m*b1` with integer `m` chosen to minimize `||b2 - m*b1||` |
| Gauss / Lagrange reduction | “2D LLL” | The exact 2D algorithm that outputs the two successive minima as basis vectors |
| Gram–Schmidt coefficient `μ` | “Projection scalar” | `μ = <b1,b2>/<b1,b1>`, the real coefficient minimizing `||b2 - μ b1||` |
| Unimodular change | “Integer basis change” | Integer matrix with determinant `±1` that changes basis without changing the lattice |
| Reduced basis (2D) | “Nice basis” | `||b1||<=||b2||` and `2|<b1,b2>| <= ||b1||^2` (not too skew) |

## Test Vectors

Source: project-internal examples, cross-checked by brute-force enumeration; reduction criteria match standard Gauss/Lagrange reduction statements.

Your code must pass `tests/vectors.json`.

## Further Reading

- [Lattice basics (Sharif)](https://public.csusm.edu/ssharif/crypto/LatticeBasics.pdf) — defines Lagrange–Gauss reduction and links it to Gram–Schmidt
- [Gaussian reduction (CryptoBook)](https://cryptohack.gitbook.io/cryptobook/lattices/lll-reduction/gaussian-reduction) — a practical intuition write-up of the 2D algorithm
- [Lattice reduction (Wikipedia)](https://en.wikipedia.org/wiki/Lattice_reduction) — overview and historical context
