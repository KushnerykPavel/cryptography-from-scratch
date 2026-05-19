# Bases, Determinant, Successive Minima

> A basis can lie to you; the determinant and minima can’t.

**Type:** Build
**Languages:** Python
**Prerequisites:** `04-lattices/01-what-is-a-lattice` (integer span, unimodular changes)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain why the lattice determinant is a volume invariant that stays constant under unimodular basis changes
- Compute the determinant of an integer basis matrix using exact Bareiss fraction-free elimination
- Distinguish between the determinant (covolume) and the successive minima as separate geometric properties of a lattice
- Identify cases where two lattices share the same determinant but have wildly different first successive minima
- Verify that brute-force enumeration of λ1 and λ2 in small dimensions is basis-independent

## The Problem

Lattice cryptography is full of “geometry words”: *volume*, *short vectors*, *density*, *reduction*. If you don’t know which quantities are actually lattice invariants, it’s easy to reason from the wrong thing.

Example mistake: “If I publish a basis with long vectors, the lattice must be sparse, so it’s hard.” That is false. A basis can look huge while the lattice still contains a tiny vector.

This lesson gives you two invariants you will use constantly:

- the **determinant** (a volume / covolume invariant), and
- the **successive minima** `λ1, …, λn` (the “true” short-vector scale of the lattice).

## The Concept

### Basis vs lattice invariants

A lattice `L(B) = {Bz : z ∈ Z^n}` has infinitely many bases: if `U ∈ Z^{n×n}` is **unimodular** (`det(U)=±1`), then `L(B) = L(BU)`.

A basis is a coordinate choice. A lattice invariant is something that stays the same under unimodular basis changes.

### Determinant = volume of the fundamental cell

In full rank (`B ∈ R^{n×n}` invertible), the **fundamental parallelepiped** is:

```text
P(B) = { Bx : x ∈ [0,1)^n }.
```

Its volume is `|det(B)|`. This value depends only on the lattice, so we define:

```text
det(L) = |det(B)|.
```

You should read `det(L)` as “how much space each lattice point gets, on average.”

### Successive minima = the real “short-vector scale”

Fix a norm (we’ll use Euclidean `||·||2`). The **successive minima** are:

```text
λi(L) = the smallest r such that L contains i linearly independent vectors
        with norm ≤ r.
```

So:

- `λ1(L)` is the length of a shortest non-zero lattice vector (SVP’s target).
- `λ2(L)` is the smallest radius that contains *two* independent lattice vectors.
- …

Computing exact minima is hard in high dimension, but in tiny dimensions we can brute-force them to build intuition.

### Determinant does not determine minima

Two lattices can have the same determinant and wildly different `λ1`. For example, both of these have `det = 100`:

- `diag(1, 100)` has `λ1 = 1`
- `diag(10, 10)` has `λ1 = 10`

Same volume-per-point, but one lattice has a trivially short vector. This is the “attack” you should keep in mind: **determinant alone is not a security measure**.

## Build It

We’ll build a small toolbox:

- exact `det(B)` for integer matrices (no floating-point),
- unimodular basis changes (to show invariance),
- brute-force `λ1` and `λ2` for tiny lattices (intuition microscope).

### Step 1: Exact determinant with integer arithmetic (Bareiss)

If you compute determinants with floating-point Gaussian elimination, you can get rounding issues even for modest integers. For lattice work you want *exact* arithmetic.

We’ll implement a fraction-free elimination variant (Bareiss) that stays in integers and does only exact divisions.

```python
det = det_int_square([[2, 1], [0, 1]])  # 2
```

### Step 2: Unimodular basis changes preserve the lattice (and `det`)

If `U` is unimodular (`det(U)=±1`) then `B' = B U` is another basis of the same lattice. We’ll implement `change_basis_unimodular` and verify:

```text
|det(BU)| = |det(B)| · |det(U)| = |det(B)|.
```

```python
B = ((2, 0), (1, 1))             # columns
U = ((1, 1), (0, 1))             # unimodular (det=1)
B2 = change_basis_unimodular(B, U)
```

### Step 3: Brute-force `λ1` and `λ2` in small dimensions

For `n=2` (and tiny coefficient windows), we can brute-force vectors `v = Bz` for `z ∈ [-k,k]^n` and compute:

- `λ1` as the shortest non-zero vector norm
- `λ2` as the smallest radius that contains two independent vectors

This is *not* an SVP solver. It’s a way to see that changing the basis changes which short vectors are “visible” in a small coefficient window, even though the lattice itself is the same.

Run it:

```
python3 code/main.py
```

## Use It

In real lattice work, you use a library like `fpylll` to handle integer linear algebra and reduction reliably (LLL/BKZ, Gram–Schmidt, enumeration tooling).

We’re not depending on `fpylll` in this lesson, but once you start experimenting with real parameter sizes, it’s the “practical toolbox” you’ll reach for.

## Attack It

**Attack the wrong heuristic:** “If `det(L)` is large, then the shortest vector must be large.”

False. Determinant is a volume invariant, not a shortest-vector invariant.

You can have `det(L)=100` and still have a unit vector in the lattice (`λ1=1`) by choosing a very “skinny” lattice. If you estimated hardness from `det(L)^{1/n}` alone, you would be catastrophically wrong.

## Ship It

A reusable prompt for checking invariants intuition lives at `outputs/prompt-det-vs-minima.md`.

## Exercises

1. Easy: Pick two different unimodular matrices `U1`, `U2` and verify `det(BU1)=det(BU2)=det(B)`.
2. Medium: Find two different 2D lattices with the same determinant but different `λ1`. Explain why determinant didn’t predict the shortest vector.
3. Hard: For a skewed basis `B`, brute-force `λ1` for increasing coefficient bounds `k`. When does it stabilize? Why does this break down in higher dimensions?

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| lattice determinant | “det(B)” | the covolume: volume of the fundamental parallelepiped `|det(B)|` |
| unimodular | “invertible over Z” | integer matrix with determinant `±1` (so it maps `Z^n` bijectively) |
| λ1 (first minimum) | “the shortest basis vector” | the length of a shortest non-zero lattice vector (basis-independent) |
| successive minima | “the k-th shortest vector” | smallest radius containing `k` independent lattice vectors |

## Test Vectors

Project-internal integer linear algebra examples for determinant, unimodular invariance, and toy minima brute-force checks.

## Further Reading

- Micciancio, Regev — *Lattice-based Cryptography* (survey) — the “map” of the area.
- Nguyen, Vallée (eds.) — *The LLL Algorithm* — classic reference for reduction (next lessons).
- Any geometry-of-numbers notes that cover Minkowski and successive minima (for the “why det and minima are linked, but not equal” story).
