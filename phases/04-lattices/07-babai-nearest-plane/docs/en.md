# Babai's Nearest Plane Algorithm
> Approximate CVP by rounding in a Gram–Schmidt coordinate system.

**Type:** Build
**Languages:** Python
**Prerequisites:** `04-lattices/03-svp-cvp` (CVP definition + brute force), `04-lattices/05-lll` (Gram–Schmidt + reduction intuition)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why Babai’s nearest-plane algorithm is a basis-dependent approximate CVP solver
- Compute exact Gram–Schmidt data (`b*`, `μ`, `||b*_i||^2`) using rational arithmetic
- Implement the nearest-plane loop (project → round → subtract) from last to first direction
- Distinguish BDD (guaranteed-near targets) from general CVP and predict when Babai succeeds
- Apply the standard LLL-then-Babai workflow and measure improvement on a skew basis

## The Problem

In lattice cryptography and lattice attacks, you repeatedly need a “good guess” for the **Closest Vector Problem (CVP)**: given a basis `B = (b1, …, bn)` and a target point `t`, find a lattice vector `v ∈ L(B)` minimizing `||v - t||`. Exact CVP is expensive, even in small dimensions, so you need a fast approximation that behaves well on typical instances.

This shows up concretely in **bounded-distance decoding (BDD)** situations where `t` is *promised* to be close to the lattice (cryptosystems: secret + small error), and in attack demos where the workflow is “reduce the basis → do a CVP-ish step → see the secret pop out”. In real tooling, Babai’s algorithm is often the first candidate you try before you do anything more expensive.

This lesson implements **Babai’s nearest-plane algorithm** and shows why the standard recipe is “LLL first, then Babai”.

## The Concept

Babai is “rounding in the right coordinate system”.

For an orthogonal basis, CVP reduces to independent rounding of coordinates. For a skew basis, naive rounding is meaningless because basis coordinates are entangled. Gram–Schmidt turns the basis into orthogonal directions `b*_1, …, b*_n` with projection coefficients

```text
μ_{i,j} = <b_i, b*_j> / <b*_j, b*_j>    (j < i)
```

Nearest-plane solves an approximate CVP by walking from the last orthogonal direction to the first:

```text
residual ← t
for i = n .. 1:
  c_i = <residual, b*_i> / ||b*_i||^2
  k_i = round(c_i)
  residual ← residual - k_i b_i
return v = Σ k_i b_i
```

If the basis is close to orthogonal, the rounding decisions are reliable. If the basis is very skew, an early rounding decision can send you to the wrong “plane”, and later steps can’t recover. This is why basis reduction (LLL/BKZ) is the usual pre-processing step.

## Build It

### Step 1: Exact Gram–Schmidt (Fractions)
```python
def _dot_frac_int(a: list[Fraction], b: list[int]) -> Fraction:
    return sum(x * y for x, y in zip(a, b))


def _dot_frac(a: list[Fraction], b: list[Fraction]) -> Fraction:
    return sum(x * y for x, y in zip(a, b))


def _gram_schmidt(basis: list[list[int]]):
    n = len(basis)
    b_star: list[list[Fraction]] = []
    mu: list[list[Fraction]] = [[Fraction(0) for _ in range(n)] for __ in range(n)]
    B: list[Fraction] = [Fraction(0) for _ in range(n)]

    for i in range(n):
        v = [Fraction(x) for x in basis[i]]
        for j in range(i):
            if B[j] == 0:
                raise ValueError("basis must be full rank (det != 0)")
            mu_ij = _dot_frac_int(b_star[j], basis[i]) / B[j]
            mu[i][j] = mu_ij
            if mu_ij:
                v = [vk - mu_ij * bjk for vk, bjk in zip(v, b_star[j])]
        b_star.append(v)
        B[i] = _dot_frac(v, v)
    return b_star, mu, B
```
Gram–Schmidt uses dot products and divisions, and Babai’s decisions depend on “is this coefficient closer to `k` or `k+1`?”. Using `Fraction` makes these comparisons deterministic and avoids floating-point “almost 0.5” bugs on integer inputs.

### Step 2: Nearest-integer rounding for rationals
```python
def _round_fraction_nearest(x: Fraction) -> int:
    if x < 0:
        return -_round_fraction_nearest(-x)
    p = x.numerator
    q = x.denominator
    return (2 * p + q) // (2 * q)
```
Babai needs a precise “nearest integer” operation on exact rationals. This implementation rounds half-integers away from zero (e.g., `±1/2 → ±1`), which is simple and deterministic for teaching and testing.

### Step 3: Babai’s nearest-plane loop
```python
def babai_nearest_plane(basis: Basis, target: Vec) -> BabaiResult:
    n = _require_full_rank_square_basis(basis)
    _require_same_dim(target)
    if len(target) != n:
        raise ValueError("target dimension mismatch")

    B = [list(b) for b in basis]
    b_star, _, Bsq = _gram_schmidt(B)

    residual = [Fraction(x) for x in target]
    coeffs = [0 for _ in range(n)]

    for i in range(n - 1, -1, -1):
        if Bsq[i] == 0:
            raise ValueError("basis must be full rank (det != 0)")
        ci = _dot_frac(residual, b_star[i]) / Bsq[i]
        ki = _round_fraction_nearest(ci)
        coeffs[i] = ki
        if ki != 0:
            residual = [ri - ki * bi for ri, bi in zip(residual, B[i])]

    v = lattice_vector(basis, tuple(coeffs))
    diff = [Fraction(v_i) - Fraction(t_i) for v_i, t_i in zip(v, target)]
    dist2 = _dot_frac(diff, diff)
    return BabaiResult(coeffs=tuple(coeffs), vector=v, residual=tuple(residual), dist2=dist2)
```
The loop processes directions from last to first, repeatedly projecting the residual onto `b*_i`, rounding that coefficient, and subtracting the corresponding multiple of the original basis vector `b_i`. The result is an approximate closest vector whose quality depends on the basis geometry.

### Step 4: LLL-then-Babai (and a tiny brute-force checker)
```python
def babai_after_lll(
    basis: Basis,
    target: Vec,
    *,
    delta: Fraction = Fraction(3, 4),
    max_iters: int = 100_000,
) -> tuple[Basis, BabaiResult]:
    reduced = lll_reduce(basis, delta=delta, max_iters=max_iters)
    return reduced, babai_nearest_plane(reduced, target)


def cvp_bruteforce(basis: Basis, target: Vec, coeff_bound: int) -> CVPResult:
    n = _require_full_rank_square_basis(basis)
    _require_same_dim(target)
    if len(target) != n:
        raise ValueError("target dimension mismatch")
    if coeff_bound < 0:
        raise ValueError("coeff_bound must be non-negative")

    best_key = None
    best = None
    for z in iter_coeffs(n, coeff_bound):
        v = lattice_vector(basis, z)
        d2 = norm2(vec_sub(v, target))
        key = (d2, z, v)
        if best_key is None or key < best_key:
            best_key = key
            best = CVPResult(coeffs=tuple(z), vector=v, dist2=d2)

    if best is None:
        raise ValueError("no candidates found")
    return best
```
In practice you almost always reduce the basis first (LLL/BKZ) and then run Babai. To make the demo concrete, we also include a brute-force CVP routine over a small coefficient window so you can verify when Babai is optimal (and when it is not) in toy dimensions.

Run it:
```bash
python3 code/main.py
```

## Use It

Use Babai through mature lattice toolchains that already combine basis reduction, stable Gram–Schmidt, and CVP/BDD-related primitives:

- **SageMath** — high-level lattice interface; wraps mature backends.
- **fplll / fpylll** — LLL/BKZ and CVP-related building blocks (including Babai-style nearest-plane).

Treat Babai as a fast candidate generator, not as a “production CVP solver”.

## Pitfalls

- **Row/column confusion:** decide whether your basis vectors are stored as columns or rows and stick to it everywhere (dot products, determinants, lattice-vector reconstruction).
- **Float rounding bugs:** using floats can flip a `round()` decision when a coefficient is near a half-integer; the output can jump to a different lattice coset.
- **Skew basis overconfidence:** Babai can be far from optimal on a skew basis; LLL/BKZ first is not optional in most workflows.
- **Tie-breaking:** Python’s `round()` is banker’s rounding; if you use it accidentally, you can get different behavior than “nearest integer, half away from zero”.
- **Comparing to CVP without bounds:** brute-force CVP checks only a coefficient window; choose bounds carefully and don’t mistake “best in window” for “global optimum”.

## Ship It

This lesson ships a reusable checklist you can paste into a review, design doc, or incident note:

- `outputs/skill-babai-nearest-plane.md` — a “LLL then Babai” procedure + diagnostics for approximate CVP / BDD work.

Use it when you need a fast CVP candidate and want a repeatable, reviewable workflow.

## Exercises

1. **Easy:** Run `python3 code/main.py`. Observe how `babai(B,t)` improves after LLL reduction on the skew basis demo.
2. **Medium:** Extend `code/main.py` with a second 2D skew basis of your choice. Measure the distance before/after LLL and compare to `cvp_bruteforce` for a small coefficient window.
3. **Hard:** Integrate a real library workflow (e.g., SageMath or fpylll): reduce a random basis with LLL/BKZ and compare the library’s nearest-plane candidate to your toy implementation on the same small instance.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| CVP | “Find the nearest lattice point” | Given `B` and target `t`, find `v ∈ L(B)` minimizing `||v - t||`. |
| BDD | “CVP but easy if noise is small” | CVP restricted to targets promised to be within a decoding radius. |
| Gram–Schmidt | “Orthogonalize the basis” | Produces orthogonal `b*` plus projection coefficients `μ`. |
| Nearest plane | “Round in a smart coordinate system” | Walk `b*_n → … → b*_1`, rounding one coordinate at a time. |
| Basis reduction | “Make the basis nicer” | Unimodular transforms (LLL/BKZ) that preserve the lattice but improve geometry. |

## Further Reading

- L. Babai, *On Lovász' lattice reduction and the nearest lattice point problem* (1986) — introduces nearest-plane / closest-hyperplane approximation for CVP.
- H. W. Lenstra, A. K. Lenstra, L. Lovász, *Factoring polynomials with rational coefficients* (1982) — LLL algorithm and lattice basis reduction.
- N. Gama, P. Q. Nguyen, *Predicting Lattice Reduction* (2008) — intuition about reduction quality and practical behavior.
