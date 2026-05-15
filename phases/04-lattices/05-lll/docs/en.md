# LLL Algorithm from Scratch

> LLL is “Gauss reduction, but in n dimensions”: iteratively size-reduce vectors and swap when Gram–Schmidt says the basis is still too skew.

**Type:** Build
**Languages:** Python
**Prerequisites:** `04-lattices/02-bases-determinant-minima` (dot products, determinants), `04-lattices/03-svp-cvp` (SVP/CVP definitions), `04-lattices/04-gauss-lagrange-2d` (2D reduction intuition)
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## The Problem

In lattice cryptography, the “hardness” is phrased in terms of the lattice (SVP, CVP, shortest dual vector, etc.), but inputs arrive as a *basis* — and a basis can be wildly misleading.

Two bases can generate the same lattice:

- one basis looks short and almost orthogonal (“easy mode”),
- another looks long and highly skew (“looks hard”),
- but the lattice — the set of all integer combinations — is identical.

If you can turn a bad basis into a good one, you unlock a huge amount of practical work:

- approximate SVP (find a “pretty short” non-zero lattice vector),
- nearest-plane style algorithms (Babai),
- the standard tool inside attacks (subset sum, knapsack-style “basis hiding”, small modular equations),
- the core subroutine in modern lattice toolchains (BKZ builds on LLL).

## The Concept

### The two operations that preserve the lattice

A lattice basis is not unique. You can transform it without changing the lattice using **unimodular** operations (integer determinant `±1`), which correspond to “legal basis changes”:

1. **Size-reduce** a vector by subtracting an integer multiple of an earlier vector:

```text
b_k ← b_k - r*b_j   with r ∈ Z
```

2. **Swap** adjacent basis vectors:

```text
swap(b_{k-1}, b_k)
```

Both operations keep the lattice the same. LLL is just a disciplined way to apply them.

### Why Gram–Schmidt is the right lens

When a basis is skew, its vectors are long mostly because they “point in similar directions”. Gram–Schmidt orthogonalization decomposes each `b_k` into:

- a component along the earlier vectors, and
- an orthogonal remainder `b*_k`.

LLL uses two signals from Gram–Schmidt:

- **projection coefficients** `μ_{k,j}`: “how much of `b_k` lies along `b*_j`?”
- **orthogonal lengths** `||b*_k||^2`: “how much new orthogonal mass does `b_k` contribute?”

### LLL’s two conditions

With a parameter `δ` (usually `3/4`), a basis is LLL-reduced if:

1. **Size reduction:** for all `k > j`, `|μ_{k,j}| ≤ 1/2`.
2. **Lovász condition:** for all `k ≥ 1`,

```text
||b*_k||^2 ≥ (δ - μ_{k,k-1}^2) * ||b*_{k-1}||^2
```

If the Lovász condition fails, the basis is too skew: swap `b_k` with `b_{k-1}` and continue.

LLL does *not* guarantee the shortest vector (that’s exact SVP), but it guarantees a *provably not-too-bad* basis and, in practice, often finds strikingly short vectors in small dimensions.

## Build It

### Step 1: Exact Gram–Schmidt (with rational arithmetic)

LLL’s decisions depend on projection coefficients `μ`. If you compute `μ` with floating point on large integers, rounding noise can flip “swap / no swap” decisions.

For this lesson, we keep it simple and exact: implement Gram–Schmidt using `fractions.Fraction`.

### Step 2: Size reduction via nearest-integer rounding

For each `k`, and each `j < k`, LLL chooses the integer `r = round(μ_{k,j})` and updates:

```python
bk = bk - r * bj
```

This enforces `|μ_{k,j}| ≤ 1/2` after recomputing Gram–Schmidt.

### Step 3: The LLL loop (swap on Lovász failure)

After size reduction at index `k`, check the Lovász condition. If it holds, move forward. If it fails, swap `b_k` and `b_{k-1}`, recompute Gram–Schmidt, and step back.

### Step 4: A checker: `is_lll_reduced`

LLL output is not unique (sign flips and different unimodular paths exist), so the most robust “test oracle” is a predicate that checks the two defining conditions.

This lesson implements:

- `lll_reduce(...)` — the reducer,
- `is_lll_reduced(...)` — the checker.

Run the demo:

```bash
python3 code/main.py
```

It prints the input basis, the reduced basis, and verifies that `is_lll_reduced` returns `True`.

If you happen to have `fpylll` installed locally, the demo also runs a sanity-check reduction using the library.

## Use It

In real work you do not implement LLL yourself — you call a hardened library:

- `fplll` / `fpLLL` (C/C++) is the classic implementation family.
- `fpylll` is a Python binding (commonly used in research notebooks).
- SageMath exposes LLL and many lattice tools.

This lesson keeps the from-scratch code stdlib-only; the optional `fpylll` call in `code/main.py` is a “compare outputs if you have it installed” sanity check, not a dependency.

## Attack It

“Basis hiding” is not security.

If a scheme tries to hide a short lattice vector by publishing a long, skew basis, LLL can often recover a noticeably shorter vector — and in toy parameters that’s enough to fully break the scheme.

Two common patterns:

1. **Hidden short vector.** A secret `s` is a short integer combination of the public basis vectors. LLL tries to find *some* short vector; in weak setups, the secret is among the short vectors.
2. **Subset sum / knapsack embeddings.** A subset sum instance is embedded into a lattice so that a short vector corresponds to a solution. LLL is the first tool you reach for.

The lesson takeaway: “make the basis look long” is not a hardness assumption. Hardness depends on dimension, distributions, and reductions — and LLL is the first thing an attacker runs.

## Ship It

This lesson ships a reduction checklist you can reuse:

- `outputs/skill-lll-reduction.md`

Use it as a “preflight” when you read lattice papers or implement attacks:

- What does size reduction guarantee?
- What does Lovász actually check?
- How does `δ` affect output?

## Exercises

1. Easy: For a few random 2D bases, compare `lll_reduce` output to the Gauss/Lagrange reducer from the previous lesson. When do they match up to signs/unimodular changes?
2. Medium: Change `δ` from `3/4` to `0.99`. How do the output norms change? How does runtime change?
3. Hard: Build a toy subset sum embedding lattice (small numbers) and use `lll_reduce` to recover the subset in easy instances. Then increase density until it stops working reliably.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| LLL reduction | “nD Gauss reduction” | An algorithm that applies unimodular operations to make a basis shorter/less skew with provable guarantees |
| Gram–Schmidt `b*` | “Orthogonalized basis” | The orthogonal components `b*_k` used to measure skew and progress |
| Gram–Schmidt coefficient `μ` | “Projection scalar” | `μ_{k,j} = <b_k, b*_j> / <b*_j, b*_j>` — how much of `b_k` lies along earlier orthogonal directions |
| Size reduction | “Make coefficients small” | Enforce `|μ_{k,j}| ≤ 1/2` by subtracting nearest integers |
| Lovász condition | “Swap test” | A criterion that detects when adjacent vectors are too skew and must be swapped |
| `δ` parameter | “Strength knob” | Larger `δ` typically yields a stronger reduction (shorter vectors) at higher runtime cost |

## Test Vectors

Source: LLL is from Lenstra–Lenstra–Lovász (1982). This lesson’s tests use small project-internal integer bases designed to force both size-reduction and swaps while staying deterministic under exact `Fraction` arithmetic.

Your code must pass `tests/vectors.json`.

## Further Reading

- Lenstra, Lenstra, Lovász (1982). *Factoring polynomials with rational coefficients* — the original LLL paper
- Nguyen & Vallée (eds.). *The LLL Algorithm: Survey and Applications* — a readable deep dive and many applications
- Micciancio & Regev (2009). *Lattice-based Cryptography* — the crypto context for why LLL matters
