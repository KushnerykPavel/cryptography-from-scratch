# BKZ — Block Korkine-Zolotarev

> BKZ is “LLL with an SVP oracle”: reduce locally in blocks, then insert the short vector you found back into the basis.

**Type:** Build
**Languages:** Python
**Prerequisites:** `04-lattices/03-svp-cvp` (SVP definition + brute force), `04-lattices/04-gauss-lagrange-2d` (2D reduction intuition), `04-lattices/05-lll` (LLL reduction + Gram–Schmidt)
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## The Problem

LLL is the first lattice reduction algorithm you reach for — and it’s often surprisingly effective. But when you need stronger reduction quality, you almost always end up using **BKZ** (Block Korkine–Zolotarev).

BKZ is the workhorse behind:

- real lattice attacks (“run BKZ with blocksize β and see if the secret pops out”),
- security estimates (“what β do we need to break these parameters?”),
- practical tooling (fplll/fpylll, NTL, Sage, etc.).

If you don’t understand BKZ, you end up stuck in a common failure mode: you can run an off-the-shelf BKZ command, but you can’t reason about what it’s doing, what the block size means, or why it sometimes “suddenly finds” a much shorter vector.

## The Concept

### The BKZ picture

LLL looks at **adjacent pairs** of vectors through Gram–Schmidt and swaps when the basis is too skew.

BKZ generalizes this idea:

1. pick a window (a **block**) of `β` consecutive basis vectors,
2. solve a (projected) **SVP** inside that block (hard, exponential in `β`),
3. **insert** the short vector you found back into the basis,
4. clean up with LLL again, and move the window forward.

You can think of it as an “LLL outer loop” with an “SVP inner oracle”.

### Why blocksize `β` is the knob

- `β = 2` is roughly “LLL strength”.
- larger `β` means you solve harder local SVP subproblems, and typically get a better reduced basis.
- runtime grows *quickly* with `β` because SVP is exponential in dimension.

So BKZ is always a **quality vs runtime tradeoff**.

### What we implement in this lesson (simplified BKZ)

Real BKZ implementations:

- work in projected sublattices,
- use floating-point Gram–Schmidt with careful precision management,
- use fast Schnorr–Euchner enumeration (with pruning),
- do deep insertion variants (BKZ 2.0, progressive BKZ, slide reduction, …).

This lesson keeps things small and deterministic:

- **LLL** is implemented with exact `fractions.Fraction` arithmetic (same style as the LLL lesson).
- the “SVP oracle” inside a block is a **brute-force coefficient search** in a small window (toy).
- insertion is done via a constrained unimodular update (column-additions + swaps) so we preserve the lattice without implementing full unimodular matrix completion.

It’s not fast, but it’s faithful to the mental model: “LLL + local SVP + insert + repeat”.

## Build It

### Step 1: Reuse the exact LLL reducer

BKZ is built on LLL. Before you touch blocks, you want the basis to be LLL-reduced.

This lesson includes:

- `lll_reduce(...)`
- `is_lll_reduced(...)`

implemented exactly with `Fraction` so results are deterministic on integer inputs.

### Step 2: A tiny SVP oracle for blocks

In a block of size `β`, we want “some very short non-zero vector” in the sublattice spanned by that block.

We use a toy oracle:

- choose a coefficient bound `k`,
- enumerate coefficients in `[-k, k]^(β-1)` and force the last coefficient to be `+1`,
- pick the shortest resulting lattice vector.

That “last coefficient is `+1`” constraint is not what real BKZ does — it’s a convenient trick so we can insert the vector using only unimodular column operations (adds + swaps).

### Step 3: Insert the short vector using unimodular moves

If a block oracle returns coefficients:

```text
z = (z0, z1, ..., z_{β-2}, 1)
```

then the short vector is:

```text
v = z0*b_k + z1*b_{k+1} + ... + z_{β-2}*b_{k+β-2} + 1*b_{k+β-1}
```

We can produce `v` *as a basis vector* with legal lattice-preserving moves:

1. **column additions:** update `b_{k+β-1} ← b_{k+β-1} + z_i*b_{k+i}` for `i < β-1`,
2. **swaps:** swap that updated vector forward until it becomes the first vector in the block.

Then we run `lll_reduce(...)` again to restore a nice shape.

### Step 4: A BKZ “tour” loop

We slide the block from left to right, attempting an insertion at each position.

We repeat the whole sweep for a small number of tours (or stop early if a full tour makes no changes).

Run the demo:

```bash
python3 code/main.py
```

## Use It

In real work, you do not implement BKZ yourself — you call a tuned library:

- `fplll` / `fpLLL` (C/C++) is the standard reference implementation family.
- `fpylll` exposes BKZ to Python.
- SageMath exposes BKZ via multiple backends.

This lesson’s `code/main.py` optionally runs a tiny `fpylll` BKZ reduction (if installed) as a sanity check.

## Attack It

BKZ is the attacker’s upgrade path.

If you publish a lattice basis that contains (or hides) a short vector — which is exactly what happens in many lattice cryptosystems and many lattice embeddings used in cryptanalysis — then BKZ with a higher blocksize is the “next lever” after LLL:

- LLL might find a noticeably shorter vector but not the secret.
- BKZ(β) with larger β often finds much shorter vectors, and can make the secret visible in toy or weak parameters.

The core takeaway: “my basis looks long” is not a security argument. The attacker chooses β and pays the runtime cost.

## Ship It

This lesson ships a practical checklist:

- `outputs/skill-bkz-tours.md`

Use it as a mental model when you read papers or run tooling:

- What does “blocksize β” buy you?
- Where does the SVP oracle sit inside BKZ?
- What does “one tour” mean, and why do implementations talk about “tours” and “early abort”?

## Exercises

1. Easy: Run `bkz_reduce` with `beta=2` on the LLL lesson’s test inputs. When does it match LLL output exactly? When does it differ but still preserve `|det|`?
2. Medium: Increase `coeff_bound` and/or `tours` on a small 4×4 basis. How does the shortest vector norm change? How does runtime change?
3. Hard (attack framing): Build a tiny “hidden short vector” lattice: start from a basis that contains a very short vector, apply random unimodular transformations to make it look skew/long, then see how far LLL vs BKZ(β) gets you in recovering a short vector.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| BKZ | “Stronger LLL” | Blockwise reduction: sweep blocks, solve local SVP, insert short vectors, and re-LLL |
| Block size `β` | “BKZ parameter” | The dimension of the local SVP subproblem; larger β is stronger but exponentially slower |
| Tour | “One pass” | One left-to-right sweep over all block positions |
| SVP oracle | “Enumeration” | The inner subroutine that finds a short vector in a block lattice (expensive) |
| Insertion | “Put the short vector in front” | A lattice-preserving basis update that moves a found short vector into the basis |

## Test Vectors

Source: BKZ originates in Schnorr’s 1987 block reduction work. This lesson’s tests are project-internal deterministic toy instances for the simplified reducer.

Your code must pass `tests/vectors.json`.

## Further Reading

- Schnorr (1987). *A hierarchy of polynomial time lattice basis reduction algorithms* — introduces block reduction ideas
- Nguyen & Vallée (eds.). *The LLL Algorithm: Survey and Applications* — context and variants
- fplll / fpylll documentation — the de-facto practical implementation family
