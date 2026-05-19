# Pairings — Weil & Tate from Scratch

> A pairing is a “bridge”: it turns hard elliptic-curve group relations into multiplicative relations you can compute with.

**Type:** Build
**Languages:** Python
**Prerequisites:** 03-elliptic-curves/02-weierstrass-and-point-addition, 03-elliptic-curves/03-scalar-multiplication
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain the three defining properties of a pairing (`e : G1 × G2 → GT`) — bilinearity, non-degeneracy, and efficiency — and why each matters for protocols like BLS signatures
- Implement arithmetic in the quadratic extension field `Fp2 = Fp[i]/(i² + 1)` and use it to perform point operations on the toy supersingular curve over `F_{p²}`
- Compute the reduced Tate pairing via Miller's algorithm (the line-evaluation loop) followed by final exponentiation to force the output into the `r`-th roots of unity
- Distinguish the Weil pairing from the reduced Tate pairing in terms of their Miller-loop structure and why final exponentiation is needed for Tate but not Weil
- Apply the MOV reduction to recover a discrete logarithm on the toy curve, and explain what embedding degree and subgroup order properties prevent this attack on production pairing-friendly curves

## The Problem

Pairings are the missing primitive behind a huge chunk of modern cryptography:

- BLS signatures and aggregation,
- identity-based encryption (IBE),
- short proofs and SNARK-friendly constructions (accumulators, commitments, recursion ingredients),
- protocols where you need to relate exponents that live in *two different elliptic-curve groups*.

If you only know elliptic curves as “add points and multiply by scalars”, pairing-based protocols feel like magic because they keep writing expressions like:

```text
e(aP, bQ) = e(P, Q)^(ab)
```

Without understanding how a pairing is computed, you can’t safely review:

- subgroup checks and cofactor clearing (where many real-world pairing bugs live),
- which curve parameters make pairings secure (embedding degree, subgroup order),
- why “small toy curves” make discrete log attacks easy (MOV reduction).

This lesson builds the Weil and Tate pairings from scratch on a tiny supersingular curve so you can see the full pipeline end-to-end: extension fields → Miller loop → (for Tate) final exponentiation → bilinearity checks → an actual attack.

## The Concept

### What a pairing is (in the way protocols use it)

A pairing is a map:

```text
e : G1 × G2 → GT
```

where:

- `G1` and `G2` are (sub)groups of elliptic curve points of the same prime order `r`,
- `GT` is a multiplicative group of `r`-th roots of unity inside a finite field extension.

The three properties you care about:

1) **Bilinear:** `e(aP, bQ) = e(P, Q)^(ab)`  
2) **Non-degenerate:** for nonzero `P`, there exists a `Q` such that `e(P, Q) != 1`  
3) **Efficient:** you can actually compute it (Miller’s algorithm)

### Why extension fields show up

For most curves, the full `r`-torsion group `E[r]` has size `r²`, but it is not all defined over the base field `F_p`. To make `e(P, Q)` land in a group where nontrivial `r`-th roots of unity exist, you work in an extension field `F_{p^k}`.

The smallest such `k` is the **embedding degree**.

### Weil vs Tate (at a high level)

- **Weil pairing** is an alternating bilinear pairing on `E[r] × E[r]` that outputs an `r`-th root of unity.
- **Tate pairing** is easier to compute in practice (same core Miller loop), but you apply a **final exponentiation** to force the output into the unique subgroup of `r`-th roots of unity.

In both cases, the workhorse is the same: **Miller’s algorithm**, which multiplies a sequence of “line evaluations” corresponding to the elliptic curve group law.

### The toy curve we’ll use

To keep arithmetic small enough to print and test, we use a supersingular curve:

```text
p = 103
E / F_p : y^2 = x^3 + x
#E(F_p) = p + 1 = 104
r = 13 divides #E(F_p)
embedding degree k = 2
```

We will compute pairings in `F_{p^2}` using the quadratic extension `a + b·i` with `i^2 = -1`.

## Build It

You’ll implement:

- a tiny quadratic extension field `Fp2`,
- elliptic curve arithmetic over `Fp2`,
- Miller’s algorithm (the “pairing loop”),
- the reduced Tate pairing,
- a Weil pairing implementation,
- the MOV reduction as a concrete “Attack It”.

### Step 1: Implement `Fp2 = F_p[i] / (i^2 + 1)`

In `Fp2`, elements look like `a + b·i` where `a, b ∈ F_p` and `i^2 = -1`.

For our toy curve we choose `p = 103` which satisfies `p ≡ 3 (mod 4)`, so `-1` is not a square in `F_p` and the extension is actually a field.

```python
from main import Fp2, FP2_I

x = Fp2(3, 4)
y = Fp2(10, 20)

print(x + y)
print(x * y)
print(FP2_I * FP2_I)
```

### Step 2: Implement curve arithmetic over `Fp2`

Pairing computations happen over `F_{p^k}`. Here `k = 2`, so we do point addition and scalar multiplication on `E(F_{p^2})`.

```python
from main import TOY_CURVE, PointFp2, Fp2, point_add_fp2, scalar_mul_fp2

P = PointFp2(Fp2(18, 0), Fp2(44, 0))
Q = scalar_mul_fp2(TOY_CURVE, 2, P)
R = point_add_fp2(TOY_CURVE, P, Q)

print(Q)
print(R)
```

### Step 3: Compute a reduced Tate pairing

The reduced Tate pairing is:

```text
e(P, Q) = f_{r,P}(Q)^((p^k - 1)/r)
```

The hard part is the Miller function evaluation `f_{r,P}(Q)`, which uses the same doubling-and-adding structure as scalar multiplication, but multiplies “line evaluation” terms along the way.

```python
from main import (
    TOY_CURVE,
    TOY_G1_GENERATOR,
    TOY_R,
    distortion_map,
    fp2_to_json,
    point_fp_to_fp2,
    reduced_tate_pairing,
)

P = point_fp_to_fp2(TOY_G1_GENERATOR)
Q = distortion_map(P)

e = reduced_tate_pairing(TOY_CURVE, TOY_R, P, Q)
print(fp2_to_json(e))
```

### Step 4: Compute a Weil pairing

Weil pairing and Tate pairing share a core Miller loop. The Weil pairing is alternating and bilinear, and (for points in `E[r]`) returns an `r`-th root of unity without a final exponentiation step.

```python
from main import TOY_CURVE, TOY_G1_GENERATOR, TOY_R, distortion_map, fp2_to_json, point_fp_to_fp2, weil_pairing

P = point_fp_to_fp2(TOY_G1_GENERATOR)
Q = distortion_map(P)

e = weil_pairing(TOY_CURVE, TOY_R, P, Q)
print(fp2_to_json(e))
```

Run it:

```
python3 code/main.py
```

## Use It

Do not implement pairings yourself for real systems. Use an audited library that matches the curve you are deploying.

Common choices:

- `py_ecc` for educational Python experiments (BLS12-381 pairing and group ops),
- Rust ecosystems: `arkworks`, `blstrs`, `pairing` crates,
- production BLS: libraries built on `blst`.

The important thing is not the API shape — it’s the guarantees:

- subgroup-checked points,
- correct cofactor clearing,
- constant-time finite-field arithmetic,
- validated parameters and correct final exponentiation.

## Attack It

### MOV reduction (how pairings can break “the wrong curves”)

If a curve has a small embedding degree, pairings can reduce elliptic-curve discrete log (ECDLP) to discrete log in `F_{p^k}^*`. On toy curves, that makes ECDLP trivial.

On our toy curve, suppose an attacker sees:

```text
Q = kP
```

and wants `k`. Using a distortion map `ψ`, the reduced Tate pairing satisfies:

```text
e(Q, ψ(P)) = e(kP, ψ(P)) = e(P, ψ(P))^k
```

Now `k` is a discrete log in a multiplicative group of order `r = 13`, so you can brute force it.

```python
from main import (
    TOY_CURVE,
    TOY_G1_GENERATOR,
    TOY_R,
    distortion_map,
    point_fp_to_fp2,
    reduced_tate_pairing,
    scalar_mul_fp2,
)

P = point_fp_to_fp2(TOY_G1_GENERATOR)
Q = scalar_mul_fp2(TOY_CURVE, 7, P)
T = distortion_map(P)

g = reduced_tate_pairing(TOY_CURVE, TOY_R, P, T)
h = reduced_tate_pairing(TOY_CURVE, TOY_R, Q, T)

for k in range(TOY_R):
    if g**k == h:
        print("recovered k =", k)
        break
```

Takeaway: pairings are not “good” or “bad”. They are a tool. Pairing-friendly curves are chosen so this reduction does not make ECDLP easy (large `r`, carefully chosen `k`, and hardened parameters).

## Ship It

This lesson ships a review prompt you can use to audit pairing implementations and pairing-based protocol code:

- `outputs/prompt-pairing-implementation-review-checklist.md`

## Exercises

1. Easy: Verify bilinearity: check that `e(2P, Q) == e(P, Q)^2` for both Weil and reduced Tate pairings on the toy curve.
2. Medium: Find a different `r` dividing `#E(F_p)` for a different small `p ≡ 3 (mod 4)` and re-run the same pipeline.
3. Hard: Implement a simple “distortion map finder” that tries small endomorphisms to map a `G1` point into an independent `G2` point over `Fp2`.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Pairing | “A function that multiplies exponents” | A bilinear map `G1 × G2 → GT` with output in a multiplicative group |
| `E[r]` | “The subgroup” | The `r`-torsion points: points `P` such that `rP = 𝒪` |
| Embedding degree `k` | “How pairing-friendly the curve is” | The smallest `k` such that `r | (p^k − 1)` |
| Miller loop | “The pairing computation” | An algorithm that evaluates a rational function built from lines in the group law |
| Final exponentiation | “A cleanup step” | Raises a Tate value into the `r`-th roots of unity so the pairing is well-defined |
| MOV attack | “Pairings break ECC” | A reduction that can move ECDLP into `F_{p^k}^*` when parameters are weak |

## Test Vectors

This lesson uses a toy curve (not a standards curve), so vectors are “known-answer checks” for the implementation on that curve:

- `tests/vectors.json` contains expected values for the distortion map and both pairings.
- `tests/test_vectors.py` checks these values and also enforces `e(P, Q)^r = 1` and non-degeneracy (`!= 1`).

## Further Reading

- Victor Miller (1986), “The Weil pairing, and its efficient calculation” — the original efficient pairing computation idea
- Lawrence C. Washington, “Elliptic Curves: Number Theory and Cryptography” — clear exposition of Weil/Tate pairings and Miller’s algorithm
- Darrel Hankerson, Alfred Menezes, Scott Vanstone, “Guide to Elliptic Curve Cryptography” — practical details and pairing background
