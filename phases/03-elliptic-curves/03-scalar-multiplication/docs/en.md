# Scalar Multiplication — Double-and-Add, NAF, wNAF

> Multiply a point by a big integer without doing “k additions”.

**Type:** Build
**Languages:** Python
**Prerequisites:** 03-elliptic-curves/02-weierstrass-and-point-addition (curve + point add/double)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain why naive repeated addition is infeasible for 256-bit scalars and how the binary double-and-add method reduces additions to `O(log k)`
- Compute the Non-Adjacent Form (NAF) of a scalar and explain why NAF digits have no two adjacent nonzero entries
- Implement windowed NAF (wNAF) scalar multiplication by precomputing a table of odd multiples and using it to reduce the number of point additions
- Distinguish the operation traces of double-and-add, NAF, and wNAF and compare their average nonzero-digit densities
- Identify how variable-time control flow in double-and-add leaks scalar bits to a side-channel attacker observing the add/double pattern

## The Problem

Almost every elliptic-curve protocol reduces to one operation:

- ECDH key exchange: `shared = k · Q`
- ECDSA / Schnorr signing: compute points like `k · G` and `e · P`
- Scalar multiplication is also where most performance and most side-channel risk lives.

If you can’t do `k · P` efficiently and correctly, you can’t build (or audit) ECC systems.

## The Concept

Scalar multiplication is repeated group addition:

```
0·P = 𝒪
1·P = P
2·P = P + P
3·P = P + P + P
...
k·P = P added to itself k times
```

Doing that literally is `O(k)` additions, which is impossible when `k` is ~256 bits.

The trick: represent `k` in a form that makes “add P” rare, and “double” cheap.

### 1) Double-and-add (binary method)

Write `k` in binary: `k = Σ b_i 2^i`, `b_i ∈ {0,1}`.

Process bits from MSB→LSB:

- Always: double (multiply current accumulator by 2)
- Sometimes: add `P` (when the current bit is 1)

This is about one double per bit, and about half a point-adds per bit on average.

### 2) NAF (Non-Adjacent Form)

NAF writes `k = Σ d_i 2^i` but with digits `d_i ∈ {−1, 0, +1}` and **no adjacent nonzero digits**.

Consequence: fewer additions. You pay a little extra to sometimes add `−P` instead of `P`.

### 3) wNAF (windowed NAF)

wNAF generalizes NAF:

- digits are odd numbers in a bounded range (plus zeros)
- you precompute a small table of odd multiples of `P` once:

```
P, 3P, 5P, ..., (2^{w-1}-1)P
```

Then each nonzero digit is a single table lookup + add. Bigger windows mean more precompute memory, fewer adds.

## Build It

You’ll implement three scalar-multiplication flavors over a short-Weierstrass curve in affine coordinates:

- `scalar_mul_double_and_add`
- `scalar_mul_naf`
- `scalar_mul_wnaf`

All of them use only `point_add` and `point_neg`.

### Step 1: Double-and-add

Implement the classic binary method. Make sure you handle:

- `k = 0` → `𝒪`
- `k < 0` → `k·P = (−k)·(−P)`
- identity (`𝒪`) consistently (this repo uses `None`)

```python
from main import Curve, Point, scalar_mul_double_and_add

toy = Curve(p=97, a=0, b=1)
G = Point(10, 15)
print(scalar_mul_double_and_add(toy, 3, G))
```

### Step 2: NAF recoding + NAF scalar multiplication

Implement `naf_digits(k)` returning digits in least-significant-first order.

Then implement `scalar_mul_naf` by scanning digits MSB→LSB:

- double every step
- add `P` when digit is `+1`
- add `−P` when digit is `−1`

```python
from main import naf_digits

print(naf_digits(15))  # [-1, 0, 0, 0, 1]  because 15 = 16 - 1
```

### Step 3: wNAF recoding + windowed scalar multiplication

Implement `wnaf_digits(k, w)`, then precompute odd multiples of `P` up to `(2^{w-1}-1)P`.

For `w=5`, that’s a table of 8 points: `1P,3P,...,15P`.

```python
from main import wnaf_digits

print(wnaf_digits(12345, 4))
```

Run it:

```
python3 code/main.py
```

## Use It

In real systems you should not implement this yourself.

- `cryptography` (OpenSSL / RustCrypto behind the scenes) exposes ECDH/ECDSA APIs and does scalar multiplication internally.
- If you need to cross-check math for learning/debugging, `ecdsa` (Python) can compute `k · G` for standard curves.

Production scalar multiplication is engineered for:

- constant-time execution (to resist timing/power/EM attacks)
- complete formulas / special-case safety
- coordinate systems that avoid field inversions (projective/Jacobian)

## Attack It

Double-and-add leaks the scalar bits through its control flow:

- every bit: one doubling
- bit `1`: an extra addition

If an attacker can distinguish “double-only” vs “double+add” (timing, power, cache), they can recover the scalar.

This lesson includes a toy function `trace_double_and_add(k)` that produces a string like:

```
A D D A D ...
```

and a corresponding `recover_bits_from_trace(...)` to show how little side-channel signal is needed.

The fix is not “hide the trace string”. The fix is to use constant-time scalar multiplication (next lesson: Montgomery ladder) and constant-time field arithmetic.

## Ship It

This lesson ships a reviewer checklist prompt for scalar multiplication implementations:

- `outputs/prompt-ec-scalar-mul-checklist.md`

## Exercises

1. Easy: For `k ∈ [1..50]` on the toy curve, verify `double_and_add`, `naf`, and `wnaf` all agree.
2. Medium: For random 256-bit `k`, compare the **number of nonzero digits** in binary vs NAF vs wNAF(w=5).
3. Hard: Write a tiny “SPA attacker” that reconstructs `k` from a noisy double-and-add trace (missing or flipped events).

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Scalar multiplication | “Multiply point by k” | Add a point to itself, but computed with bit tricks |
| Double-and-add | “Binary method” | Use scalar bits: always double, sometimes add |
| NAF | “Sparse signed bits” | Digits in {−1,0,+1} with no adjacent nonzero digits |
| wNAF | “Windowed NAF” | Sparse digits plus a small precomputation table |

## Test Vectors

Source: project-internal vectors, cross-checked against `ecdsa` (secp256k1) and an independent script (toy curve).

Code must pass all vectors in `tests/vectors.json`.

## Further Reading

- SEC 1: Elliptic Curve Cryptography (group law + scalar multiplication context)
- Guide to Elliptic Curve Cryptography (Hankerson/Menezes/Vanstone) — NAF and window methods
