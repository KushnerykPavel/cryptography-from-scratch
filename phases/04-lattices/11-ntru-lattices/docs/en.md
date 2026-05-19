# NTRU Lattices

> A public key `h` is just “multiplication by `h`” — a circulant matrix — and the secret key is a short vector in the lattice that matrix defines.

**Type:** Build
**Languages:** Python
**Prerequisites:** `04-lattices/05-lll`, `04-lattices/10-rlwe-mlwe`
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain how the NTRU relation f·h ≡ g (mod q) translates polynomial multiplication into a short-vector problem in a 2n-dimensional lattice
- Compute the circulant matrix Rot(h) that encodes "multiplication by h" as a linear map on coefficient vectors
- Implement cyclic convolution mod q, toy NTRU key generation (h ≡ g·f⁻¹ mod q), and the explicit NTRU lattice basis B = [I | Rot(h); 0 | qI]
- Verify that the secret key pair (f, g) is a short vector inside the public NTRU lattice
- Apply LLL to the public lattice basis and recover a short vector satisfying the NTRU relation for toy parameters

## The Problem

NTRU is often described as “polynomials modulo `x^n - 1`”, which can feel far away from the lattice algorithms you actually use in attacks and tooling (LLL/BKZ, shortest vectors, nearest plane).

If you can’t translate:

- “`h` is a public polynomial” into “`h` is a *circulant matrix*”, and
- “`(f,g)` is a secret polynomial pair” into “`(f,g)` is a *short lattice vector*”,

then the security story stays magical: you can’t reason about why certain parameters are safe, why some toy instances break instantly, or why “finding any rotation of the secret” is considered a break.

This lesson builds that bridge: you’ll construct the **public NTRU lattice basis** from `h` and `q`, then use **LLL** to recover a short vector that satisfies the NTRU relation for toy parameters.

## The Concept

### The ring

Work in the cyclic ring:

```text
R = Z[x] / (x^n - 1)
R_q = (Z/qZ)[x] / (x^n - 1)
```

Represent a polynomial as its `n` coefficients:

```text
f(x) = f0 + f1 x + ... + f(n-1) x^(n-1)   ↔   (f0, f1, ..., f(n-1))
```

Multiplication is **cyclic convolution** (because `x^n ≡ 1`).

### The NTRU relation

Toy NTRU key generation picks small (ternary) polynomials `f,g` and publishes:

```text
h ≡ g * f^{-1}   (mod q)     in R_q
```

Equivalently:

```text
f * h ≡ g   (mod q)
```

So the public key `h` hides a “short relation” between `f` and `g`.

### Circulant matrices: “multiplication by h”

Multiplying by `h` is a linear operation on coefficient vectors, so it has a matrix.

Let `Rot(h)` be the `n×n` circulant matrix whose rows are cyclic shifts of `h`. Then:

```text
u * h   ↔   u · Rot(h)
```

This is the key translation step: ring multiplication becomes matrix multiplication.

### The NTRU lattice

Define the lattice of all integer pairs `(u,v)` that satisfy the public NTRU constraint:

```text
L_{h,q} = { (u, v) ∈ Z^n × Z^n : v ≡ u*h (mod q) } ⊂ Z^(2n)
```

Unpack “mod q”:

```text
v = u*h + q*t    for some t ∈ Z^n
```

So a concrete row-basis for `L_{h,q}` is:

```text
B = [ I   Rot(h) ]
    [ 0    q I   ]
```

If `h ≡ g * f^{-1} (mod q)`, then `(f,g)` is in this lattice and is short (because `f,g` are small).

### Why this becomes an attack

For real parameters, “find the secret short vector in a `2n`-dimensional lattice” is hard.

For toy parameters (small `n`, modest `q`), LLL often finds a short vector quickly — which is why parameter selection matters and why NTRU security is ultimately about (approximate) shortest-vector problems.

## Build It

### Step 1: Cyclic polynomial multiplication in `Z_q[x]/(x^n - 1)`

You’ll implement cyclic convolution mod `q`:

```python
from main import poly_mul_cyclic_mod

q = 29
a = (1, 0, 1, 0, 0, 0, 0)
b = (0, 1, 0, 0, 0, 0, 0)
ab = poly_mul_cyclic_mod(a, b, q)
```

### Step 2: Toy NTRU keygen (`h ≡ g * f^{-1} (mod q)`)

Sample small ternary `f,g`, invert `f` in `R_q`, and compute `h`.

```python
from main import NTRUParams, Sha256CtrRng, ntru_keygen, ntru_secret_is_in_lattice

params = NTRUParams(n=7, q=29, f_ones=2, f_negs=1, g_ones=2, g_negs=2)
rng = Sha256CtrRng(b"demo")
pk, sk = ntru_keygen(rng, params)
assert ntru_secret_is_in_lattice(sk, pk, params.q)
```

### Step 3: Build the NTRU lattice and recover a short secret via LLL (toy break)

Construct the basis:

```python
from main import ntru_lattice_basis_rows

B = ntru_lattice_basis_rows(pk.h, params.q)  # 2n row vectors in Z^(2n)
```

Then run LLL and read a short vector as a candidate `(f,g)` pair:

```python
from main import recover_ntru_secret_via_lll

rec = recover_ntru_secret_via_lll(pk=pk, q=params.q)
assert ntru_secret_is_in_lattice(rec, pk, params.q)
```

Run it:

```
python3 code/main.py
```

## Use It

In practice, you don’t implement lattice reduction yourself.

This lesson’s `code/main.py` includes an optional sanity check using `fpylll` (if installed): it builds the same public basis matrix and runs library LLL to show it also finds a short vector.

For actual NTRU deployments, use a vetted implementation and vetted parameters. This lesson’s code is a learning tool for the “polynomials ↔ lattices” translation, not a production cryptosystem.

## Attack It

The textbook toy attack is exactly what you just implemented:

1. build the public lattice basis `B` from `h` and `q`,
2. run LLL,
3. interpret a short output vector as a candidate `(f,g)` satisfying `f*h ≡ g (mod q)`.

Important nuance: the NTRU lattice contains not only `(f,g)` but also **rotations** (cyclic shifts) that correspond to multiplying by powers of `x` in `R`. Recovering any such short vector is usually considered a break, because it gives an equivalent secret relation.

## Ship It

`outputs/skill-ntru-lattice.md`: a compact checklist for turning an NTRU public key into a lattice basis and running a toy LLL recovery.

## Exercises

1. Easy: Change `n` to `5` or `9` (keep it small) and regenerate vectors. When does LLL still recover a short relation quickly?
2. Medium: Add a “canonicalization” step: given a recovered `(f,g)`, rotate it to make the first non-zero coefficient of `f` appear at index `0`. Verify it still satisfies `f*h ≡ g (mod q)`.
3. Hard: Implement a simple “multiple candidates” recovery: scan the reduced basis for the shortest vector whose `f` and `g` are ternary and match the expected weights.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| NTRU relation | “`h` is `g/f`” | A modular relation `f*h ≡ g (mod q)` in the cyclic ring `Z_q[x]/(x^n-1)` |
| circulant matrix | “shifts of `h`” | A matrix encoding cyclic convolution, i.e. “multiplication by `h`” |
| NTRU lattice `L_{h,q}` | “the public lattice” | The set of integer pairs `(u,v)` such that `v ≡ u*h (mod q)` |
| short vector | “small coefficients” | A lattice vector with small Euclidean norm; in NTRU it corresponds to small `(f,g)` |

## Test Vectors

Source: NTRU is due to Hoffstein–Pipher–Silverman (1996/1998). These tests use deterministic toy instances generated by this lesson’s implementation (so they’re stable regression tests for your ring arithmetic, keygen relation, and toy LLL recovery).

Your code must pass `tests/vectors.json`.

## Further Reading

- Hoffstein–Pipher–Silverman — *NTRU: A Ring-Based Public Key Cryptosystem* (ANTS-III, 1998)
- Peikert (2016) — *A Decade of Lattice Cryptography* (context for why short-vector problems show up everywhere)
