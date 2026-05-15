---
name: skill-ntru-lattice
description: Quick checklist for translating an NTRU public key h into a public lattice basis and running a toy LLL recovery of a short (f,g) relation
version: 1.0.0
phase: 4
lesson: 11
tags: [lattices, ntru, circulant, lll, svp, post-quantum, ring]
---

# NTRU Lattices — Quick Skill

Use this when you need to go from “NTRU is polynomials mod `x^n-1`” to “NTRU is a `2n`-dimensional lattice containing a short vector”.

## Setup

Pick toy parameters:

- `n`: small (e.g. 5–9)
- `q`: modulus (toy: a small odd integer; larger makes the `qI` block clearly non-short)
- `R_q = Z_q[x]/(x^n-1)`

Represent polynomials as length-`n` coefficient vectors.

## Public key relation

Keygen publishes a polynomial `h ∈ R_q` such that for small polynomials `f,g`:

```text
h ≡ g * f^{-1} (mod q)    ⇔    f*h ≡ g (mod q)
```

## Circulant matrix for “multiply by h”

Build the `n×n` circulant matrix `Rot(h)` so that:

```text
u*h   ↔   u · Rot(h)
```

`Rot(h)` rows are cyclic shifts of `h`.

## NTRU lattice basis (rows)

Define the lattice:

```text
L_{h,q} = { (u,v) ∈ Z^n×Z^n : v ≡ u*h (mod q) }
```

Row basis matrix:

```text
B = [ I   Rot(h) ]
    [ 0    q I   ]    (size 2n × 2n)
```

Any lattice vector has the form `(u, u*h + q*t)`.

In particular, the secret `(f,g)` is a short lattice vector.

## Toy lattice attack

1. Build the public basis `B` from `h` and `q`.
2. Run LLL on `B`.
3. Interpret a short output vector as `(f,g)`.
4. Verify it satisfies `f*h ≡ g (mod q)` (coefficient-wise).

## Safety warning

Educational implementation. Not constant-time. Not production-safe.

