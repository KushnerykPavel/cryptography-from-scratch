---
name: skill-lwe
description: Quick checklist for building a toy LWE instance (samples + Regev-style bit encryption + decryption thresholding + tiny brute-force attack)
version: 1.0.0
phase: 4
lesson: 9
tags: [lattices, lwe, post-quantum, pke, noise, learning-with-errors]
---

# LWE — Quick Skill

Use this when you need a small, deterministic, educational LWE demo that you can test and reason about.

## Core object: noisy linear equations mod q

Pick:

- `q`: modulus (integer, typically odd in toys)
- `n`: secret dimension
- `m`: number of equations (rows)
- `s`: secret (often “small”, e.g. ternary)
- `A`: uniform random matrix in `Z_q^{m×n}`
- `e`: small error vector in `Z^m`

Publish:

```text
b = A·s + e   (mod q)
```

## Toy Regev-style bit encryption

Public key: `(A, b)`. Secret key: `s`.

Encrypt bit `μ ∈ {0,1}`:

```text
choose r ∈ {0,1}^m, small e1 ∈ Z^n, small e2 ∈ Z
u = A^T·r + e1            (mod q)
v = b^T·r + e2 + μ·(q/2)  (mod q)
ct = (u, v)
```

Decrypt:

```text
x = v - u^T·s   (mod q) ≈ μ·(q/2) + small noise
μ̂ = argmin_{b∈{0,q/2}} dist_mod_q(x, b)
```

## Sanity checks (correctness, not security)

- `q` must be “big enough” compared to the total noise so `x` doesn’t wrap across the decision boundary.
- Keep a `center_lift` function to interpret residues as signed small integers when debugging.
- Use a deterministic RNG for test vectors; never use this code for production.

## Tiny attack for intuition (toy only)

If the secret is ternary and `n` is tiny, brute force works:

1. enumerate `s ∈ {-1,0,1}^n`
2. compute `e = b - A·s (mod q)`
3. center-lift each coordinate and check `|e_i| ≤ bound`

Real schemes rely on `n` being large enough that this is impossible.

## Safety warning

Educational implementation. Not constant-time. Not production-safe.

