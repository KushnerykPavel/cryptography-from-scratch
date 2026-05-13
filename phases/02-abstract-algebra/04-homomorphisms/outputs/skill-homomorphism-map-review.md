---
name: skill-homomorphism-map-review
description: Checklist for reviewing structure-preserving maps, kernels, images, and isomorphism assumptions in cryptographic constructions
version: 1.0.0
phase: 2
lesson: 4
tags: [homomorphisms, isomorphisms, kernels, images, discrete-log, validation]
---

# Homomorphism Map Review

Use this checklist whenever a construction maps one algebraic object into another.

## Identify the Map

Record the domain, codomain, operations, and exact mapping rule.

```text
Domain group:       G
Domain operation:   *
Codomain group:     H
Codomain operation: ·
Map:                f: G -> H
Preservation rule:  f(a * b) = f(a) · f(b)
```

If the two operations are written with the same symbol, rewrite them explicitly before reviewing the code.

## Check Kernel and Image

| Question | Why it matters |
|----------|----------------|
| What maps to the codomain identity? | This is the kernel; a nontrivial kernel collapses distinct inputs |
| Which codomain values are reachable? | This is the image; unreachable values break surjectivity assumptions |
| Is the kernel trivial? | A trivial kernel is the finite-group signal for injectivity |
| Is the image the full codomain? | If not, the map lands in a proper subgroup |
| Does `|G| = |ker f| * |im f|` hold? | Finite homomorphisms should satisfy this size relation |

## Common Crypto Examples

```text
Exponent map:       k -> g^k
Preserves:          addition of exponents -> group multiplication
Kernel risk:        exponents collapse modulo ord(g)
Image risk:         outputs live only in <g>, not necessarily the full group
Security boundary:  inverse direction is the discrete logarithm problem
```

Do not call an exponent map an isomorphism unless the domain is reduced modulo the exact order of `g` and the codomain is exactly the generated subgroup `<g>`.

## Failure Modes

| Mistake | Consequence |
|---------|-------------|
| Mapping into a larger group but reasoning as if the image is full | Subgroup assumptions become wrong |
| Ignoring a nontrivial kernel | Multiple secrets may produce the same public value |
| Reducing exponents by the wrong modulus | Operation preservation can fail |
| Treating an efficient forward map as an efficient inverse map | Discrete-log hardness is accidentally erased |
| Skipping identity handling | Degenerate public keys or commitments can pass |

## Safe Engineering Habit

For production cryptography, use library types that encode the intended subgroup and map. From-scratch homomorphism checks are for understanding assumptions, not for validating high-value protocol inputs.
