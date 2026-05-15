---
name: skill-field-extension-review
description: Checklist for reviewing field and extension-field parameters in cryptographic constructions
version: 1.0.0
phase: 2
lesson: 6
tags: [fields, extension-fields, irreducibility, finite-fields, pairings, validation]
---

# Field Extension Review

Use this checklist whenever a construction claims to work over a field, extension field, scalar field, or polynomial quotient field.

## Identify the Field

Write the exact object before reviewing code.

```text
Base field:          F_p, F_2, or another field
Characteristic:      p
Extension degree:    m
Construction:        F[x] / (f(x))
Modulus polynomial:  f(x)
Representation:      coefficient basis, tower basis, normal basis, etc.
```

If the code only says "mod" or "reduce," decide whether it is reducing integers, polynomials, or tower-field elements.

## Check Field Preconditions

| Question | Why it matters |
|----------|----------------|
| Is the base modulus prime? | `Z/nZ` is a field only when `n` is prime |
| Is the polynomial irreducible over the base field? | `F[x]/(f)` is a field only when `f` is irreducible |
| Is the extension degree what the protocol expects? | Wrong degree changes group orders and subgroup checks |
| Are non-residue parameters fixed and vetted? | Bad non-residue choices create zero divisors |
| Does the library type encode the field parameters? | Type-level parameters prevent mixed-field arithmetic |

## Quadratic Extension Quick Check

For odd prime `p`:

```text
F_p[u] / (u^2 - beta) is a field
iff beta is a quadratic non-residue mod p
```

If `beta = r^2`, then:

```text
(r + u)(r - u) = r^2 - u^2 = beta - beta = 0
```

Both factors are nonzero, so the quotient has zero divisors.

## Common Crypto Examples

```text
AES:        F_2[x] / (x^8 + x^4 + x^3 + x + 1)
BLS12-381: tower fields above F_p, including F_p^2 and F_p^12
SNARKs:    scalar fields F_r for circuit arithmetic
RS codes:  finite fields large enough for evaluation domains
```

## Failure Modes

| Mistake | Consequence |
|---------|-------------|
| Treating `Z/nZ` as a field for composite `n` | Nonzero elements may not invert |
| Reducing by a reducible polynomial | Zero divisors appear in the quotient |
| Mixing base-field and extension-field values | Equality, serialization, and subgroup checks break |
| Assuming every nonzero-looking denominator is invertible | Division can fail or leak exceptional paths |
| Reusing parameters without source citations | Implementations silently fork into incompatible fields |

## Safe Engineering Habit

For production cryptography, use audited field libraries with named parameters. From-scratch field checks are for understanding, test-vector generation, and parameter review, not for handling secrets.
