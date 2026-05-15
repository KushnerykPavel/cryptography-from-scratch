---
name: skill-prime-field-review
description: Review checklist for GF(p) arithmetic used in cryptographic code
version: 1.0.0
phase: 2
lesson: 7
tags: [crypto, finite-fields, algebra, review]
---

# Prime-Field Review Checklist

Use this checklist when reviewing code that claims to implement arithmetic in `GF(p)`.

## Field Parameters

1. Confirm the modulus `p` is prime.
2. Confirm every field element carries or can recover its modulus.
3. Reject arithmetic between values from different fields.
4. Normalize values into `0..p-1` at construction and after every operation.

## Division

1. Reject division by zero.
2. Compute inverses with a vetted algorithm for the context.
3. Do not return a sentinel such as `0`, `None`, or `-1` for failed inversion unless callers must handle it explicitly.
4. Treat negative exponents as inversion plus positive exponentiation.

## Group Checks

1. Remember that only nonzero field elements belong to `F_p^*`.
2. For generator checks, verify the element has order `p - 1`.
3. For large fields, use factorization of `p - 1` instead of brute-force order search.
4. For protocol groups, validate subgroup membership separately from base-field arithmetic.

## Polynomial Code

1. Reduce coefficients, inputs, and outputs modulo `p`.
2. Require distinct interpolation x-coordinates modulo `p`.
3. In Lagrange interpolation, every denominator must be nonzero modulo `p`.
4. Never run Shamir, Reed-Solomon, or polynomial-commitment code over a composite modulus by accident.

## Security Boundary

This course code is educational. Real cryptographic implementations need constant-time arithmetic, vetted parameters, side-channel review, and protocol-specific validation.
