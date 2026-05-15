---
name: skill-binary-field-review
description: Review checklist for GF(2^n) binary-polynomial arithmetic used in cryptographic code
version: 1.0.0
phase: 2
lesson: 8
tags: [crypto, finite-fields, gf2n, aes, review]
---

# Binary-Field Review Checklist

Use this checklist when reviewing code that claims to implement arithmetic in `GF(2^n)`.

## Field Parameters

1. Write the field as `F_2[x] / (m(x))`, not just "mod".
2. Record the exact modulus polynomial and its integer encoding.
3. Confirm `m(x)` is irreducible over `F_2`.
4. Confirm every element is reduced to degree `< n`.
5. Reject arithmetic between values that use different modulus polynomials.

## Representation

1. Interpret each bit as a coefficient in `F_2`, not as a base-10 digit.
2. Use XOR for addition and subtraction.
3. Use carryless multiplication before polynomial reduction.
4. Keep serialization byte order separate from polynomial coefficient order.

## Division and Inversion

1. Reject inversion of zero.
2. Use polynomial extended Euclid, exponentiation by `2^n - 2`, or a vetted library routine.
3. Treat failures as parameter bugs unless the modulus is intentionally a ring modulus.
4. Test inverses with `a * inv(a) = 1` for representative nonzero values.

## AES-Specific Checks

1. AES uses `x^8 + x^4 + x^3 + x + 1`, encoded as `0x11b`.
2. `xtime(0x57)` should be `0xae`.
3. `0x57 * 0x83` should be `0xc1`.
4. MixColumns maps `[db, 13, 53, 45]` to `[8e, 4d, a1, bc]`.

## Failure Modes

| Mistake | Consequence |
|---------|-------------|
| Using integer addition instead of XOR | Carries create the wrong ring |
| Reducing by a reducible polynomial | Nonzero elements may fail to invert |
| Forgetting reduction after multiplication | Values leave the field |
| Mixing AES and non-AES moduli | Test vectors and interoperability break |
| Treating table code as constant-time | Secret-dependent memory access leaks |

## Security Boundary

This course code is educational. Real cryptographic implementations need constant-time arithmetic, vetted tables, parameter citations, and side-channel review.
