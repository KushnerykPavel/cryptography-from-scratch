---
name: skill-finite-field-library-api-review
description: Review checklist for finite-field APIs (GF(p) and GF(p^m)) used in cryptographic code
version: 1.0.0
phase: 2
lesson: 14
tags: [crypto, finite-fields, algebra, api, review]
---

# Finite-Field Library API Review Checklist

Use this checklist when reviewing code that claims to implement arithmetic in `GF(p)` or `GF(p^m)`.

## Field Parameters and Types

1. Prime fields: confirm `p` is prime and validated at construction time.
2. Extension fields: confirm modulus polynomial `f(x)` is monic and irreducible over `F_p`.
3. Ensure every element carries (or can recover) its field parameters (`p`, and modulus for extensions).
4. Reject arithmetic between values from different fields (even if the values share the same integer range).
5. Normalize every element on construction (reduce modulo `p`, and modulo `f(x)` for extensions).

## Arithmetic Invariants

1. Addition/subtraction/multiplication always reduce to canonical representation.
2. Division is implemented only as multiplication by inverse.
3. Inversion rejects zero and fails loudly on non-invertible elements.
4. Negative exponentiation is implemented as inversion plus positive exponentiation.
5. Equality comparisons and `int()`/serialization are consistent with the canonical representation.

## Extension-Field Specifics

1. Polynomial `divmod` is correct over `F_p` (handles leading coefficient inverses).
2. Multiplication reduces modulo `f(x)` and never grows unbounded in degree.
3. Inversion uses extended Euclid in `F_p[x]` (or a correct exponentiation fallback).
4. Irreducibility checks are explicit and documented as toy/educational if not optimized.

## AES / GF(2^8) Footguns

1. Byte-to-polynomial mapping is consistent (bit i ↔ x^i) and documented.
2. The AES modulus is exactly `x^8 + x^4 + x^3 + x + 1` (0x11B) when implementing AES math.
3. Reject out-of-range byte inputs and avoid silently truncating.

## Security Boundary

This course code is educational. Production crypto needs constant-time arithmetic, vetted parameters, side-channel review, and protocol-specific validation.

