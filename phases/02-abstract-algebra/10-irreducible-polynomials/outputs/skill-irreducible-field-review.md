---
name: skill-irreducible-field-review
description: Review extension-field construction parameters for irreducible polynomial mistakes.
version: 1.0.0
phase: 02
lesson: 10
tags: [cryptography, finite-fields, algebra, review]
---

# Irreducible Field Review

Use this when code constructs `GF(p^n)`, `GF(2^n)`, tower fields, pairing fields, Reed-Solomon fields, or any quotient `F_p[x]/(m(x))` that is meant to be a field.

## Checklist

1. Identify the coefficient field.
   - Confirm `p` is prime for `F_p`.
   - For binary fields, confirm arithmetic is over `F_2[x]`, not integer arithmetic modulo `2^n`.

2. Identify the modulus polynomial.
   - Record coefficient order and degree.
   - Normalize the modulus to monic form.
   - Reject degree `0` moduli.

3. Check irreducibility.
   - For degree `2` or `3`, root checks over `F_p` are enough.
   - For higher degree, use a real irreducibility test such as Rabin's criterion or a trusted algebra library.
   - Do not accept "no roots" as proof for degree `>= 4`.

4. Look for reducible-witness behavior.
   - If `m(x) = a(x)b(x)`, then `a` and `b` are nonzero zero divisors modulo `m`.
   - Confirm the implementation rejects reducible moduli before exposing division or inversion.

5. Validate inversion.
   - Inversion should use polynomial extended Euclid or a vetted library operation.
   - Nonzero elements should be invertible only after irreducibility is established.
   - Error messages should distinguish zero input from a bad reducible modulus when possible.

6. Check parameter provenance.
   - Prefer standard, published field parameters.
   - If parameters are generated, keep the generation and validation code in the repository.
   - Do not describe course or toy field code as production-safe.

## Common Findings

| Finding | Why it matters |
|---------|----------------|
| Root-only test on degree `>= 4` | A polynomial can factor into higher-degree pieces without linear roots |
| Reducible modulus accepted | The quotient has zero divisors, so division is not field division |
| Integer `%` used for polynomial reduction | Coefficients and powers are reduced in the wrong algebra |
| Missing coefficient-field validation | Polynomial long division needs field inverses for leading coefficients |
| Field values do not carry `p` and `m(x)` | Values from different fields can be accidentally mixed |

## Review Prompt

Review this extension-field construction. Identify the coefficient field, modulus polynomial, irreducibility proof or check, inversion method, and any place a reducible modulus could be accepted. If the code uses root checks, verify whether the degree makes that sufficient. Report concrete zero-divisor witnesses when available.
