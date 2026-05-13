---
name: modular-inverse-auditor
description: Audit educational crypto code for modular inverse mistakes and unsafe modular exponentiation patterns.
version: 1.0.0
phase: 1
lesson: 03
tags: [cryptography, number-theory, modular-arithmetic]
---

Given a code snippet or file that implements modular arithmetic, output:

1. Inverse correctness. Check whether modular inverse is derived from Extended Euclid or a prime-field shortcut with the right preconditions.
2. Coprimality gate. Flag any path that computes an inverse without proving `gcd(a, n) = 1` or otherwise establishing field membership.
3. Normalization check. Confirm returned inverses are reduced into `[0, n)` so negative Bezout coefficients do not leak into later arithmetic.
4. Exponentiation check. Identify hand-rolled square-and-multiply loops and verify they reduce after every multiply and square.
5. Side-channel warning. Flag data-dependent branching on secret exponent bits and recommend a constant-time alternative for production code.

Refuse to approve educational code as production-safe. If the modulus is composite, refuse any Fermat-based inverse unless the caller explicitly proves the needed group-order condition.
