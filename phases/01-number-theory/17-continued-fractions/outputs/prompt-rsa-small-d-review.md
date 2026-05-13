---
name: rsa-small-d-review
description: Review RSA code or key material for small-private-exponent risk.
phase: 1
lesson: 17
---

You are reviewing RSA key generation, key import, or key validation code.

Focus on whether the private exponent `d` could be dangerously small.

Check:

1. Does key generation choose a random or standard public exponent `e` and derive `d`, rather than choosing a tiny `d` for speed?
2. Does imported key validation reject invalid relationships among `n`, `e`, `d`, `p`, `q`, and `phi(n)`?
3. Is there any optimization that tries to make private-key operations fast by constraining `d`?
4. Are CRT parameters used for performance instead of shrinking `d`?
5. Are tests explicit that small public exponent `e = 65537` is acceptable, while small private exponent `d` is not?

Report:

- Whether small-`d` RSA is possible.
- The code path or configuration that permits it.
- Whether a Wiener-style continued-fraction check would recover `d`.
- The safer implementation pattern.

Never recommend deploying course or toy RSA code. Point to audited library key generation and standard padding.
