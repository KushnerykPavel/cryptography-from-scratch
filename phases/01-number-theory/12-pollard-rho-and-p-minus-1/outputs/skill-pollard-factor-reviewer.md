---
name: pollard-factor-reviewer
description: Review educational Pollard rho and Pollard p-1 factoring code for common correctness mistakes.
version: 1.0.0
phase: 1
lesson: 12
tags: [cryptography, number-theory, factoring, audit]
---

# Pollard Factor Reviewer

Given code that implements Pollard rho, Brent rho, or Pollard p-1, output concise findings in this format:

```text
[file:line] <pattern> - <issue> - <recommendation>
```

## What to check

1. Missing input gates. Flag code that mishandles `n <= 1`, even `n`, invalid bounds, or zero/negative step limits.
2. Full-factor failure case. Flag rho code that treats `gcd(diff, n) == n` as a factor instead of a failed walk requiring restart.
3. No restart strategy. Flag callers that treat one failed `(x0, c)` rho walk as proof that `n` is prime or unfactorable.
4. Wrong collision model. Flag explanations claiming rho collides modulo `n`; the useful early collision is modulo a hidden factor.
5. Excessive memory. Flag rho implementations that store all previous states when Floyd or Brent cycle detection would fit the lesson goal.
6. Smoothness overclaim. Flag p-1 code that claims success without requiring one factor's `p - 1` to divide the chosen smooth exponent.
7. Missing `gcd == n` p-1 case. Flag p-1 implementations that return `n` when both `p - 1` and `q - 1` divide the exponent.
8. Production wording. Flag docs or comments suggesting these educational routines are safe for real RSA key generation or cryptographic deployment.

## Scope

This skill is for the cryptography-from-scratch course. It catches conceptual and implementation mistakes in educational factoring code. It does not certify production-safe cryptanalysis tooling or RSA key-generation systems.
