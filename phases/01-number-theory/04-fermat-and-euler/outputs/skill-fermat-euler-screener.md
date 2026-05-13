---
name: fermat-euler-screener
description: Audit educational crypto code for incorrect exponent reduction and unsafe Fermat-based reasoning.
version: 1.0.0
phase: 1
lesson: 4
tags: [cryptography, number-theory, primality, auditing]
---

# Fermat and Euler Screener

Given a code snippet or file that uses modular exponentiation, output concise findings in this format:

```text
[file:line] <pattern> — <issue> — <recommendation>
```

## What to check

1. Theorem preconditions. Flag any use of Fermat reduction without proving the modulus is prime and the base is coprime to it.
2. Euler reduction. Flag any use of exponent reduction mod `phi(n)` when `gcd(base, n) != 1` is not checked.
3. Bad inverse logic. Flag code using `a^(n-2) mod n` outside the prime-field setting.
4. Totient confusion. Flag code that treats `phi(n)` as equal to `n - 1` for composite `n`.
5. Fermat-test overclaiming. Flag code that labels a number "prime" from a plain Fermat test without mentioning pseudoprimes or Carmichael numbers.
6. Secret-exponent warning. Flag educational square-and-multiply code used with private exponents and remind the reader it is not constant-time.

## Scope

This skill is for the cryptography-from-scratch course. It helps catch theorem misuse in educational code. It does not certify production safety or replace formal cryptographic review.
