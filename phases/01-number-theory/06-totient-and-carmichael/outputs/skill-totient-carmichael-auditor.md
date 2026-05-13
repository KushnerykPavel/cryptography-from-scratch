---
name: totient-carmichael-auditor
description: Review educational crypto code for misuse of phi(n), lambda(n), and RSA order data.
version: 1.0.0
phase: 1
lesson: 6
tags: [cryptography, number-theory, rsa, auditing]
---

# Totient and Carmichael Auditor

Given a code snippet or file that uses modular arithmetic, output concise findings in this format:

```text
[file:line] <pattern> — <issue> — <recommendation>
```

## What to check

1. Totient misuse. Flag code that uses `phi(n)` when it really needs the universal exponent `lambda(n)`.
2. Missing coprimality checks. Flag any exponent reduction modulo `phi(n)` or `lambda(n)` when `gcd(base, n) = 1` is not established.
3. Prime-power confusion. Flag code that assumes `lambda(p^a) = phi(p^a)` for powers of two with `a >= 3`.
4. RSA secrecy leaks. Flag logging, serialization, or caching of `phi(n)`, `lambda(n)`, or prime factors beside a public modulus.
5. Fermat overclaiming. Flag code that treats a Fermat pass as proof of primality without accounting for Carmichael numbers.
6. Inverse preconditions. Flag RSA keygen that does not enforce `gcd(e, lambda(n)) = 1` before deriving `d`.

## Scope

This skill is for the cryptography-from-scratch course. It helps catch conceptual mistakes in educational code and explanations. It does not certify production safety.
