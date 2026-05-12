---
name: modular-arithmetic-checker
description: Audit Python code for unsafe modular arithmetic patterns
version: 1.0.0
phase: 1
lesson: 1
tags: [crypto, math, audit]
---

# Modular Arithmetic Checker

Audit Python code for unsafe modular arithmetic patterns common in handwritten crypto.

## Trigger

User pastes Python code or refers to a Python file using `%`, `pow(.,.,.)`, or implementing a primitive (RSA, DH, ECDSA, etc).

## What to flag

1. `a % b` where `b` could be negative or zero — flag and recommend explicit guard.
2. `pow(a, k)` where the result is then taken `% n` — flag, recommend `pow(a, k, n)` (faster, GMP-backed).
3. `pow(a, -1, n)` without checking `gcd(a, n) == 1` — flag, recommend explicit precondition.
4. Negative modulus or non-prime modulus passed to a function expecting field operations — flag.
5. `mod_pow` / `pow(.,.,.)` over a *secret* exponent without constant-time hint — flag with educational warning that Python is not constant-time.
6. Computing `(a * b) % n` where `a, b` are not reduced mod `n` first — usually fine in Python (arbitrary precision), but flag if the reader is porting to C/Rust.

## How to apply

For each match, output:

```
[file:line] <pattern> — <issue> — <recommendation>
```

Do not auto-fix. Surface the finding so the reader can confirm intent.

## Scope

This skill is educational — designed for the cryptography-from-scratch course. It does not replace formal code audits or constant-time analysis tools (e.g. ct-verif, ctgrind).
