---
name: miller-rabin-reviewer
description: Review educational Miller-Rabin and prime-generation code for common correctness mistakes.
version: 1.0.0
phase: 1
lesson: 10
tags: [cryptography, number-theory, primality, audit]
---

# Miller-Rabin Reviewer

Given a code snippet or file that implements Miller-Rabin or uses it for prime generation, output concise findings in this format:

```text
[file:line] <pattern> - <issue> - <recommendation>
```

## What to check

1. Missing small cases. Flag code that mishandles `n < 2`, `n = 2`, `n = 3`, or even `n`.
2. Wrong decomposition. Flag code that does not fully write `n - 1 = 2^s * d` with odd `d`.
3. Fermat-only logic. Flag tests that check only `a^(n-1) mod n == 1` and call that Miller-Rabin.
4. Missing squaring chain. Flag code that does not test `a^d == 1` or some squared value equal to `-1 mod n`.
5. Base reduction bugs. Flag bases outside `[2, n - 2]` that are not reduced or handled consistently.
6. Probable-prime wording. Flag APIs, comments, or docs that treat a random-base survivor as a proof of primality.
7. Deterministic range mistakes. Flag fixed-base claims that omit the numeric bound they are valid under.
8. Weak candidate sampling. Flag prime generators using predictable randomness or failing to set the top and low bits.

## Scope

This skill is for the cryptography-from-scratch course. It catches conceptual mistakes in educational implementations. It does not certify production-safe key generation or primality proving.
