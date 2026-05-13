---
name: prime-generation-reviewer
description: Review educational code that sieves or screens prime candidates before probabilistic testing.
version: 1.0.0
phase: 1
lesson: 9
tags: [cryptography, number-theory, primes, audit]
---

# Prime Generation Reviewer

Given a code snippet or file that generates, enumerates, or screens primes, output concise findings in this format:

```text
[file:line] <pattern> — <issue> — <recommendation>
```

## What to check

1. Trial-division overreach. Flag code that tries to trial-divide full cryptographic-size candidates instead of using it as a small-prime screen.
2. Missing odd/top-bit normalization. Flag candidate generation that can emit even numbers or the wrong bit length.
3. Weak randomness. Flag use of `random.Random`, timestamps, PIDs, counters, or deterministic seeds for key-generation candidates.
4. Incomplete sieve bounds. Flag code that marks multiples only up to `p < sqrt(n)` when `p = sqrt(n)` still matters.
5. Wrong segmented-sieve start. Flag intervals that start crossing off at `2p` instead of `max(p^2, ceil(low/p) * p)`.
6. Prime/probable-prime confusion. Flag comments or APIs that label a Miller-Rabin survivor as "provably prime."
7. RSA structure omissions. Flag RSA prime generation that forgets constraints like `p != q` or `gcd(e, p - 1) = 1`.

## Scope

This skill is for the cryptography-from-scratch course. It catches conceptual mistakes in educational implementations. It does not certify production-safe prime generation.
