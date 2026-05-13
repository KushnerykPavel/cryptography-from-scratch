---
name: skill-crt-sanity-check
description: Checklist for deciding when CRT applies and how to use RSA-CRT safely
version: 1.0.0
phase: 1
lesson: 5
tags: [crt, number-theory, rsa, recombination, fault-attack]
---

# CRT Sanity Check

Use this checklist whenever you want to recombine congruences or speed up RSA with CRT.

## Applicability

CRT applies cleanly only when the moduli are pairwise coprime.

```text
For every i != j, check gcd(ni, nj) = 1.
If not, stop and switch to the generalized non-coprime case explicitly.
```

## Reconstruction

For a system `x ≡ ai (mod ni)`:

1. Compute `N = n1 * ... * nk`.
2. For each `i`, compute `Ni = N / ni`.
3. Compute `ui = Ni^(-1) mod ni`.
4. Recombine with `x = sum(ai * Ni * ui) mod N`.

If the full product is awkward or you want an implementation-friendly form, use Garner's algorithm instead.

## RSA-CRT Safety

If you use CRT in RSA signing or decryption:

1. Compute the `mod p` and `mod q` branches separately.
2. Recombine with CRT.
3. Verify the final result before releasing it.

Reason: a single fault in one branch can leak a prime factor through `gcd(bad_result^e - message, n)`.

## Common Failure Modes

| Mistake | Consequence |
|---------|-------------|
| Non-coprime moduli accepted silently | Wrong or inconsistent reconstruction |
| Inverse assumed instead of checked | Runtime failure or invalid algebra |
| Textbook RSA with small `e` and repeated message | Hastad broadcast attack |
| RSA-CRT without post-recombination verification | Bellcore fault attack |
