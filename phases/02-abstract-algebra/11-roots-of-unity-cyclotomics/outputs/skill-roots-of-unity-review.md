---
name: skill-roots-of-unity-review
description: Review NTT parameters and roots-of-unity usage in cryptographic code.
version: 1.0.0
phase: 02
lesson: 11
tags: [cryptography, ntt, finite-fields, algebra, review]
---

# Roots of Unity Review

Use this when code performs an NTT, selects field parameters for lattice schemes, or constructs polynomial rings of the form `Z_p[x]/(x^n - 1)` or `Z_p[x]/(x^n + 1)`.

## Checklist

1. Verify the divisibility condition.
   - Confirm `n | (p - 1)` before any NTT or roots-of-unity computation.
   - If `n` does not divide `p - 1`, there are only `gcd(n, p-1)` roots instead of `n` and the transform is invalid.

2. Verify the primitive root selection.
   - Confirm `ω` has multiplicative order exactly `n`, not a proper divisor.
   - The canonical method is `ω = g^((p-1)/n)` where `g` is a primitive root mod `p`.
   - Test: `ω^n = 1` and `ω^(n/q) ≠ 1` for every prime factor `q` of `n`.

3. Check the inverse transform twiddle factor.
   - The inverse NTT uses `ω^(-1) mod p`, not `ω`.
   - Confirm `ω * ω_inv ≡ 1 (mod p)`.

4. Verify the scaling factor.
   - The inverse NTT divides by `n`. Confirm `n` is invertible in `F_p` (always true when `p` is prime and `p ≠ n`).
   - The scale factor is `n^(-1) mod p = pow(n, p-2, p)`.

5. Check the cyclotomic context if present.
   - If the ring is `Z_p[x]/(x^n + 1)`, confirm `n` is a power of 2 and `2n | (p - 1)` (need a primitive `2n`-th root).
   - The NTT-friendly ring for lattice schemes (`x^n + 1`) uses `x^n + 1 = Φ_{2n}(x)` when `n` is a power of 2.

6. Confirm parameter provenance.
   - Prefer published NTT primes (e.g., `p = 998244353 = 119 * 2^23 + 1` for `n` up to `2^23`).
   - If generating parameters, document the prime and verify `n | (p - 1)` in the test suite.

## Common Findings

| Finding | Why it matters |
|---------|----------------|
| `n` does not divide `p-1` | Fewer than `n` roots exist; twiddle factors repeat; transform matrix is singular |
| `ω` has order `n/2` not `n` | Used `g^(2(p-1)/n)` instead of `g^((p-1)/n)`; every other butterfly is wrong |
| Inverse uses `ω` instead of `ω^(-1)` | Transform is its own inverse only when `ω = ω^(-1)`, i.e., `ω^2 = 1`; general case is wrong |
| Forgot to scale by `n^(-1)` | Forward NTT composes correctly but inverse output is off by factor `n` |
| `x^n + 1` ring needs `2n \| (p-1)` | Primitive `2n`-th root needed, not `n`-th; using `n`-th root gives wrong negacyclic twiddles |
| Integer `p` without primality check | Modular inversion undefined; silent wrong results if `p` is composite |

## Review Prompt

Review this NTT or roots-of-unity code. Identify the prime `p`, the transform length `n`, the twiddle factor `ω`, and any inverse or scaling steps. Verify that `n | (p-1)`, that `ω` has order exactly `n`, that the inverse uses `ω^(-1)`, and that the output is scaled by `n^(-1)`. If the ring is `Z_p[x]/(x^n + 1)`, check whether `2n | (p-1)`. Report any parameter that is not verified in the code or test suite.
