---
name: skill-ntt-review
description: Review an NTT (and inverse/negacyclic) implementation for correctness and parameter safety.
version: 1.0.0
phase: 02
lesson: 12
tags: [cryptography, ntt, fft, finite-fields, polynomial-multiplication, review]
---

# NTT Review

Use this when you see NTT-based polynomial multiplication in lattice cryptography, ZK tooling, or general modular arithmetic code.

## Checklist

1. Verify the parameter condition.
   - Confirm `n | (p - 1)` before selecting `ω`.
   - If the algorithm assumes `n` is a power of two (Cooley–Tukey), confirm `n` is a power of two.

2. Verify `ω` is primitive.
   - Check `ω^n ≡ 1 (mod p)`.
   - For every prime factor `q` of `n`, check `ω^(n/q) ≠ 1 (mod p)`.
   - Red flag: `ω` is an `n`-th root but not primitive (transform becomes non-invertible).

3. Verify twiddle exponents per stage.
   - In a `len` stage, the per-stage base should be `wlen = ω^(n/len)`.
   - Twiddle progression inside each butterfly block should multiply by `wlen` each step.

4. Verify the inverse transform.
   - Inverse uses `ω_inv = ω^(-1) mod p`, not `ω`.
   - Inverse scales every output by `n_inv = n^(-1) mod p`.
   - Quick property: `iNTT(NTT(a)) == a` for multiple random inputs.

5. Verify modular normalization.
   - Ensure subtractions are reduced mod `p` (no negative residues leaking into later multiplies).

6. Verify the polynomial ring.
   - Cyclic multiplication targets `F_p[x]/(x^n - 1)`.
   - Negacyclic multiplication targets `F_p[x]/(x^n + 1)` and typically needs a primitive `2n`-th root `ψ` with `ω = ψ^2`.
   - For negacyclic, verify a twist / untwist by powers of `ψ` is present and consistent.

## Common Findings

| Finding | What it breaks |
|---------|----------------|
| `n` does not divide `p-1` | No primitive `n`-th root exists; transform definition cannot be invertible |
| `ω` has order `n/2` | Collisions in the “NTT”; inverse fails; multiplication results wrong |
| Used `ω` in inverse | Outputs are scrambled (wrong twiddles) |
| Forgot `n_inv` scaling | Inverse outputs are off by a factor of `n` |
| Negacyclic used only an `n`-th root | Multiplication is for `(x^n - 1)`, not `(x^n + 1)` |

## Review Prompt

Review this NTT implementation. Identify `p`, `n`, `ω` (and `ψ` if negacyclic). Verify that `n | (p-1)` and that `ω` is a primitive `n`-th root. Confirm each stage uses `wlen = ω^(n/len)`. Confirm the inverse uses `ω^(-1)` and scales by `n^(-1)`. If negacyclic multiplication is intended, confirm it uses a primitive `2n`-th root `ψ` with a twist/untwist by powers of `ψ`.

