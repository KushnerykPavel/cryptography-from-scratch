---
name: skill-legendre-jacobi-auditor
description: Review code that uses Legendre or Jacobi symbols for quadratic-residue decisions.
version: 1.0.0
phase: 1
lesson: 8
tags: [legendre-symbol, jacobi-symbol, quadratic-residues, primality-testing]
---

# Legendre/Jacobi Auditor

Use this checklist when code claims to test whether a value is a quadratic residue.

## Prime modulus checks

1. Confirm the modulus is an odd prime before using the Legendre symbol.
2. Reduce `a` modulo `p` before exponentiation.
3. Interpret `p - 1` from Euler's criterion as `-1`, not as the integer `p - 1`.
4. Treat `0` separately: `(a/p) = 0` means `p` divides `a`.

## Composite modulus checks

1. Confirm Jacobi is only called with positive odd `n`.
2. Remember that Jacobi `-1` proves non-residue, but Jacobi `+1` is inconclusive.
3. Look for code that accepts Jacobi `+1` as proof of squarehood. That is usually a bug.
4. For small educational moduli, cross-check with direct square enumeration or factorization.

## Solovay-Strassen checks

1. Reject even `n` before choosing bases.
2. If `gcd(a, n) > 1`, the base has already found compositeness.
3. Compare `a^((n - 1) / 2) mod n` with `jacobi(a, n) mod n`.
4. Treat a passing base as probabilistic evidence only; one base can miss a composite.

## Security warning

For RSA-style `n = p*q`, distinguishing true quadratic residues from Jacobi `+1` non-residues is the Quadratic Residuosity Problem. Do not replace a real protocol's residue proof with a Jacobi-symbol check.
