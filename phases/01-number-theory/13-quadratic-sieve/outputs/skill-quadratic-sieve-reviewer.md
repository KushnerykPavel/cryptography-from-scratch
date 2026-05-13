---
name: skill-quadratic-sieve-reviewer
description: Review educational Quadratic Sieve implementations for conceptual and safety mistakes.
version: 1.0.0
phase: 1
lesson: 13
tags: [crypto, number-theory, factoring, quadratic-sieve]
---

# Quadratic Sieve Reviewer

Use this checklist when reviewing toy QS code for a cryptography lesson.

## Scope

This skill is for educational implementations only. Flag any wording that suggests the code is constant-time, side-channel-safe, or suitable for production RSA key assessment.

## Checklist

1. Verify the goal is a square congruence: `x^2 ≡ y^2 (mod n)`, followed by `gcd(x - y, n)` and `gcd(x + y, n)`.
2. Check that the factor base uses small primes where `n` is a quadratic residue modulo `p`. Including every prime wastes work and confuses the sieve model.
3. Ensure smoothness is exact. A relation with leftover factor greater than `1` is not a full relation unless the implementation explicitly supports a large-prime variant.
4. Confirm exponent vectors are reduced modulo `2`, not modulo `n`, not modulo `p`, and not stored as raw exponent sums for linear algebra.
5. Reject trivial dependencies where both gcds return `1` or `n`; a failed dependency is not proof that `n` is prime.
6. Look for enough relations. A run usually needs more smooth relations than factor-base primes, plus retries when dependencies are trivial.
7. Check validation for `n <= 1`, even `n`, square `n`, too-small bounds, and non-positive intervals.
8. Keep claims modest: toy QS explains the method; real factoring tools use MPQS/SIQS, sparse matrix solvers, ECM pre-processing, and NFS escalation.

## Good Review Language

- "This relation is not smooth over the base because a leftover factor remains."
- "This dependency produces a trivial square congruence; try another dependency."
- "The implementation teaches QS, but it should not be described as RSA-safe tooling."
