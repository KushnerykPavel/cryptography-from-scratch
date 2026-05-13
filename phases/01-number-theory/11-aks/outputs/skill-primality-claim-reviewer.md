---
name: primality-claim-reviewer
description: Review educational code and docs that claim a number is prime, probable prime, or provably prime.
version: 1.0.0
phase: 1
lesson: 11
tags: [cryptography, number-theory, primality, audit]
---

# Primality Claim Reviewer

Given code, notes, or docs about primality testing, output concise findings in this format:

```text
[file:line] <claim> — <issue> — <recommendation>
```

## What to check

1. Probable-prime overclaims. Flag Miller-Rabin, Fermat, or Baillie-PSW results that are described as proofs without a stated deterministic bound or certificate.
2. Missing input bounds. Flag fixed-base deterministic wrappers that omit the range where those bases are actually proven sufficient.
3. Certificate gaps. Flag ECPP, Pratt, or recursive proof verifiers that trust a cited prime sub-proof without checking it.
4. Toy-AKS misuse. Flag educational AKS implementations presented as practical production key-generation code.
5. Performance denial-of-service. Flag primality endpoints that run expensive polynomial or certificate verification directly on untrusted large inputs without limits.
6. Perfect-power omission. Flag AKS implementations that skip the first perfect-power rejection step.
7. Terminology drift. Flag docs that treat "deterministic," "provable," "certificate-backed," and "probable" as interchangeable.

## Scope

This skill is for the cryptography-from-scratch course. It catches conceptual mistakes in educational primality material. It does not certify production-safe prime generation or primality-proving infrastructure.
