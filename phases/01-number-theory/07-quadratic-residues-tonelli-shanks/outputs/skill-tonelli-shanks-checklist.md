---
name: skill-tonelli-shanks-checklist
description: Checklist for deciding when modular square roots are valid and when they become a factoring hazard.
version: 1.0.0
phase: 1
lesson: 7
tags: [quadratic-residues, tonelli-shanks, modular-square-roots, rsa]
---

# Tonelli-Shanks Checklist

Use this checklist when code claims it can compute a modular square root.

## Prime-field preconditions

1. Confirm the modulus is an odd prime.
2. Reduce `a` modulo `p` before testing anything.
3. Check Euler's criterion: `a^((p - 1) / 2) mod p` must be `1` for non-zero inputs.
4. Handle `a = 0` as a special case.

## Fast path

If `p % 4 == 3`, use:

```text
sqrt(a) mod p = a^((p + 1) / 4) mod p
```

If not, switch to Tonelli-Shanks instead of inventing an ad hoc search loop.

## Tonelli-Shanks structure

1. Factor `p - 1 = q * 2^s` with `q` odd.
2. Find a quadratic non-residue `z`.
3. Initialize `c = z^q`, `t = a^q`, `r = a^((q + 1) / 2)`.
4. Iterate until `t = 1`.

## Security warning

Square roots modulo a composite `n = p*q` are different. If code can produce two distinct non-opposite roots of the same value modulo `n`, then `gcd(r - s, n)` reveals a factor. Treat composite-modulus root oracles as factoring-sensitive.
