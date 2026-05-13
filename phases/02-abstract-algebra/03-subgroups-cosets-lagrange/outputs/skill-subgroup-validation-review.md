---
name: skill-subgroup-validation-review
description: Checklist for reviewing subgroup, coset, cofactor, and Lagrange assumptions in cryptographic constructions
version: 1.0.0
phase: 2
lesson: 3
tags: [subgroups, cosets, lagrange, cofactors, validation]
---

# Subgroup Validation Review

Use this checklist whenever a primitive or protocol receives a group element from outside its trust boundary.

## Identify the Intended Subgroup

Record the exact group and subgroup.

```text
Full group:          G
Full group order:    |G|
Intended subgroup:   H
Subgroup order:      |H|
Index / cofactor:    [G : H] = |G| / |H|
Generator:           g
Generator order:     ord(g)
```

If `|H|` or `ord(g)` is unknown, do not make security claims about exponents in that subgroup.

## Check Lagrange Assumptions

| Question | Why it matters |
|----------|----------------|
| Does `|H|` divide `|G|`? | A valid finite subgroup must satisfy Lagrange's theorem |
| Is the index small? | Small cofactors need explicit handling |
| Does the generator have order `|H|`? | Otherwise secrets may live in a smaller cycle |
| Is the identity accepted? | Identity inputs often create degenerate shared secrets or proofs |
| Are public elements checked? | Attackers can choose small-subgroup or invalid elements |

## Review Public Element Handling

For every decoded public group element, answer:

```text
Is the encoding canonical?
Is the element on the curve / in the field / in the group?
Is the element in the intended subgroup?
Is the identity allowed by this protocol?
Is cofactor clearing required before secret-dependent operations?
```

The check belongs at the boundary where untrusted bytes become a group element.

## Common Failure Modes

| Mistake | Consequence |
|---------|-------------|
| Only checking that an element is not zero | Small-subgroup elements may still pass |
| Confusing group membership with subgroup membership | Valid elements can live outside the intended prime-order subgroup |
| Ignoring the cofactor | Secret operations may leak modulo small factors |
| Accepting the identity as a public key | Shared secrets or commitments can become fixed values |
| Assuming a named curve removes validation needs | Some curves and encodings still require subgroup or cofactor handling |

## Safe Engineering Habit

Use audited libraries that expose subgroup-safe types and validation APIs. From-scratch coset and Lagrange code is for understanding the failure mode, not for production validation.
