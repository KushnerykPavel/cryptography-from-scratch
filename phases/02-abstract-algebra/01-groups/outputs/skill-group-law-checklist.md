---
name: skill-group-law-checklist
description: Checklist for verifying that a cryptographic construction is really using the intended group
version: 1.0.0
phase: 2
lesson: 1
tags: [groups, algebra, subgroup, validation, cryptography]
---

# Group Law Checklist

Use this checklist whenever a proof, primitive, or protocol says "let G be a group."

## Identify the Algebra

Name the exact set and operation.

```text
Set:        valid elements of G
Operation: how two elements combine
Identity:  the do-nothing element
Order:     number of elements in G
```

If any of these are vague, stop and make them explicit.

## Check the Four Rules

| Rule | Question |
|------|----------|
| Closure | Does combining two valid elements always return a valid element? |
| Associativity | Can repeated operations be regrouped without changing the result? |
| Identity | Is there a unique do-nothing element for both sides? |
| Inverses | Can every valid element be undone inside the same set? |

For tiny examples, build a Cayley table. For real crypto, rely on the proof and the library's validated element type.

## Check Order Assumptions

Record both the group order and the relevant element or subgroup order.

```text
Group order:      |G|
Generator order:  ord(g)
Expected subgroup: prime order / cofactor-cleared / full group
```

Small-order elements are often attack inputs, not harmless edge cases.

## Common Failure Modes

| Mistake | Consequence |
|---------|-------------|
| Using all residues mod n for multiplication | Non-units have no inverse |
| Accepting unchecked public group elements | Invalid-element or small-subgroup attacks |
| Confusing group order with element order | Wrong security estimate |
| Allowing the identity as a public key when forbidden | Trivial shared secret or degenerate proof |
| Ignoring cofactors | Secret leakage through small subgroups |

## Safe Engineering Habit

Prefer libraries that encode group membership in types, validate external inputs, and expose subgroup-safe operations.

From-scratch group code is for learning and tests, not deployment.
