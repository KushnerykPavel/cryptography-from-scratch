---
name: skill-generator-subgroup-auditor
description: Checklist for reviewing generator, subgroup, and small-order assumptions in cryptographic protocols
version: 1.0.0
phase: 2
lesson: 2
tags: [cyclic-groups, generators, subgroups, discrete-log, validation]
---

# Generator and Subgroup Auditor

Use this checklist whenever a construction publishes a group element as a base, generator, or public key.

## Identify the Cycle

Record the exact group and generated subgroup.

```text
Group:             G
Operation:         multiplication / addition / point addition
Identity:          e
Candidate base:    g
Group order:       |G|
Generator order:   ord(g)
Generated subgroup: <g>
```

If `ord(g)` is not known, do not treat `g` as a safe generator.

## Check Generator Claims

| Claim | Question |
|-------|----------|
| Full generator | Does `<g>` equal the whole group? |
| Subgroup generator | Does `<g>` equal the intended subgroup? |
| Prime order | Is `ord(g)` the expected large prime? |
| Cofactor | Is the cofactor handled by validation or clearing? |
| Identity | Is the identity rejected when the protocol requires a non-identity element? |

Most protocols need a generator of a specific large subgroup, not merely any non-identity element.

## Review Public Inputs

For every external group element, ask:

```text
Is it encoded canonically?
Is it a valid group element?
Is it in the correct subgroup?
Can it be the identity?
Can it have small order?
```

Unchecked public keys are where small-subgroup and invalid-element attacks enter.

## Common Failure Modes

| Mistake | Consequence |
|---------|-------------|
| Confusing non-identity with generator | Public keys may live in tiny cycles |
| Using a generator with small order | Secret exponents leak modulo that order |
| Ignoring subgroup membership | Attackers can choose malicious public elements |
| Accepting identity public keys | Shared secrets or proofs become degenerate |
| Forgetting cofactors on curves | Small-subgroup components survive into secret-dependent operations |

## Safe Engineering Habit

Use audited parameter sets and library types that validate membership. From-scratch generator search is useful for tiny examples, not for choosing production cryptographic groups.
