---
name: Poseidon Integration Checklist
description: PR-review checklist for using Poseidon safely and compatibly across circuits, contracts, and backends.
phase: 09-hashes-commitments-accumulators
lesson: 07-poseidon
---

# Poseidon Integration Checklist

Use this when reviewing or implementing Poseidon in:

- SNARK circuits (Circom, Noir, halo2, arkworks)
- Smart contracts verifying roots/commitments
- Off-chain services computing the same hashes as the circuit

## 1) Instance agreement (the #1 source of “hash mismatch” bugs)

Confirm every component uses the exact same Poseidon instance:

- Field modulus `p` (e.g., BN254 scalar field)
- State width `t` and rate/capacity split (usually `capacity = 1`, `rate = t - 1`)
- S-box exponent `alpha` (often `5` for BN254)
- Round numbers (`full_rounds`, `partial_rounds`)
- Round constants and MDS matrix (or sparse matrices), including how they were generated

If any of these differ, the outputs differ. “Poseidon” is a family name, not a single function.

## 2) Input encoding rules (treat this as part of the hash definition)

Write down and test the exact input rules:

- Are inputs **field elements** already, or are bytes mapped to field elements?
- If mapping bytes → field, what are the chunk size and endianness?
- Are inputs reduced mod `p` at the boundary (and is this consistent everywhere)?
- Which state element is output (e.g., first rate element)?

## 3) Variable length: padding and length separation

If the API accepts variable-length input, ensure **injective** handling:

- Length is encoded into the initial state (IV), or a safe padding rule is used, or both.
- Trailing zeros do **not** create collisions (`hash([x])` must differ from `hash([x, 0])`).

If you do not need variable length, prefer a fixed-arity hash and enforce `len(inputs) == rate`.

## 4) Domain separation (never reuse the same hash domain for different objects)

Define explicit domains and use them consistently, for example:

- `domain = 0`: leaves
- `domain = 1`: internal Merkle nodes
- `domain = 2`: nullifiers
- `domain = 3`: commitments

Document it and add tests that demonstrate the same input under different domains produces different outputs.

## 5) Circuit / backend interoperability tests

Add “golden vectors” that are tested in every environment:

- Circuit test vectors (witness generation)
- Backend test vectors (Python/Rust/TS)
- Contract test vectors (if a contract checks roots/commitments)

Checklist for the vectors themselves:

- Cover typical values and edge cases (`0`, `1`, `p-1`)
- Cover the exact arities used in the protocol
- Cover domain-separated variants
- Cover the variable-length padding/length cases if supported

## 6) Performance and denial-of-service

- Ensure the number of absorbed elements is bounded.
- If the hash is computed on-chain or in a verifier, define maximum input length.

## 7) Safe usage notes

- Do not treat educational implementations as production-ready.
- Prefer audited libraries and well-known parameter sets.
- When in doubt, pin a specific library/version and treat the hash definition as “code + parameters + encoding”.

