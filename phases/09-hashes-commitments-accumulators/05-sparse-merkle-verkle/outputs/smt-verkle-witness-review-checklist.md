---
name: SMT/Verkle Witness Review Checklist
description: A practical checklist for reviewing Sparse Merkle / Verkle-style witness (proof) code in PRs.
phase: 09-hashes-commitments-accumulators
lesson: 05-sparse-merkle-verkle
---

# SMT/Verkle Witness Review Checklist

Use this in PR review when someone changes:
- hashing / node encoding
- proof formats (ordering, directions)
- default/empty-node handling
- key-to-path derivation
- witness verification logic

## 1) Commitment definition (root meaning)

- Root is defined over a fixed key space (e.g., 2^256 leaves for SMT, width=256 and depth=32 for Verkle) and does not depend on insertion order.
- Empty tree root is specified and consistent across implementations (explicitly computed from default empties).
- Node hashing/commitment uses domain separation between leaves and internal nodes (different prefixes / tags).
- Serialization is unambiguous (length-prefix or fixed-width encoding; no silent concatenation ambiguity).

## 2) Key → path derivation

- Key hashing is explicit: `path = H(key)` (or `H(stem)`/`H(key)`), not the raw key bytes unless spec says so.
- Bit/byte order is pinned down (MSB-first vs LSB-first; big-endian vs little-endian).
- Path length is fixed and validated (reject wrong-length inputs early).
- For Verkle-style tries: stem/suffix split is specified (e.g., 31-byte stem + 1-byte suffix in Ethereum-style designs).

## 3) Proof format invariants (SMT)

- Proof includes enough information to reconstruct the root (sibling list length equals the tree depth).
- Sibling order is documented and consistent (leaf→root, and which side the sibling corresponds to).
- Verification recomputes the leaf hash from the *claimed* value (not trusting a pre-hashed leaf from the prover unless explicitly part of the format).
- Non-inclusion is handled as “the leaf at that index is empty” (default leaf hash), not as a special-case boolean.

## 4) Proof format invariants (Verkle-style)

- Each level provides an opening proof that binds (index, child_value) to the parent commitment.
- The opened child value is exactly what the next level commits to (commitments chain correctly).
- Proof rejects:
  - wrong index
  - wrong child value
  - wrong commitment (root mismatch)
  - truncated/extra levels

## 5) Default/empty handling

- Empty leaves share a single canonical value (e.g., `H("")` or `0x00…00`), not key-dependent empties.
- Pruning is safe: removing a node is equivalent to replacing it with the correct default at that level.
- Deletion semantics are defined: “absent” vs “present with empty payload” are not conflated unless the protocol explicitly allows it.

## 6) Security/robustness checks

- Domain separation prevents “internal node hash reused as leaf” attacks.
- Verification is constant work for a fixed depth (no quadratic behavior from recomputing too much).
- Input validation rejects malformed proofs before expensive operations.
- Tests cover:
  - inclusion and non-inclusion
  - delete → returns to previous root
  - wrong sibling order / wrong index bit
  - tampered one-byte in the proof

## 7) Performance footguns (practical)

- SMT: avoid materializing the full 2^depth tree; store only non-default nodes + precomputed defaults.
- Verkle-style: avoid rebuilding full vectors per node when only one child changed (batching / caching if applicable).
- Witness size is measured and asserted in tests (regression guard).

