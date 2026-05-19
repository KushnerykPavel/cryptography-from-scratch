# Merkle Trees from Scratch
> One root hash commits to a whole dataset; `O(log n)` hashes prove one item.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 07 · 09 (SHA-256), Phase 09 · 01 (Hash-Based Commitments)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain what a Merkle root commits to (and what it doesn’t).
- Compute a Merkle root from leaf values using a deterministic tree shape.
- Implement inclusion proof creation and verification.
- Distinguish leaf hashing from internal-node hashing (domain separation).
- Apply Merkle proofs to integrity-check a large dataset with small receipts.

## The Problem

You want to publish a *small* commitment to a *large* dataset: a block’s list of
transactions, a list of users eligible for an airdrop, a software release’s file
manifest, or an append-only transparency log. Later, someone should be able to
verify that a specific item was included — without downloading the full dataset.

Without Merkle trees you’re forced into bad choices: either publish the entire
dataset to let others recompute a hash (expensive), or rely on a trusted party
to answer “is item X included?” (fragile). Merkle trees give you a commitment
that’s one hash long, plus a short *receipt* that proves inclusion.

This “commit once, prove many” pattern shows up in blockchains, transparency
logs, backup verification, package registries, and any system where bandwidth
is limited but integrity matters.

## The Concept

A Merkle tree is a binary hash tree:

- **Leaf hash:** hash each data item (with a leaf prefix).
- **Node hash:** hash a pair of child hashes (with a node prefix).
- **Root hash:** the single hash at the top commits to *all* leaves.

We’ll use SHA-256 and domain separation prefixes:

```
LeafHash(x)      = SHA256(0x00 || encode(x))
NodeHash(L, R)   = SHA256(0x01 || L || R)
MerkleRoot(xs)   = fold(NodeHash, LeafHash(xs))
```

Two practical details matter in real systems:

1. **Unambiguous leaf encoding:** if a leaf value is “some bytes”, we encode it
   as `u32be(len(x)) || x` so boundaries are explicit.
2. **Tree shape for odd counts:** when a level has an odd number of nodes, we
   duplicate the last one so every node has a pair. (This is a convention; other
   systems use different rules.)

An **inclusion proof** for leaf `xs[i]` is the list of sibling hashes you need
to recompute the root. Verification is: start from the leaf hash and hash upward
with the siblings in the provided order.

## Build It

### Step 1: Hash leaves and nodes (domain separation)
```python
from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Iterable, Sequence


LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _u32be(n: int) -> bytes:
    if not isinstance(n, int):
        raise TypeError("n must be int")
    if n < 0 or n > 0xFFFFFFFF:
        raise ValueError("n out of range for u32")
    return struct.pack(">I", n)


def sha256(data: bytes) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    return hashlib.sha256(bytes(data)).digest()


def sha256_hex(data: bytes) -> str:
    return sha256(data).hex()


def encode_leaf_value(*, value: bytes) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("value must be bytes-like")
    v = bytes(value)
    return _u32be(len(v)) + v


def hash_leaf(*, value: bytes) -> bytes:
    return sha256(LEAF_PREFIX + encode_leaf_value(value=value))


def hash_node(*, left: bytes, right: bytes) -> bytes:
    if not isinstance(left, (bytes, bytearray, memoryview)):
        raise TypeError("left must be bytes-like")
    if not isinstance(right, (bytes, bytearray, memoryview)):
        raise TypeError("right must be bytes-like")
    return sha256(NODE_PREFIX + bytes(left) + bytes(right))
```

This fixes two common Merkle pitfalls up front: (1) leaf data is encoded
unambiguously, and (2) leaf hashes and internal-node hashes can’t be confused
because they use different prefixes.

### Step 2: Build the tree and compute the root
```python
def build_merkle_levels(*, leaves: Sequence[bytes]) -> list[list[bytes]]:
    if not isinstance(leaves, Sequence):
        raise TypeError("leaves must be a sequence")
    if len(leaves) == 0:
        raise ValueError("leaves must be non-empty")

    level0 = [hash_leaf(value=v) for v in leaves]
    levels: list[list[bytes]] = [level0]

    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt: list[bytes] = []
        i = 0
        while i < len(cur):
            left = cur[i]
            if i + 1 < len(cur):
                right = cur[i + 1]
            else:
                right = cur[i]
            nxt.append(hash_node(left=left, right=right))
            i += 2
        levels.append(nxt)

    return levels


def merkle_root(*, leaves: Sequence[bytes]) -> bytes:
    return build_merkle_levels(leaves=leaves)[-1][0]


def merkle_root_hex(*, leaves: Sequence[bytes]) -> str:
    return merkle_root(leaves=leaves).hex()
```

`build_merkle_levels` returns the full tree (level by level) so you can later
produce proofs. The “duplicate-last” rule makes the root deterministic even when
the number of leaves isn’t a power of two.

### Step 3: Create an inclusion proof
```python
def merkle_proof(*, leaves: Sequence[bytes], index: int) -> list[tuple[str, bytes]]:
    if not isinstance(index, int):
        raise TypeError("index must be int")
    if index < 0:
        raise ValueError("index must be non-negative")
    if index >= len(leaves):
        raise ValueError("index out of range")

    levels = build_merkle_levels(leaves=leaves)
    proof: list[tuple[str, bytes]] = []
    idx = index

    for level in levels[:-1]:
        if idx % 2 == 0:
            sib_idx = idx + 1
            if sib_idx >= len(level):
                sibling = level[idx]
            else:
                sibling = level[sib_idx]
            proof.append(("right", sibling))
        else:
            sibling = level[idx - 1]
            proof.append(("left", sibling))
        idx //= 2

    return proof
```

The proof is a list of `(side, sibling_hash)` pairs. `side` says whether the
sibling goes on your left or right when hashing upward. Verification doesn’t
need the full tree — only these siblings.

### Step 4: Verify an inclusion proof
```python
def verify_merkle_proof(
    *,
    leaf_value: bytes,
    proof: Sequence[tuple[str, bytes]],
    root: bytes,
) -> bool:
    if not isinstance(proof, Sequence):
        raise TypeError("proof must be a sequence")
    if not isinstance(root, (bytes, bytearray, memoryview)):
        raise TypeError("root must be bytes-like")

    cur = hash_leaf(value=leaf_value)
    for side, sibling in proof:
        if side not in ("left", "right"):
            raise ValueError("proof side must be 'left' or 'right'")
        if not isinstance(sibling, (bytes, bytearray, memoryview)):
            raise TypeError("proof sibling must be bytes-like")
        sib = bytes(sibling)
        if side == "left":
            cur = hash_node(left=sib, right=cur)
        else:
            cur = hash_node(left=cur, right=sib)

    return hmac.compare_digest(cur, bytes(root))
```

Verification recomputes the root from the claimed leaf value and the proof.
If any sibling hash is wrong, or if the leaf value is different, the final hash
won’t match the known root.

Run it:
python3 code/main.py

## Use It

Merkle trees show up in many production systems (the details vary, but the idea
is the same):

- **Blockchains:** commit to all transactions in a block; SPV/light clients use proofs.
- **Transparency logs:** append-only logs publish a root; clients verify inclusion receipts.
- **Data integrity:** publish a root for a dataset; later prove a record was included.

Implementation patterns you’ll see in real libraries:

- Different hash functions (SHA-256, SHA-3, BLAKE2/3) and different encodings.
- Different tree shapes: “duplicate-last”, “pad with zero”, or “left/right split”
  definitions (some are standardized, e.g., CT’s Merkle Tree Hash).
- Proof formats that include the leaf index, tree size, or additional consistency proofs.

## Pitfalls

1. **No domain separation:** if leaf and node hashing use the same rule, you can
   get “structural” confusions (treating an internal node hash as a leaf).
2. **Ambiguous leaf encoding:** committing to `(a, bc)` vs `(ab, c)` is a real bug
   if your leaf is built by concatenating fields without lengths.
3. **Mismatched odd-node rule:** root/proof verification fails if one side duplicates
   the last node but the other side uses a different convention.
4. **Forgetting order:** `NodeHash(L, R)` is not commutative; swapping siblings breaks proofs.
5. **Not binding to context:** if “what the leaves mean” changes (different dataset,
   different serialization), a root by itself is meaningless without context/versioning.

## Ship It

Save the checklist in `outputs/prompt-merkle-tree-review.md` and reuse it when you:

- review a PR that adds “Merkle proof” verification,
- design a “snapshot root” integrity scheme for a large dataset,
- integrate with a protocol that specifies a Merkle hashing convention.

Use it as a gate: are leaf encodings unambiguous, is the tree shape specified,
are proofs validated strictly, and is the root bound to a clear context?

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that the same root verifies the proof, but a tampered leaf or sibling hash fails verification.
2. Medium. Extend `code/main.py` with a `merkle_root_for_strings(values: list[str]) -> str` helper that UTF-8 encodes inputs, and add vectors/tests for it.
3. Hard. Integrate Merkle proofs into a “dataset snapshot” design: store a root plus `(index, proof)` receipts, and write a short verification function that rejects wrong proof lengths, invalid sides, and malformed hashes.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Merkle root | “A hash of the dataset” | A single digest that commits to all leaves *given a specific hashing + tree-shape rule*. |
| Leaf hash | “Hash the item” | `H(0x00 || encode(item))`: domain-separated hashing of raw data. |
| Node hash | “Hash the children” | `H(0x01 || left_hash || right_hash)`: order-sensitive parent hash. |
| Inclusion proof | “Merkle proof / receipt” | The sibling hashes needed to recompute the root from one leaf (`O(log n)` data). |
| Domain separation | “Use a prefix” | A context tag (like `0x00` vs `0x01`) that prevents cross-structure confusion. |

## Further Reading

- Ralph Merkle, *A Digital Signature Based on a Conventional Encryption Function* (1979) — the original “hash tree” idea.
- NIST, *FIPS 180-4: Secure Hash Standard (SHS)* (2015) — SHA-256 definition.
- RFC 9162, *Certificate Transparency Version 2.0* (2021) — standardized Merkle Tree Hashing and inclusion proofs.

