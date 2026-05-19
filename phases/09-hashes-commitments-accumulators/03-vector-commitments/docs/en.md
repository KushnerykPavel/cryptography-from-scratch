# Vector Commitments

> Commit once to a whole list; later prove one entry in it.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 9, Lesson 01 (Hash-Based Commitments)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why a “vector commitment” is a commitment scheme plus per-index openings
- Compute a Merkle-style commitment root from an ordered list of bytes
- Implement `vector_commit`, `vector_open`, and `vector_verify` from scratch
- Distinguish index binding, length binding, and domain separation (and why each matters)
- Apply these ideas to design-review real systems (Merkle trees, tries, Verkle, KZG)

## The Problem

You have a list of values (balances, KYC claims, allowlist entries, configuration knobs, log entries). You want to publish a single “commitment” to the whole list today, and later answer queries like: “what was entry #i?” without revealing the entire list.

Without vector commitments, you end up either (a) sending the full list every time, (b) trusting a server to answer honestly, or (c) inventing an ad-hoc format that’s easy to malleate (“just hash the concatenation”) and later fails an audit.

Vector commitments are the backbone of “prove membership with a short proof” systems: Merkle trees in blockchains, authenticated data structures, transparency logs, and (in more advanced forms) Verkle trees and polynomial commitments.

## The Concept

A vector commitment (VC) is like a commitment scheme for an *ordered array*:

- `commit(v[0..n-1]) -> root`
- `open(v, i) -> (v[i], proof_i)`
- `verify(root, i, v_i, proof_i, n) -> bool`

For a VC to be useful, it should be:

- **Binding**: once you publish `root`, you can’t later “open” the same index `i` to two different values.
- **Succinct openings**: `proof_i` should be much smaller than sending the whole vector.
- **Index-aware**: “value `x` exists somewhere” is not enough; you must prove “at position `i` the value is `x`”.

The simplest VC is a **Merkle tree**:

- Each leaf is a hash of `(index, value)` (this binds the position).
- Each internal node hashes its two children.
- The commitment is the top hash (often also bound to the vector length `n`).
- An opening proof is the list of sibling hashes along the path (size `O(log n)`).

This lesson implements a Merkle-based VC using SHA-256 with:

- **Domain separation**: different prefixes for leaves, internal nodes, and the final root
- **Length binding**: `root = H("VC:root" || n || merkle_root)` so the same tree can’t be reused under a different `n`

## Build It

### Step 1: Domain-separated leaf hashing (bind index + value)

We hash each `(index, value)` into a 32-byte leaf hash. We include both the index and the value length to avoid ambiguity, and we prefix with a tag so leaf hashing can’t be confused with internal-node hashing.

```python
from __future__ import annotations

import hashlib
from typing import Sequence, Tuple


Hash32 = bytes
ProofStep = Tuple[str, Hash32]  # ("L" | "R", sibling_hash)


def sha256(data: bytes) -> Hash32:
    return hashlib.sha256(data).digest()


def u32be(n: int) -> bytes:
    if not (0 <= n < 2**32):
        raise ValueError("u32 out of range")
    return n.to_bytes(4, "big")


def _require_bytes_seq(values: Sequence[bytes]) -> None:
    for v in values:
        if not isinstance(v, (bytes, bytearray)):
            raise TypeError("values must be a sequence of bytes-like objects")


def leaf_hash(index: int, value: bytes) -> Hash32:
    if index < 0:
        raise ValueError("index must be non-negative")
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError("value must be bytes-like")
    v = bytes(value)
    payload = b"VC:leaf" + u32be(index) + u32be(len(v)) + v
    return sha256(payload)
```

This “index binding” matters: if you don’t include `index`, a prover could potentially reuse a proof from position `j` to claim the same value at position `i`.

### Step 2: Merkle tree building (hash pairs upward)

We combine leaf hashes into parent hashes until one root remains. If a level has an odd number of nodes, we duplicate the last node (and we’ll separately bind the overall length so this padding choice can’t be exploited).

```python
from typing import List


def node_hash(left: Hash32, right: Hash32) -> Hash32:
    if len(left) != 32 or len(right) != 32:
        raise ValueError("node children must be 32-byte hashes")
    return sha256(b"VC:node" + left + right)


def merkle_levels(leaf_hashes: Sequence[Hash32]) -> List[List[Hash32]]:
    if len(leaf_hashes) == 0:
        raise ValueError("cannot build Merkle tree for empty list")
    for h in leaf_hashes:
        if len(h) != 32:
            raise ValueError("leaf hashes must be 32 bytes")

    levels: List[List[Hash32]] = [list(leaf_hashes)]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt: List[Hash32] = []
        i = 0
        while i < len(cur):
            left = cur[i]
            right = cur[i + 1] if i + 1 < len(cur) else cur[i]
            nxt.append(node_hash(left, right))
            i += 2
        levels.append(nxt)
    return levels


def merkle_root(leaf_hashes: Sequence[Hash32]) -> Hash32:
    return merkle_levels(leaf_hashes)[-1][0]
```

### Step 3: Commit to the vector (length-bound root)

We turn the vector into leaf hashes, compute a Merkle root, then bind the length `n` into the final commitment. Length binding prevents “same tree, different meaning” bugs (especially when padding or truncation is possible).

```python
def vector_commit(values: Sequence[bytes]) -> Hash32:
    _require_bytes_seq(values)
    n = len(values)
    if n == 0:
        raise ValueError("cannot commit to empty vector")

    leaves = [leaf_hash(i, v) for i, v in enumerate(values)]
    root = merkle_root(leaves)
    return sha256(b"VC:root" + u32be(n) + root)
```

### Step 4: Open and verify one index

An opening proof is the sibling hash at each level on the path from leaf `i` to the root, plus whether the sibling was on the left or right. Verification re-hashes upward and checks that the computed commitment root matches.

```python
from typing import Iterable, Tuple


def vector_open(values: Sequence[bytes], index: int) -> Tuple[Hash32, List[ProofStep]]:
    _require_bytes_seq(values)
    n = len(values)
    if not (0 <= index < n):
        raise IndexError("index out of range")

    leaves = [leaf_hash(i, v) for i, v in enumerate(values)]
    levels = merkle_levels(leaves)

    proof: List[ProofStep] = []
    i = index
    for level in levels[:-1]:
        if i % 2 == 0:
            sib_index = i + 1
            sibling = level[sib_index] if sib_index < len(level) else level[i]
            proof.append(("R", sibling))
        else:
            sibling = level[i - 1]
            proof.append(("L", sibling))
        i //= 2

    root = sha256(b"VC:root" + u32be(n) + levels[-1][0])
    return root, proof


def vector_verify(root: Hash32, index: int, value: bytes, proof: Iterable[ProofStep], n: int) -> bool:
    if len(root) != 32:
        raise ValueError("root must be a 32-byte hash")
    if not (0 <= index < n):
        return False
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError("value must be bytes-like")

    acc = leaf_hash(index, bytes(value))
    i = index
    for side, sibling in proof:
        if side not in ("L", "R"):
            raise ValueError("proof side must be 'L' or 'R'")
        if len(sibling) != 32:
            raise ValueError("proof hash must be 32 bytes")

        if side == "L":
            acc = node_hash(sibling, acc)
        else:
            acc = node_hash(acc, sibling)
        i //= 2

    computed = sha256(b"VC:root" + u32be(n) + acc)
    return computed == root
```

Run it:
python3 code/main.py

## Use It

Vector commitments show up in multiple “production shapes”:

| Construction | What it gives you | Typical use |
|---|---|---|
| Merkle tree (hash VC) | `O(log n)` proofs, no trusted setup, simple | blockchains, transparency logs, authenticated data structures |
| KZG / polynomial commitment VC | constant-size proofs, fast batch openings, needs pairings + (often) trusted setup | Verkle trees, many ZK systems, data availability commitments |
| Verkle tree | trie-like key/value structure with KZG vector commitments at nodes | Ethereum research direction to shrink state proofs |

In real systems, you rarely build these primitives yourself. You pick a construction and use audited implementations (and standardized serialization formats).

## Pitfalls

- **No unambiguous encoding**: hashing `str(i) + value` is ambiguous (e.g., `("1","23")` vs `("12","3")`). Length-prefix or structured encoding fixes this.
- **No domain separation**: using the same hash format for leaves and internal nodes can create weird cross-level collisions in badly designed trees.
- **Not binding the index**: if leaf hashes don’t include `index`, a proof for “value `x` exists somewhere” can be misused as “value `x` at index `i`”.
- **Not binding the length**: padding rules (“duplicate last”) can become a malleability surface if `n` isn’t committed to.
- **Treating Merkle VCs as hiding**: hash-based VCs are typically *not hiding*; if values are guessable, attackers can brute-force.

## Ship It

Save the reusable review prompt/checklist in `outputs/vector-commitment-audit.md`. Use it when:

- reviewing a PR that introduces Merkle proofs / “state roots” / “commitment roots”
- designing an authenticated data structure API (`commit`, `open`, `verify`)
- evaluating whether you actually need KZG/Verkle (or a Merkle VC is enough)

## Exercises

1. Easy. Run `python3 code/main.py`. Observe how `verify(...)` flips to `False` when you change the value, the proof, or the root.
2. Medium. Add a helper `batch_open(values, indices)` that returns openings for several indices. Measure total proof size vs opening each index independently.
3. Hard. Production integration: pick a real Merkle proof format (e.g., from a blockchain client) and write a small verifier that checks a proof against a published root, paying attention to byte/endianness conventions.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Commitment (root) | “the hash of everything” | a value that binds you to a whole vector without revealing it |
| Opening proof | “Merkle proof” | sibling hashes that let a verifier recompute the root for one index |
| Binding | “can’t change your mind” | you can’t open the same committed index to two different values |
| Index binding | “position matters” | the proof/value is tied to a specific `i`, not just “somewhere in the set” |
| Length binding | “size matters” | `n` is committed so padding/truncation can’t change interpretation |

## Further Reading

- Gennaro, Halevi, Rabin, “Secure Hash-and-Sign Signatures Without the Random Oracle” (1999) — early context for hash-based authenticated structures.
- Catalano, Fiore, “Vector Commitments and Their Applications” (2013) — formalizes VCs and applications beyond Merkle trees.
- Boneh, Bünz, Fisch, “A Survey of Two Verkle Tree Designs” (2020) — practical VC design trade-offs for blockchain state proofs.
