# Sparse Merkle Trees & Verkle Trees (Toy)

> A tiny root can commit to a huge key→value map — and a short witness can prove one key (or its absence).

**Type:** Build  
**Languages:** Python  
**Prerequisites:** Phase 09 · 01 (Hash commitments), Phase 09 · 04 (Merkle trees), Phase 09 · 03 (Vector commitments, recommended)  
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** why sparse trees give non-inclusion proofs “for free”.
- **Compute** empty/default hashes for a fixed-depth Sparse Merkle Tree.
- **Implement** SMT updates and inclusion/non-inclusion verification in `O(depth)`.
- **Distinguish** Merkle “sibling lists” from Verkle “openings” (vector commitment proofs).
- **Apply** witness-size reasoning: depth vs width tradeoffs, and what Verkle multiproofs aim to fix.

## The Problem

You want a single 32-byte commitment (a “state root”) to a massive key→value map — billions of possible keys — without storing or transmitting the whole dataset. Light clients, bridges, rollups, and auditors all want the same thing: “show me *this* key’s value is X (or that it’s absent) under the published root.”

With a normal Merkle tree over a list, the index is “where in the list the item is.” But for a map (keys are arbitrary), you want the position to be *deterministic* from the key. That’s what Sparse Merkle Trees do: they commit to a *fixed key space* (often 2^256 leaves), so every key has a predefined leaf position.

Then comes the bandwidth bottleneck: Merkle proofs are a sibling hash *per level*. If the tree is deep (e.g., 256), proofs become large. Verkle trees attack that by replacing “hash of children” with a **vector commitment** at each node, so you can prove “child i has value v” without sending all siblings.

## The Concept

### Sparse Merkle Tree (SMT): the empty tree is a real tree

Pick a fixed depth `d`. Conceptually there are `2^d` leaves. Most are empty, represented by a single canonical empty leaf hash.

We use domain separation:

- `leaf = H("L" || len(value) || value)`
- `node = H("N" || left || right)`

Empty/default hashes are precomputed bottom-up:

- `default[0] = leaf_hash(empty_value)`
- `default[i+1] = node_hash(default[i], default[i])`

So the empty tree root is `default[d]`.  
Inclusion and non-inclusion proofs are the same shape: the sibling hashes along the key’s path.

### Verkle idea: replace sibling lists with openings

In a Merkle proof, to convince a verifier that the `i`-th child is correct, you must provide the `width-1` siblings (for binary width=2, that’s 1 sibling; for width=16, it’s 15 siblings).

In a Verkle proof, the parent stores **one commitment** to all `width` children, and you provide:

- the child value at position `i`
- a short opening proof (“witness”) that this value is indeed at `i` in the committed vector

Real Verkle trees use elliptic-curve vector commitments (Pedersen/IPA or KZG-style polynomial commitments) and aggregate many openings into a *small multiproof*. This lesson builds a **toy** version with an RSA-accumulator-style commitment so we can see the “open-by-index” shape using only Python stdlib.

### What this lesson implements

| Structure | What a node stores | Proof for one key contains | Proof grows with |
|---|---|---|---|
| SMT (binary) | `H(left || right)` | 1 sibling hash per level | depth |
| Toy Verkle (width=16) | 1 vector commitment to 16 children | 1 opening (witness) per level + opened values | depth (but depth is smaller with large width) |

## Build It

### Step 1: Empty hashes and domain separation

We define leaf and internal node hashing, then precompute the “all-empty” hashes for every level.

```python
import hashlib
from typing import List


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def h_leaf(value: bytes) -> bytes:
    return sha256(b"L" + len(value).to_bytes(4, "big") + value)


def h_node(left: bytes, right: bytes) -> bytes:
    return sha256(b"N" + left + right)


def default_hashes(bit_length: int) -> List[bytes]:
    if bit_length < 1:
        raise ValueError("bit_length must be >= 1")

    defaults = [h_leaf(b"")]
    for _ in range(bit_length):
        defaults.append(h_node(defaults[-1], defaults[-1]))
    return defaults
```

### Step 2: Sparse Merkle tree updates + proofs

An SMT stores only non-default nodes. Updates touch exactly one root-to-leaf path (`O(depth)`), and proofs are the sibling hashes along that path. Verification recomputes the root from the claimed value and the sibling list.

```python
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple


def key_to_leaf_index(key: bytes, bit_length: int) -> int:
    if bit_length < 1 or bit_length > 256:
        raise ValueError("bit_length must be in [1, 256]")
    digest = sha256(b"K" + key)
    value = int.from_bytes(digest, "big")
    return value >> (256 - bit_length)


@dataclass(frozen=True)
class SparseMerkleProof:
    bit_length: int
    leaf_index: int
    siblings: Tuple[bytes, ...]

    def size_bytes(self) -> int:
        return sum(len(s) for s in self.siblings)


class SparseMerkleTree:
    def __init__(self, bit_length: int):
        self.bit_length = bit_length
        self._defaults = default_hashes(bit_length)
        self._nodes: Dict[Tuple[int, int], bytes] = {}

    def _get(self, level: int, index: int) -> bytes:
        value = self._nodes.get((level, index))
        if value is None:
            return self._defaults[level]
        return value

    def _set(self, level: int, index: int, value: bytes) -> None:
        if value == self._defaults[level]:
            self._nodes.pop((level, index), None)
            return
        self._nodes[(level, index)] = value

    def root(self) -> bytes:
        return self._get(self.bit_length, 0)

    def non_default_node_count(self) -> int:
        return len(self._nodes)

    def update(self, key: bytes, value: Optional[bytes]) -> None:
        if value is not None and len(value) == 0:
            raise ValueError("empty values are reserved for 'absent'")

        leaf_index = key_to_leaf_index(key, self.bit_length)
        current_hash = self._defaults[0] if value is None else h_leaf(value)
        idx = leaf_index

        self._set(0, idx, current_hash)

        for level in range(1, self.bit_length + 1):
            sibling_idx = idx ^ 1
            sibling_hash = self._get(level - 1, sibling_idx)
            if (idx & 1) == 0:
                parent_hash = h_node(current_hash, sibling_hash)
            else:
                parent_hash = h_node(sibling_hash, current_hash)

            idx >>= 1
            current_hash = parent_hash
            self._set(level, idx, parent_hash)

    def prove(self, key: bytes) -> SparseMerkleProof:
        leaf_index = key_to_leaf_index(key, self.bit_length)
        siblings: List[bytes] = []
        idx = leaf_index
        for level in range(0, self.bit_length):
            siblings.append(self._get(level, idx ^ 1))
            idx >>= 1
        return SparseMerkleProof(
            bit_length=self.bit_length,
            leaf_index=leaf_index,
            siblings=tuple(siblings),
        )


def smt_verify(
    root: bytes,
    key: bytes,
    value: Optional[bytes],
    proof: SparseMerkleProof,
) -> bool:
    if proof.bit_length < 1 or len(proof.siblings) != proof.bit_length:
        return False

    if value is not None and len(value) == 0:
        return False

    idx = key_to_leaf_index(key, proof.bit_length)
    if idx != proof.leaf_index:
        return False

    current_hash = h_leaf(b"") if value is None else h_leaf(value)

    for sibling_hash in proof.siblings:
        if (idx & 1) == 0:
            current_hash = h_node(current_hash, sibling_hash)
        else:
            current_hash = h_node(sibling_hash, current_hash)
        idx >>= 1

    return current_hash == root
```

### Step 3: Toy vector commitment (RSA accumulator style)

This is a minimal “commit to a vector, open one position” construction:

- Map `(index, value)` to a prime `p_i` (“hash-to-prime”).
- Commit: `C = g^(∏ p_i) mod n`
- Open index `i` with witness `w = g^(∏_{j≠i} p_j) mod n`
- Verify: `w^(p_i) mod n == C`

```python
import math
from dataclasses import dataclass
from typing import Sequence, Tuple


def _miller_rabin_witness(a: int, s: int, d: int, n: int) -> bool:
    x = pow(a, d, n)
    if x == 1 or x == n - 1:
        return False
    for _ in range(s - 1):
        x = (x * x) % n
        if x == n - 1:
            return False
    return True


def is_prime_64(n: int) -> bool:
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if n in small_primes:
        return True
    for p in small_primes:
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while (d & 1) == 0:
        s += 1
        d >>= 1

    for a in small_primes:
        if a % n == 0:
            continue
        if _miller_rabin_witness(a, s, d, n):
            return False
    return True


def hash_to_prime_64(data: bytes, bits: int = 61) -> int:
    if bits < 16 or bits > 63:
        raise ValueError("bits must be in [16, 63]")

    mask = (1 << bits) - 1
    x = int.from_bytes(sha256(b"P" + data), "big") & mask
    x |= 1
    x |= 1 << (bits - 1)

    while not is_prime_64(x):
        x += 2
        x &= mask
        x |= 1
        x |= 1 << (bits - 1)
    return x


@dataclass(frozen=True)
class RSAParams:
    n: int
    g: int

    @property
    def byte_len(self) -> int:
        return (self.n.bit_length() + 7) // 8


def rsa_params_for_demo() -> RSAParams:
    p = hash_to_prime_64(b"rsa-p", bits=61)
    q = hash_to_prime_64(b"rsa-q", bits=61)
    n = p * q
    g = 5
    if math.gcd(g, n) != 1:
        g = 7
    return RSAParams(n=n, g=g)


def vc_element_prime(index: int, value: bytes) -> int:
    if index < 0 or index > 0xFFFF:
        raise ValueError("index out of range for demo encoding")
    payload = b"E" + index.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value
    return hash_to_prime_64(payload, bits=61)


def vc_commit(params: RSAParams, values: Sequence[bytes]) -> int:
    exp = 1
    for i, v in enumerate(values):
        exp *= vc_element_prime(i, v)
    return pow(params.g, exp, params.n)


def vc_open(params: RSAParams, values: Sequence[bytes], index: int) -> Tuple[bytes, int]:
    if index < 0 or index >= len(values):
        raise ValueError("index out of range")
    exp = 1
    for i, v in enumerate(values):
        if i == index:
            continue
        exp *= vc_element_prime(i, v)
    witness = pow(params.g, exp, params.n)
    return values[index], witness


def vc_verify(params: RSAParams, commitment: int, index: int, value: bytes, witness: int) -> bool:
    p_i = vc_element_prime(index, value)
    return pow(witness, p_i, params.n) == (commitment % params.n)
```

### Step 4: Toy Verkle-style tree (openings, no siblings)

We build a fixed-depth, width-`W` tree. Each internal node commits to its `W` children using the vector commitment from Step 3. A proof for one key contains one opening per level (index, opened child value, witness).

```python
import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple


def int_to_bytes(x: int, length: int) -> bytes:
    if x < 0:
        raise ValueError("x must be non-negative")
    return x.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _is_power_of_two(x: int) -> bool:
    return x > 0 and (x & (x - 1)) == 0


def key_to_base_w_path(key: bytes, width: int, depth: int) -> List[int]:
    if not _is_power_of_two(width):
        raise ValueError("width must be a power of two")
    bits_per_digit = int(math.log2(width))
    total_bits = bits_per_digit * depth
    if total_bits > 256:
        raise ValueError("depth * log2(width) must be <= 256 for this demo")
    digest = sha256(b"V" + key)
    v = int.from_bytes(digest, "big") >> (256 - total_bits)
    digits: List[int] = []
    for i in range(depth):
        shift = (depth - 1 - i) * bits_per_digit
        digits.append((v >> shift) & (width - 1))
    return digits


def leaf_value_hash(value: bytes) -> bytes:
    return sha256(b"val" + len(value).to_bytes(4, "big") + value)


@dataclass(frozen=True)
class ToyVerkleProof:
    width: int
    depth: int
    indices: Tuple[int, ...]
    values: Tuple[bytes, ...]
    witnesses: Tuple[int, ...]

    def size_bytes(self, params: RSAParams) -> int:
        return sum(len(v) for v in self.values) + len(self.witnesses) * params.byte_len


class ToyVerkleTree:
    def __init__(self, width: int, depth: int, params: RSAParams):
        if width < 2 or not _is_power_of_two(width):
            raise ValueError("width must be a power of two and >= 2")
        if depth < 1:
            raise ValueError("depth must be >= 1")
        self.width = width
        self.depth = depth
        self.params = params
        self._nodes: Dict[Tuple[int, Tuple[int, ...]], Tuple[bytes, ...]] = {}
        self._default_commitments: List[int] = self._compute_default_commitments()

    def _compute_default_commitments(self) -> List[int]:
        commit_bytes_len = self.params.byte_len
        zeros = b"\x00" * 32

        defaults: List[int] = [0 for _ in range(self.depth)]
        values = [zeros for _ in range(self.width)]
        defaults[self.depth - 1] = vc_commit(self.params, values)

        for level in range(self.depth - 2, -1, -1):
            child_value = int_to_bytes(defaults[level + 1], commit_bytes_len)
            values = [child_value for _ in range(self.width)]
            defaults[level] = vc_commit(self.params, values)
        return defaults

    def root_commitment(self) -> int:
        return self._default_commitments[0] if not self._nodes else self._node_commitment(0, ())

    def _default_child_value(self, level: int) -> bytes:
        if level == self.depth - 1:
            return b"\x00" * 32
        return int_to_bytes(self._default_commitments[level + 1], self.params.byte_len)

    def _node_values(self, level: int, prefix: Tuple[int, ...]) -> Tuple[bytes, ...]:
        current = self._nodes.get((level, prefix))
        if current is not None:
            return current
        default_child = self._default_child_value(level)
        return tuple(default_child for _ in range(self.width))

    def _store_node_values(self, level: int, prefix: Tuple[int, ...], values: Sequence[bytes]) -> None:
        default_child = self._default_child_value(level)
        if all(v == default_child for v in values):
            self._nodes.pop((level, prefix), None)
        else:
            self._nodes[(level, prefix)] = tuple(values)

    def _node_commitment(self, level: int, prefix: Tuple[int, ...]) -> int:
        values = self._node_values(level, prefix)
        if level < self.depth - 1:
            return vc_commit(self.params, values)
        return vc_commit(self.params, values)

    def update(self, key: bytes, value: Optional[bytes]) -> None:
        if value is not None and len(value) == 0:
            raise ValueError("empty values are reserved for 'absent'")

        path = key_to_base_w_path(key, self.width, self.depth)
        leaf_bytes = b"\x00" * 32 if value is None else leaf_value_hash(value)

        prefix: Tuple[int, ...] = tuple(path[:-1])
        level = self.depth - 1
        node_values = list(self._node_values(level, prefix))
        node_values[path[-1]] = leaf_bytes
        self._store_node_values(level, prefix, node_values)

        commit = vc_commit(self.params, node_values)
        for level in range(self.depth - 2, -1, -1):
            parent_prefix = tuple(path[:level])
            parent_values = list(self._node_values(level, parent_prefix))
            parent_values[path[level]] = int_to_bytes(commit, self.params.byte_len)
            self._store_node_values(level, parent_prefix, parent_values)
            commit = vc_commit(self.params, parent_values)

    def prove(self, key: bytes) -> ToyVerkleProof:
        path = key_to_base_w_path(key, self.width, self.depth)
        indices: List[int] = []
        values: List[bytes] = []
        witnesses: List[int] = []

        prefix: Tuple[int, ...] = ()
        commit = self._node_commitment(0, prefix)
        for level in range(0, self.depth):
            idx = path[level]
            node_values = self._node_values(level, prefix)
            value_bytes, witness = vc_open(self.params, node_values, idx)
            indices.append(idx)
            values.append(value_bytes)
            witnesses.append(witness)
            prefix = tuple(path[: level + 1])
            if level < self.depth - 1:
                commit = bytes_to_int(value_bytes)

        return ToyVerkleProof(
            width=self.width,
            depth=self.depth,
            indices=tuple(indices),
            values=tuple(values),
            witnesses=tuple(witnesses),
        )


def toy_verkle_verify(
    params: RSAParams,
    root_commitment: int,
    key: bytes,
    expected_value: Optional[bytes],
    proof: ToyVerkleProof,
) -> bool:
    if proof.depth < 1 or proof.width < 2:
        return False
    if len(proof.indices) != proof.depth:
        return False
    if len(proof.values) != proof.depth:
        return False
    if len(proof.witnesses) != proof.depth:
        return False
    if expected_value is not None and len(expected_value) == 0:
        return False

    path = key_to_base_w_path(key, proof.width, proof.depth)

    commit = root_commitment % params.n
    for level in range(proof.depth):
        idx = proof.indices[level]
        if idx != path[level]:
            return False
        if not vc_verify(params, commit, idx, proof.values[level], proof.witnesses[level]):
            return False
        if level < proof.depth - 1:
            commit = bytes_to_int(proof.values[level]) % params.n

    leaf_expected = b"\x00" * 32 if expected_value is None else leaf_value_hash(expected_value)
    return proof.values[-1] == leaf_expected
```

Run it:

```bash
python3 code/main.py
```

## Use It

Production equivalents are much more engineered (storage layout, batching, serialization, formal specs).

- **Sparse Merkle Trees**
  - Diem’s “Jellyfish Merkle Tree” (a sparse Merkle design optimized for DB storage): https://developers.diem.com/docs/technical-papers/jellyfish-merkle-tree-paper
  - Many zk systems use SMT variants for state/notes/nullifiers (typically with SNARK-friendly hashes like Poseidon).

- **Verkle trees**
  - Ethereum’s `go-verkle` implementation uses IPA-based vector commitments: https://github.com/ethereum/go-verkle
  - Verkle structure overview and key encoding (stem/suffix): https://blog.ethereum.org/2021/12/02/verkle-tree-structure

## Pitfalls

1. **No domain separation.** If leaf hashes and internal node hashes share the same input domain, “internal-as-leaf” confusions become possible.
2. **Empty value ambiguity.** If an “absent” leaf is represented as `hash(b"")`, then allowing a present value `b""` makes absence vs presence indistinguishable.
3. **Bit/byte order drift.** Proof verification depends on a consistent definition of left/right at each level; one endianness bug breaks every proof.
4. **Wrong default hash ladder.** In an SMT, the empty root must be computed from the same default recursion; hardcoding `0x00…00` without matching the hash rules breaks determinism.
5. **Assuming Verkle proofs are “constant size” automatically.** The *multiproof* is what compresses many openings; a naive implementation still has one opening per level.

## Ship It

This lesson ships `outputs/smt-verkle-witness-review-checklist.md`: a PR-review checklist you can paste into a code review when someone touches witness/proof logic (hashing, default nodes, path encoding, verification invariants).

## Exercises

1. Easy: Run `code/main.py`. Observe the SMT proof size (siblings) vs the toy Verkle proof size (openings).
2. Medium: Add a delete demo: insert `(key,value)`, record the root, delete the key, and confirm the root returns to the empty root.
3. Hard: Sketch what a Verkle multiproof would need to aggregate in this toy model (which openings are shared across keys, and what you’d like to compress).

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| Sparse Merkle Tree (SMT) | “Merkle tree for maps” | Fixed-depth tree where each key maps to a deterministic leaf index; empty leaves share a default hash |
| Default/empty hash | “Null node” | The canonical hash value representing an empty subtree at a given level |
| Inclusion proof | “Merkle proof” | Sibling hashes (SMT) or openings (Verkle) that let a verifier recompute the root for one key |
| Non-inclusion proof | “Proof of absence” | In an SMT, a proof that the leaf at the key’s index is the default empty value |
| Vector commitment | “Commit to an array” | One commitment to many ordered values, plus short per-index openings |
| Verkle tree | “Vector + Merkle” | A tree where internal nodes are vector commitments to children, reducing witness size vs high-depth Merkle trees |
| Opening (witness) | “Proof for one position” | Proof that a committed vector has a particular value at index `i` |

## Further Reading

- John Kuszmaul, *Verkle Trees* (2018) — original introduction of the “vector commitment tree” idea: https://math.mit.edu/research/highschool/primes/materials/2018/Kuszmaul.pdf
- Ethereum Foundation, *Verkle tree structure* (2021) — practical design notes (width=256, stem/suffix): https://blog.ethereum.org/2021/12/02/verkle-tree-structure
- Diem, *Jellyfish Merkle Tree* (2021) — sparse Merkle tree optimized for DB-backed state: https://developers.diem.com/docs/technical-papers/jellyfish-merkle-tree-paper
